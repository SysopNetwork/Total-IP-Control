/***************************************************************************
 *                                                                         *
 *   SNTIPCTL.C  --  Total IP Control                                      *
 *                                                                         *
 *   Centralized IP management, proxy detection, connection control,       *
 *   and audit logging for The Major BBS v10.                              *
 *                                                                         *
 *   Incorporates and extends functionality from PROXCLIP and IPControl.   *
 *                                                                         *
 *   Proxy detection works by IAT-patching recv() in GALTNTD.DLL so the   *
 *   PROXY Protocol v1 header is consumed the instant GALTNTD reads it     *
 *   from the socket, before any telnet processing occurs.                 *
 *                                                                         *
 *   LOAD ORDER: must appear AFTER GALTNTD in wgserv.cfg or the hdlcon    *
 *   pointer will be NULL at init and proxy detection will not function.   *
 *                                                                         *
 *   Total IP Control is developed and maintained by Mark Laudenbach       *
 *   at Sysop Network.                                                     *
 *                                                                         *
 *   Copyright (c) 2026 Sysop Network.  All Rights Reserved.              *
 *                                                                         *
 ***************************************************************************/

/*
 * winsock2.h must precede all SDK headers.  The SDK's tcpip.h pulls in
 * windows.h which drags winsock.h; including winsock2.h first sets
 * _WINSOCK2API_ and blocks the double-include.
 */
#include <winsock2.h>
#include <ws2tcpip.h>       /* in6_addr, inet_pton/inet_ntop for IPv6 text     */
#include <windows.h>
#include <winhttp.h>        /* outbound HTTPS/HTTP for GeoIP lookups          */
#include <process.h>        /* _beginthreadex for the GeoIP worker thread    */
#include <intrin.h>         /* _ReturnAddress: identify our caller (see hook) */

#include "gcomm.h"
#include "majorbbs.h"
#include "tcpip.h"
#include "SNTIPCTL.H"
#include "SNTVER.H"

#include <stdio.h>
#include <stddef.h>         /* offsetof                                      */
#include <string.h>
#include <stdarg.h>         /* va_list for the debug trace logger            */
#include "dfaapi.h"

/* Link the WinHTTP client library (also listed in the .vcxproj for clarity). */
#pragma comment(lib, "winhttp.lib")

/* The running build, as sysops see it (Audit Trail, trace, N!SNTVER). */
#define SNTIPCTL_VERSION "v" SNTVER_STR

/*
 * Names under which each daemon registers its server in the per-channel svrinf
 * list.  TELNETD.H defines the telnet name as TNTNAME "Telnet"; the SSH Server
 * module (SNSSH) registers SSHNAME "SSH" via regtcpsvr().  Both are kept as
 * local literals to avoid pulling those headers' export-decorated globals into
 * this module.
 *
 * Every proxy policy in SNTIPCTL is keyed off the accepting server's name, so
 * telnet and SSH are enforced independently and Rlogin / FTP / any other
 * registered daemon is left untouched.
 */
#define SNT_TELNET_SVRNAME "Telnet"
#define SNT_SSH_SVRNAME    "SSH"

/* Protocol tag recorded per pending channel (see pending_proto). */
#define SNT_PROTO_TELNET   'T'
#define SNT_PROTO_SSH      'S'

static HMCVFILE modmb = NULL;     /* SNTIPCTL.MCV                           */

/*
 * Values for the refusal messages (N!SNTUSERS, N!SNTMAXIP), filled just
 * before CLIMIT or IPGDNY is shown.  384 holds a dozen userids at the
 * 29-character BBS maximum.
 */
static CHAR tv_users[384];
static CHAR tv_maxip[12];

/* ======================================================================== */
/*   Proxy detection state                                                   */
/* ======================================================================== */

/*
 * Pending socket table, indexed by usrnum.
 * INVALID_SOCKET means no PROXY header processing is pending for that slot.
 * Set in sntipctl_hdlcon, cleared in prx_recv_hook or sntipctl_hup.
 *
 * pending_proto[] records which daemon accepted that channel (SNT_PROTO_*), so
 * prx_consume_header can apply the right trusted-proxy list and enforcement
 * flag.  It is only meaningful while pending_skt[] holds a socket.
 */
static SOCKET pending_skt[MAXNTERM];
static CHAR   pending_proto[MAXNTERM];

/*
 * Connection type per channel, for the /WHOSON N!SNTTIPCT column ("Telnet" or
 * "SSH").  Deliberately separate from pending_proto[] above: that array is
 * "only meaningful while pending_skt[] holds a socket" (i.e. transiently,
 * during PROXY header processing), whereas SNTTIPCT needs the value for the
 * whole session.  Set unconditionally in sntipctl_hdlcon right after is_ssh
 * is computed (so it does not depend on whether PROXY header processing is
 * enabled), reset at CONNECT and at hangup like every other per-channel store.
 *
 * Three states, not two: hdlcon runs for every registered daemon, not just
 * telnet and SSH (a WorldLink network link, Rlogin, FTP, etc. all reach it
 * too), so a channel that is neither must record UNKNOWN rather than being
 * defaulted to TELNET -- a WorldLink call is not a telnet session, and
 * snt_tv_conntype() must be able to tell "genuinely telnet" apart from
 * "never went through our hdlcon as telnet or SSH."
 */
#define SNT_PROTO_UNKNOWN  '\0'
CHAR   snt_conn_proto[MAXNTERM];

/*
 * Pre-hdlcon PROXY header stash (the "WorldLink" fix).
 *
 * GALTNTD'S OWN TELNET READER BEATS GALTNTD'S OWN CONNECT HANDLER.  That is the
 * whole problem, stated plainly because it is easy to misdiagnose.
 *
 * tntincall calls bbscon(usrnum) and then, on the very next line,
 * sktnfy(TNFRECV, clskt, tntrdt, tiptr, usrnum) -- registering the raw socket
 * for read notification.  bbscon() does NOT invoke hdlcon: it only sets
 * state=WCDICN and injects CDICONN (MAJORBBS.C), leaving hdlcon to be called
 * later from the main loop's channel service.  So when the caller's first bytes
 * land, the notification path runs first -- tcpwproc's FD_READ -> hdlsock ->
 * tntrdt -> tnordt -> recv() (TCPIP.C / TELNETD.C) -- and consumes the PROXY
 * header while hdlcon is still waiting its turn.  The deferred hook then finds
 * nothing left to strip and the caller is shown the gateway IP.
 *
 * It is a RACE between the Windows message pump and the main loop, not a
 * property of WorldLink.  WorldLink merely makes the main loop busy enough to
 * widen the gap between tntincall and hdlcon past the caller's round-trip, so
 * the notification wins nearly every time; with the link down hdlcon usually
 * gets there first, which is exactly why this looked like a WorldLink bug for so
 * long.  Nothing in the engine peeks at payload to route connections -- servers
 * are dispatched by PORT (regtcpsvr -> accept on the server's own socket ->
 * sip->incall), so no "WL-server detection peek" exists.
 *
 * prx_recv_hook catches that early read (the socket is not yet pending), grabs
 * the header here keyed by the raw socket handle, and sntipctl_hdlcon applies it
 * the instant it learns which channel the socket belongs to.  The socket handle
 * is the only identifier that exists in BOTH moments.  Entries are small and
 * transient -- created at the early read, taken at the following hdlcon, and
 * otherwise reclaimed on hangup / socket reuse / capacity / TTL.
 */
static VOID dbglog(const CHAR *fmt, ...);   /* full declaration further below */

struct early_proxy {
    SOCKET    skt;              /* INVALID_SOCKET = free slot                */
    ULONGLONG stamp;            /* GetTickCount64() at capture -- see TTL    */
    CHAR      line[128];        /* header line, from "PROXY ", NUL-terminated */
    ULONG     peer_ip;          /* peer address at capture time, see below   */
    USHORT    peer_port;
    GBOOL     peer_known;       /* FALSE if getpeername() failed at capture  */
};
static struct early_proxy early_stash[MAXNTERM];

/*
 * Windows recycles a closed SOCKET's numeric handle quickly, and under load
 * (scanner noise hammering the port) that can happen within the TTL window
 * above.  If the connection that stashed an entry never reaches hdlcon to
 * claim it -- dies mid-handshake, or belongs to some other protocol sharing
 * the hooked reader -- and the OS then reissues the same handle number to an
 * unrelated new connection that DOES reach hdlcon, early_stash_take() keyed
 * on the socket handle alone would hand that new connection a stranger's
 * captured IP.  Recording the peer's address at capture time and requiring
 * it to still match at take time closes that gap; a mismatch means the
 * handle was recycled, so the stash is stale and must be discarded, not
 * applied.
 */
static GBOOL
early_peer_addr(SOCKET s, ULONG *ip, USHORT *port)
{
    struct sockaddr_in sa;
    INT len = (INT)sizeof(sa);

    if (s == INVALID_SOCKET) return FALSE;
    if (getpeername(s, (struct sockaddr *)&sa, &len) != 0) return FALSE;
    if (sa.sin_family != AF_INET) return FALSE;
    *ip   = sa.sin_addr.s_addr;
    *port = sa.sin_port;
    return TRUE;
}

/*
 * How long a capture stays valid.  The real gap between the pre-hdlcon routing
 * peek and sntipctl_hdlcon is ~3ms, so this is enormously generous -- its only
 * job is to guarantee that an entry hdlcon never comes to collect cannot linger.
 * That case is reachable: a socket that never becomes a BBS channel (another
 * protocol's connection through the same hooked reader, or one that dies during
 * the handshake) is captured but never taken.  Without a TTL such an entry would
 * sit in the table until the OS recycled its handle onto an unrelated session,
 * which would then be handed the previous connection's IP.  Belt and braces with
 * the unconditional take in sntipctl_hdlcon, which covers every channel path.
 */
#define SNT_EARLY_STASH_TTL_MS  10000

static VOID
early_stash_free(INT i)
{
    early_stash[i].skt        = INVALID_SOCKET;
    early_stash[i].stamp      = 0;
    early_stash[i].line[0]    = '\0';
    early_stash[i].peer_ip    = 0;
    early_stash[i].peer_port  = 0;
    early_stash[i].peer_known = FALSE;
}

static VOID
early_stash_put(SOCKET s, const CHAR *line)
{
    ULONGLONG now = GetTickCount64();
    INT       i, slot = -1, oldest = 0;

    for (i = 0; i < MAXNTERM; i++) {
        if (early_stash[i].skt == s) { slot = i; break; }      /* same socket: overwrite */
        /* Reclaim anything past its TTL on the way past. */
        if (early_stash[i].skt != INVALID_SOCKET &&
            now - early_stash[i].stamp > SNT_EARLY_STASH_TTL_MS)
            early_stash_free(i);
        if (slot < 0 && early_stash[i].skt == INVALID_SOCKET) slot = i;
        if (early_stash[i].stamp < early_stash[oldest].stamp) oldest = i;
    }
    if (slot < 0) slot = oldest;  /* full: evict the oldest, never a fixed slot */
    early_stash[slot].skt   = s;
    early_stash[slot].stamp = now;
    stzcpy(early_stash[slot].line, line, sizeof(early_stash[slot].line));
    early_stash[slot].peer_known = early_peer_addr(s, &early_stash[slot].peer_ip,
                                                    &early_stash[slot].peer_port);
}

/*
 * If a fresh header is stashed for s, copy it to out and return TRUE.  The slot
 * is released either way: a match past its TTL is discarded rather than applied,
 * so a recycled handle can never inherit an older connection's IP.
 *
 * "Fresh" also requires the peer at s to still be the same peer recorded at
 * capture time (see early_peer_addr above) -- a handle recycled onto an
 * unrelated connection within the TTL must not hand that connection someone
 * else's captured IP.  A capture made when getpeername() itself failed
 * (peer_known FALSE) is passed through on TTL alone, same as before this
 * check existed.
 */
static GBOOL
early_stash_take(SOCKET s, CHAR *out, INT outsz)
{
    ULONGLONG now = GetTickCount64();
    INT       i;

    if (s == INVALID_SOCKET) return FALSE;
    for (i = 0; i < MAXNTERM; i++) {
        if (early_stash[i].skt == s) {
            GBOOL fresh = (GBOOL)(now - early_stash[i].stamp <= SNT_EARLY_STASH_TTL_MS);
            if (fresh && early_stash[i].peer_known) {
                ULONG  ip;
                USHORT port;
                if (!early_peer_addr(s, &ip, &port) ||
                    ip != early_stash[i].peer_ip || port != early_stash[i].peer_port) {
                    dbglog("EARLY-PROXY: skt=%d peer no longer matches capture -- "
                           "handle was recycled, discarding stashed header", (int)s);
                    fresh = FALSE;
                }
            }
            if (fresh) stzcpy(out, early_stash[i].line, outsz);
            early_stash_free(i);
            return fresh;
        }
    }
    return FALSE;
}

static VOID
early_stash_clear(SOCKET s)
{
    INT i;
    if (s == INVALID_SOCKET) return;
    for (i = 0; i < MAXNTERM; i++)
        if (early_stash[i].skt == s)
            early_stash_free(i);
}

/*
 * ------------------------------------------------------------------------
 * Closing a refused connection
 * ------------------------------------------------------------------------
 *
 * A refused caller is told why -- PRXBLK when require-trusted-proxy turns away a
 * direct connection, CLIMIT when one is over the per-IP limit -- and the socket
 * is then closed.  Getting the message out while still closing promptly is the
 * whole problem here, and it has a history of being solved wrongly.
 *
 * Closing a socket while data the peer sent sits UNREAD makes the stack send an
 * RST rather than a FIN (RFC 1122 4.2.2.13), and an RST lets the peer discard
 * bytes it received but has not yet displayed.  A refused telnet client has
 * almost always sent its IAC negotiation by now, so a bare close can destroy the
 * very message it exists to deliver.
 *
 * Older builds papered over that with Sleep(500) before the close.  That worked
 * only by side effect: it gave the client time to paint the message before the
 * RST landed -- and it did land, since after 500ms the negotiation is certainly
 * sitting unread, so those builds reset every refused connection.  The comment
 * on it claimed the wait was needed to flush the socket, which was never true:
 * with SO_LINGER off, the default here, closesocket() returns at once and
 * Windows sends what is queued before the FIN.  What the wait really did was
 * stop the ENTIRE BBS for half a second -- every channel shares one cooperative
 * thread -- charged on every port scanner, i.e. exactly the traffic that
 * require-trusted-proxy refuses all day.
 *
 * The fix is neither to wait nor to defer: READ OFF what the peer sent, then
 * close.  With the receive buffer empty there is nothing to trigger an RST, the
 * close is a clean FIN, and the queued message goes out ahead of it.  Every call
 * below is non-blocking, so this costs the board nothing, and it is strictly
 * better than the Sleep it replaces -- the message is delivered by design rather
 * than by winning a race against the client's screen.
 *
 * DO NOT defer this close to an rtkick to "let the message settle".  That was
 * tried, and it is wrong twice over:
 *
 *   - The socket is not ours to keep.  These paths return WITHOUT hcsave(), so
 *     the channel is left in WCDICN -- and the main loop's WCDICN arm has no
 *     CYCLE case, so the very next cycle takes default: -> rstchn() -> tcprst ->
 *     uscauto(usrnum), which finds the socket still mapped to that channel in
 *     sktunm[] and clsskt()s it (TCPIP.C).  The engine closes it within a cycle,
 *     milliseconds later.  Touching that handle a second afterwards can land on
 *     one the OS has already recycled onto a live session -- reading a real
 *     user's input and closing them.  (This is also why the raw closesocket()
 *     older builds used never leaked GALTCPIP's tables: uscauto released them
 *     all along.)
 *
 *   - Handing back a live socket wakes a reader we cannot see.  GALTNTD's
 *     tntincall calls sktnfy(TNFRECV, skt, tntrdt, tiptr, usrnum) BEFORE our
 *     hdlcon ever runs -- bbscon() does NOT invoke hdlcon, it only sets
 *     state=WCDICN and injects CDICONN; hdlcon is called later, from the main
 *     loop's channel service.  So the raw handle is already registered against
 *     the channel, pointing at GALTNTD's telnet reader.  Return with it open and
 *     that notification fires tntrdt on the refused channel, which recv()s
 *     tcpipinf[].socket -- which we have set to INVALID_SOCKET -- yielding
 *     "TCP/IP ERROR ... RECEIVE error 10038" and a bogus teardown: the exact
 *     error class the v1.1.1 fix removed.  Closing inline is what keeps that
 *     shut, because the socket is dead before control returns.
 *
 * Closing via GALTCPIP's clsskt() rather than closesocket() cancels the four
 * notification registrations and releases sktunm[]/sktarr[] as it closes, so
 * uscauto later finds nothing to do and cannot close the handle twice.  clsskt()
 * applies its abortive SO_LINGER {1,0} only when kilipg is set (kill system /
 * shutdown), so this is a graceful close in normal running.
 */

/*
 * GALTCPIP owns the socket bookkeeping, and this module is not linked against its
 * import library (the .vcxproj links wgserver_lib/galgsbl_lib only), so clsskt is
 * resolved by name at init exactly as _tcpipinf is.  Verified present in the
 * shipped DLL: _clsskt @7 (C:\BBSV10\GALTCPIP.DLL).
 */
typedef INT (*clsskt_fn_t)(INT skt);
static clsskt_fn_t p_clsskt = NULL;

/*
 * Finish the send side, read off what the peer sent, close.  See the note above
 * for why this is inline rather than deferred.
 *
 * Non-blocking mode is asserted rather than assumed.  These sockets already are
 * non-blocking: GALTCPIP drives I/O with WSAAsyncSelect (SelectSetup, TCPIP.C),
 * which sets that mode as a side effect -- which is why tnordt has an EWOULDBLOCK
 * case at all.  (Its own nonblock() helper is #ifdef IPSWITCH/PACSOFT and
 * compiles away here, so that is NOT the reason; do not go looking there.)  But a
 * blocking recv() on a peer with nothing left to say would park the whole board,
 * and that is too costly a failure to rest on a side effect of someone else's
 * registration.  We own the handle and are closing it; setting the mode affects
 * nobody.
 *
 * The drain is bounded rather than looping to EOF: a peer that keeps talking gets
 * closed on anyway.  It has had its message.
 */
static VOID
snt_refuse_close(SOCKET s)
{
    ULONG nonblk = 1;
    CHAR  scratch[256];
    INT   i;

    if (s == INVALID_SOCKET) return;

    shutdown(s, SD_SEND);       /* commit the message, queue the FIN behind it */

    if (ioctlsocket(s, FIONBIO, &nonblk) == 0) {
        for (i = 0; i < 8; i++)
            if (recv(s, scratch, sizeof(scratch), 0) <= 0)
                break;
    }

    if (p_clsskt != NULL)
        p_clsskt((INT)s);
    else
        closesocket(s);         /* uscauto still releases GALTCPIP's tables */
}

/*
 * Send one of our messages straight to a socket, for a caller refused before
 * the channel is handed to the telnet daemon (so there is no output channel to
 * prfmsg() to yet).  getmsg() is rawmsg() plus text-variable expansion
 * (getMsgBlk, MAJORBBS.C), so variables such as N!SNTUSERS work here too;
 * fill their buffers before calling.  send() on a fresh socket does not block
 * for a message this size.
 */
static VOID
snt_send_msg(SOCKET s, INT msgnum)
{
    const CHAR *txt;

    if (modmb == NULL || s == INVALID_SOCKET) return;
    setmbk(modmb);
    txt = getmsg(msgnum);
    if (txt != NULL && txt[0] != '\0')
        send(s, txt, (int)strlen(txt), 0);
    rstmbk();
}

/*
 * Set for a channel when prx_consume_header emitted a connect-time Audit Trail
 * line for it (real IP applied, or header ignored as untrusted).  sntipctl_logon
 * consults this to avoid writing a second, redundant trail line for the same
 * session.  Cleared in sntipctl_hdlcon and sntipctl_hup.
 */
static GBOOL conn_ip_logged[MAXNTERM];

/*
 * Real (post-proxy) client IP as text, for BOTH IPv4 and IPv6 callers.  The
 * engine's tcpipinf[].inaddr is a 32-bit struct in_addr -- IPv4 only -- so an
 * IPv6 client's real address has nowhere to live in the engine.  We keep our
 * own per-channel string copy: for IPv4 it mirrors inaddr; for IPv6 it is the
 * only record of the true address.  The audit trail, log files, /myip and
 * /whoson all read it so they show the real caller regardless of family.
 * Empty ("") means no PROXY header was processed (direct connect).  Cleared in
 * sntipctl_hdlcon and sntipctl_hup, sized for INET6_ADDRSTRLEN (46).
 */
static CHAR snt_real_ip[MAXNTERM][46];

/*
 * After globalcmd returns 1, MBBS calls sttrou 1-2 times with spurious input
 * ("/" and/or "") before waiting for real user input.  absorb_count[] tracks
 * how many of those calls to silently swallow for each channel.
 */
static INT absorb_count[MAXNTERM];

/*
 * IAT patch state.
 *
 * recv() is patched in more than one module: GALTNTD.DLL (or GALTCPIP.DLL as a
 * fallback) for telnet, and ssh.dll -- the libssh library SNSSH hands its
 * accepted sockets to -- when SSH PROXY header processing is configured.  Each
 * patched slot is remembered with its original address so sntipctl_fin can put
 * every one of them back.
 *
 * real_recv is the original recv() address (identical for every module, since
 * they all import it from WS2_32) and doubles as the "any patch installed" flag.
 */
typedef int (WINAPI *recv_fn_t)(SOCKET, char *, int, int);

#define SNT_MAX_IAT_PATCH 6         /* GALTNTD + GALTCPIP + GALTNT + GALTCPAT + ssh.dll (+margin) */

struct iat_patch {
    recv_fn_t *slot;                /* address of the IAT entry we overwrote */
    recv_fn_t  orig;                /* what it held before                   */
};

static recv_fn_t        real_recv = NULL;
static struct iat_patch iat_patches[SNT_MAX_IAT_PATCH];
static INT              iat_patch_count = 0;

/*
 * The telnet module's recv() IAT slot, captured when the hook is installed.
 * Used only by the debug trace (debug_hook_installed) to report whether our
 * hook is still the value living in that slot -- if another module (e.g. a
 * networking module that patches recv() when it establishes its link) has
 * since overwritten it, GALTNTD's telnet reads would bypass prx_recv_hook and
 * the PROXY header would no longer be stripped.  NULL if the hook was never
 * installed.  Read-only after startup; never used to drive behavior.
 */
static recv_fn_t       *tnt_iat_slot = NULL;

/*
 * Which modules actually got hooked.  These are tracked separately rather than
 * inferred from real_recv, because either patch can fail on its own: telnet must
 * fall back to its FIONREAD path when only ssh.dll was hooked, and SSH header
 * processing must stay off when only the telnet module was.
 */
static GBOOL tnt_recv_hooked = FALSE;   /* GALTNTD.DLL or GALTCPIP.DLL        */
static GBOOL ssh_recv_hooked = FALSE;   /* ssh.dll (libssh), for SNSSH        */

/*
 * tcpipinf is resolved at runtime to avoid linking GALTCPIP_LIB.LIB,
 * which causes DLL load failure due to ordinal mismatch on some servers.
 */
static struct tcpipinf **pp_tcpipinf = NULL;

/*
 * TRUE if socket s belongs to a channel with a fully logged-on user (ACTUSR).
 * The pre-hdlcon PROXY capture uses this to stay away from established sessions:
 * it must never peek at or consume an active user's mid-session input.  A fresh,
 * pre-hdlcon connection has no logged-on user yet, so this is FALSE for it and it
 * remains eligible for capture.  (Defined here, below pp_tcpipinf.)
 */
static GBOOL
socket_has_active_user(SOCKET s)
{
    INT j;
    if (pp_tcpipinf == NULL || s == INVALID_SOCKET) return FALSE;
    for (j = 0; j < MAXNTERM && j < nterms; j++)
        if ((*pp_tcpipinf)[j].socket == s && usroff(j)->usrcls == ACTUSR)
            return TRUE;
    return FALSE;
}

/*
 * Which channel currently owns socket s, or -1.  Unlike pending_unum_for this
 * asks the ENGINE, not our own table, so it answers even for a socket we have
 * not registered yet -- which is the case we need to describe.
 */
static INT
snt_chan_for_socket(SOCKET s)
{
    INT j;
    if (pp_tcpipinf == NULL || s == INVALID_SOCKET) return -1;
    for (j = 0; j < MAXNTERM && j < nterms; j++)
        if ((*pp_tcpipinf)[j].socket == s)
            return j;
    return -1;
}

/*
 * Name the module that called us, and where in it the call came from.
 *
 * This exists to PROVE, rather than assert, which module consumes a caller's
 * first bytes before sntipctl_hdlcon runs.  The recv() IAT patch means a
 * module's own `recv(...)` call lands in prx_recv_hook, so our return address is
 * the instruction after that module's call site: resolving it to a module gives
 * the reader's identity directly, and `base+RVA` can be mapped back to a
 * function name against that module's .MAP/PDB.  Reading the SDK source says
 * this should be GALTNTD's telnet reader (tnordt, woken by the notification
 * tntincall registers immediately after bbscon, while hdlcon still waits on the
 * main loop) -- but that is an inference from the WG 3.3 source, and the engine
 * in the field is v10.  This turns the inference into evidence.
 *
 * Debug-only and only on a positively identified PROXY header, so it costs
 * nothing in normal running and cannot widen what the trace records.
 */
static VOID
snt_caller_module(VOID *ret, CHAR *out, INT outsz)
{
    HMODULE hm = NULL;
    CHAR    path[MAX_PATH];
    CHAR   *base;

    if (out == NULL || outsz <= 0) return;
    out[0] = '\0';

    if (ret == NULL ||
        !GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCSTR)ret, &hm) ||
        hm == NULL ||
        GetModuleFileNameA(hm, path, sizeof(path)) == 0) {
        _snprintf(out, outsz, "unknown(ret=%p)", ret);
        out[outsz - 1] = '\0';
        return;
    }

    base = strrchr(path, '\\');
    base = (base != NULL) ? base + 1 : path;
    _snprintf(out, outsz, "%s+0x%08lX", base,
              (ULONG)((BYTE *)ret - (BYTE *)hm));
    out[outsz - 1] = '\0';
}

/*
 * snt_source_ip
 *
 * The canonical answer to "where is this channel calling from", as text.
 *
 * This is the ONE place that decides a caller's identity, and everything that
 * counts, records or looks up an address goes through it.  It exists because
 * the engine's inaddr is a 32-bit IPv4 value and an IPv6 caller has no
 * representation there at all (TCPIP.H:195 -- struct in_addr, and the struct is
 * capped at 255 bytes with 13 spare, so there is no room to add one).  We keep
 * the real address in our own text store instead, and for an IPv6 caller inaddr
 * is deliberately set to 0.0.0.0 as a marker.
 *
 * So: prefer our store, and fall back to inaddr only when it is empty (a direct
 * connection, which had no PROXY header to record).  That fallback is what makes
 * this uniform -- one comparison works for direct v4, proxied v4 and proxied v6
 * alike, with no special cases at the call sites.
 *
 * NOTE the v4 text is the SAME string for a proxied and a direct caller from one
 * address, so comparing these strings groups sessions exactly as comparing
 * inaddr used to -- with the single, intended difference that two IPv6 callers
 * are now told apart instead of both being "the proxy".
 */
static VOID
snt_source_ip(INT unum, CHAR *out, INT outsz)
{
    struct in_addr a;

    if (out == NULL || outsz <= 0) return;
    out[0] = '\0';
    if (unum < 0 || unum >= MAXNTERM || unum >= nterms || pp_tcpipinf == NULL) return;

    if (snt_real_ip[unum][0] != '\0') {
        stzcpy(out, snt_real_ip[unum], outsz);
        return;
    }
    a.s_addr = (*pp_tcpipinf)[unum].inaddr.s_addr;
    if (a.s_addr == 0) return;                   /* no address we can name */
    stzcpy(out, inet_ntoa(a), outsz);
}

/* TRUE if an address in text form is IPv6 (a colon can appear in nothing else). */
static GBOOL
snt_ip_is_v6(const CHAR *ip)
{
    return (GBOOL)(ip != NULL && strchr(ip, ':') != NULL);
}

/*
 * snt_v6_src_check
 *
 * Validate the source address out of a "PROXY TCP6 ..." header before a single
 * byte of it is trusted.
 *
 * This MUST exist because src_ip is whatever sscanf's "%63s" lifted off the
 * wire -- any 63-character non-whitespace token -- and from here it becomes the
 * channel's identity: it is written into the user's account record and
 * interpolated into an outbound GeoIP URL.  The IPv4 branch has always
 * validated (inet_addr, rejecting INADDR_NONE); without the same check here,
 * a header reading "PROXY TCP6 :anything-at-all 1 1 1" is stored verbatim.
 *
 *   returns  1 = a genuine IPv6 address; use src_ip as text
 *            0 = valid but IPv4-MAPPED ("::ffff:1.2.3.4") -- *v4 receives the
 *                real IPv4 address and the caller should take its IPv4 path.
 *                A v6-only backend listener reports v4 peers this way, and they
 *                are v4 callers: unwrapping keeps one client to one identity,
 *                keeps the private-range checks working, and puts the real
 *                address in inaddr rather than the 0.0.0.0 marker.
 *           -1 = not an IPv6 address at all -- reject the header.
 */
static INT
snt_v6_src_check(const CHAR *src_ip, struct in_addr *v4)
{
    struct in6_addr a6;

    if (src_ip == NULL || v4 == NULL) return -1;
    if (inet_pton(AF_INET6, src_ip, &a6) != 1) return -1;
    if (IN6_IS_ADDR_V4MAPPED(&a6)) {
        memcpy(&v4->s_addr, &a6.s6_addr[12], 4);
        return 0;
    }
    return 1;
}

/*
 * snt_ip_for_field
 *
 * Render an address to fit a user-record field, which is the one place the
 * engine's limits bite and we cannot design around them: NADSIZ is 30, so an
 * address field holds 29 characters, and no longer field exists in usracc.
 * A full IPv6 address is up to 39 -- and the common real-world case is the long
 * one, because SLAAC privacy extensions give a random 64-bit interface ID that
 * never compresses.
 *
 * Truncating is not an option: a cut-off address still LOOKS like an address,
 * so it would quietly corrupt the very record it is meant to document.  Instead,
 * when the full address will not fit, fall back to the /64 prefix
 * ("2601:648:8600:1234::/64", never more than 24 characters).  That is the
 * stable, meaningful half -- it identifies the subscriber's network, while the
 * interface ID it drops is often randomised and rotates anyway -- and the "/64"
 * suffix makes the field self-describing, so a sysop can always tell which form
 * they are looking at.  IPv4 and short IPv6 addresses are stored verbatim.
 */
static VOID
snt_ip_for_field(const CHAR *ip, INT maxlen, CHAR *out, INT outsz)
{
    struct in6_addr a6;
    CHAR            pfx[INET6_ADDRSTRLEN];
    CHAR            cand[64];

    if (out == NULL || outsz <= 0) return;
    out[0] = '\0';
    if (ip == NULL || ip[0] == '\0' || maxlen < 2) return;

    /* Fits as-is: every IPv4 address, and any IPv6 that compresses small. */
    if ((INT)strlen(ip) <= maxlen - 1) {
        stzcpy(out, ip, outsz);
        return;
    }

    /* Too long, and there is no shorter honest form of an IPv4 address. */
    if (!snt_ip_is_v6(ip)) return;

    /* Too long: zero the interface ID and try the /64 prefix instead. */
    if (inet_pton(AF_INET6, ip, &a6) != 1) return;   /* unparseable -- write nothing */
    memset(&a6.s6_addr[8], 0, 8);
    if (inet_ntop(AF_INET6, &a6, pfx, sizeof(pfx)) == NULL) return;
    _snprintf(cand, sizeof(cand), "%s/64", pfx);
    cand[sizeof(cand) - 1] = '\0';

    /*
     * If even the prefix will not fit, write a MARKER.  The only field this can
     * happen for is 5 (usrpho, PHOSIZ = 16 -> 15 usable), which is too short for
     * any form of a v6 address -- a /64 prefix runs to 24 characters.
     *
     * The two tempting options are both worse.  Clipping is out: a cut-off
     * address still looks like an address, so it puts a WRONG one in the record.
     * But writing nothing is not "safe" either -- this field's entire job is "the
     * caller's current address", so a v4 address left over from that user's last
     * login would sit there reading as current.  Stale and plausible is the same
     * lie in slower motion.  So say the one true thing that fits, and let the
     * logs carry the address.
     */
    if ((INT)strlen(cand) > maxlen - 1) {
        stzcpy(out, "IPv6", outsz);
        return;
    }

    stzcpy(out, cand, outsz);
}

/* Saved hdlcon pointer -- we chain to this after our processing. */
static VOID (*hcsave)(VOID) = NULL;

/* ======================================================================== */
/*   Configuration state                                                     */
/* ======================================================================== */

/*
 * IPv4 CIDR entry: network address + subnet mask, both in network byte order.
 * An all-zero entry (addr=0, mask=0) is treated as "not set".
 */
struct snt_cidr {
    ULONG addr;     /* network address (host bits zeroed)  */
    ULONG mask;     /* subnet mask                         */
};

/*
 * IPv6 CIDR entry: 128-bit network address (host bits zeroed) plus a prefix
 * length.  prefix == 0 is the "not set" sentinel (an all-zero record reads as
 * unset, and parse_cidr6 refuses a "::/0" entry) -- this both mirrors the v4
 * all-zero convention and prevents a bare "::/0" from matching every v6 caller.
 */
struct snt_cidr6 {
    UCHAR addr[16];     /* network address, network byte order, host bits zeroed */
    UCHAR prefix;       /* prefix length 1..128; 0 == not set                    */
};

/* Trusted proxy enforcement -- only process PROXY headers from known proxies. */
static GBOOL           proxy_trust_enabled = FALSE;
static struct snt_cidr trusted_proxy_cidrs[SNTIPCTL_MAX_TRUSTED];
static INT             trusted_proxy_count = 0;

/*
 * Require-trusted-proxy ("block direct").  When enabled, a connection whose
 * raw source IP is NOT one of the configured trusted proxies is refused at
 * connect time, before the login prompt.  This stops users from bypassing the
 * reverse proxy by telnetting straight to the backend port.  Independent of
 * proxy_trust_enabled, but only takes effect when at least one trusted proxy
 * CIDR is configured (so an empty list can never lock the BBS out).  Loopback
 * and connection-limit whitelist IPs are always exempt. */
static GBOOL           proxy_block_enabled = FALSE;

/*
 * SSH policy (v1.1.3).  Deliberately a parallel, fully independent copy of the
 * telnet settings above -- separate enable flags and a separate trusted proxy
 * CIDR list -- so the two protocols can be fronted by different proxies, or one
 * can be locked down while the other is left open.
 *
 *   ssh_manage_enabled -- master gate.  Off (the default, and what every
 *       pre-v1.1.3 settings file reads as) means SNTIPCTL does not touch SSH
 *       connections at all beyond the protocol-agnostic logon-path features.
 *   ssh_hdr_enabled -- consume a PROXY Protocol v1 header on SSH connections
 *       and rewrite the channel's IP to the real client.  Requires ssh.dll's
 *       recv() to be hooked (ssh_recv_hooked); only enable it if the front end
 *       actually sends the header on the SSH port.
 *   ssh_trust_enabled -- only APPLY a consumed header when the relaying proxy
 *       is in the SSH trusted list (mirrors proxy_trust_enabled).
 *   ssh_block_enabled -- refuse SSH connections whose raw source IP is not a
 *       trusted SSH proxy (mirrors proxy_block_enabled).  Inert unless at
 *       least one SSH CIDR is configured; loopback and the connection-limit
 *       whitelist are always exempt.
 */
static GBOOL           ssh_manage_enabled = FALSE;
static GBOOL           ssh_hdr_enabled    = FALSE;
static GBOOL           ssh_trust_enabled  = FALSE;
static GBOOL           ssh_block_enabled  = FALSE;
static struct snt_cidr ssh_proxy_cidrs[SNTIPCTL_MAX_TRUSTED];
static INT             ssh_proxy_count    = 0;

/* Global IP connection limiting -- BBS-wide cap per source IP. */
static GBOOL conn_limit_enabled = FALSE;
static INT   conn_limit_max     = 1;

/*
 * Audit logging.  log_mode is one of LOGM_* (OFF/AUDIT/LOG/BOTH) and selects
 * two independent sinks, derived into log_to_audit / log_to_file by
 * log_apply_mode():
 *   - the BBS Audit Trail (the live sysop log, written via shocst), and
 *   - daily log files under TOTALIPCONTROL\ (PROXCLIP LOGS, DENIED ...).
 */
static INT              log_mode     = LOGM_OFF;
static GBOOL            log_to_audit = FALSE;   /* derived from log_mode        */
static GBOOL            log_to_file  = FALSE;   /* derived from log_mode        */
static CRITICAL_SECTION log_cs;

/*
 * Debug trace logging.  Independent of log_mode: when on, a verbose per-event
 * trace of the connection-processing path (connect, recv-hook fire, PROXY-header
 * consume, fallback, logon, hangup, plus a recv-hook integrity check at each
 * connect) is written to hourly files under TOTALIPCONTROL\DEBUG\YYYY-MM-DD\.
 * Off by default; General Settings in /TIP.  This is a diagnostic
 * aid, not a routine log -- it is chatty and meant to be turned on to capture a
 * problem, then turned back off.  It shares log_cs with the audit-log writer.
 */
static GBOOL            debug_enabled = FALSE;

/* User profile IP recording -- write real IP to a user account field at logon. */
static GBOOL usrip_enabled = FALSE;
static INT   usrip_field   = 1;    /* 1=usrad1, 2=usrad2, 3=usrad3, 4=usrad4, 5=usrpho */

/*
 * Bypass key -- any user holding this BBS key is exempt from connection
 * limit enforcement.  SYSOP and MASTER key holders are always exempt
 * regardless of this setting.  Empty string = no additional bypass.
 */
static CHAR bypass_key[16];

/* BBS key that grants access to the /WHOSON staff who's-online view.  Defaults
 * to SYSOP; SYSOP/MASTER always have access regardless of this setting. */
static CHAR staff_key[16];

/* Connection limit whitelist -- connections from these IPs/CIDRs are never
 * subject to the global per-IP connection limit. */
static struct snt_cidr whitelist_cidrs[SNTIPCTL_MAX_WHITELIST];

/* IPv6 connection-limit whitelist -- IPv6 clients matching these CIDRs are
 * never subject to the global per-IP connection limit.  Independent of the v4
 * list above; matched against the caller's real IPv6 text (snt_real_ip) since
 * the engine's inaddr holds only v4.  Persisted in the "SNTIPV6WL" record. */
static struct snt_cidr6 whitelist6_cidrs[SNTIPCTL_MAX_WHITELIST6];
static INT              whitelist6_count = 0;

/*
 * GeoIP Location -- at logon, look up the caller's approximate City / State /
 * Country from their IP via an online provider and store it in a configurable
 * user profile field.  Lookups run on a background worker thread so login is
 * never delayed, and a failed lookup can never block a user from logging in.
 * See the "GeoIP Location" section further down for the full implementation.
 */
static GBOOL geoip_enabled   = FALSE;
static INT   geoip_field     = 3;     /* city/state field: 1=usrad1..4=usrad4, 5=usrpho (default Address 3) */
static GBOOL geoip_split     = TRUE;  /* TRUE=city/state in geoip_field, country in geoip_cty_field */
static INT   geoip_cty_field = 4;     /* country field in split mode (default Address 4) */
static INT   geoip_cty_fmt   = GEOCF_FULL; /* country rendering: full name or 2-letter code */
static INT   geoip_reg_fmt   = GEORF_CODE; /* state/region rendering: 2-letter code or full name */
static INT   geoip_provider  = GEOPRV_IPWHOIS;
static GBOOL geoip_use_https = TRUE;
static INT   geoip_timeout   = 5;     /* seconds per WinHTTP leg               */
static GBOOL geoip_cache_on     = TRUE;  /* caching enabled at all                */
static GBOOL geoip_cache_bytime = TRUE;  /* TRUE=expire by duration; FALSE=per-IP */
static INT   geoip_cache_min = 1440;  /* cache TTL in minutes (24h default)    */
static INT   geoip_retries   = 1;     /* extra attempts after the first failure*/
static INT   geoip_loglevel  = GEOLOG_NORMAL;
static CHAR  geoip_host[64];          /* API host, e.g. "ipwho.is"            */
static CHAR  geoip_key[80];           /* API key/token, empty = keyless        */
static CHAR  geoip_format[48];        /* location template, e.g. "{city}, {region}, {country}" */

/* Online config editor -- module state number assigned at init. */
static INT cfgstt = -1;

/* ======================================================================== */
/*   Btrieve settings storage                                                */
/*                                                                           */
/*   All configuration is stored in SNTIPCTL.DAT (a Btrieve file created    */
/*   at first run via dfaCreateSpec).  One record, keyed by "SNTIPCTL".     */
/* ======================================================================== */

/*
 * On-disk config record.  Must be packed to 1-byte alignment so field
 * offsets match the key spec passed to dfaCreateSpec, regardless of the
 * compiler's default alignment.
 *
 * version == 12 identifies this layout (v8 added the GeoIP block; v9 added the
 * split write-mode / country field / country format / cache-mode flag; v10
 * repurposed the audit-logging byte from 'Y'/'N' to a LOGM_* mode; v11 added
 * the SSH policy block; v12 added the /WHOSON staff view key).  Each block is
 * carved from the spare region, so an older record's zeroed bytes read as the
 * feature-off / legacy default and stay byte-compatible.  The geoip_reg_fmt
 * (state format) byte was earlier
 * carved from the spare region with no size or version change -- a zeroed byte
 * in an older record reads as GERF_CODE, so v9/v10 records stay byte-compatible
 * via legacy mapping.  The v11 SSH block is carved the same way: every one of
 * its flags reads FALSE from the zeroed spare bytes of an older record, which
 * is exactly the pre-v1.1.3 behavior (SSH unmanaged).
 * Field sizes:
 *   original v7 core .......... 142 bytes
 *   GeoIP block (v8) .......... 213 bytes
 *   GeoIP split block (v9) ....   7 bytes
 *   geoip_reg_fmt (state fmt) .   1 byte
 *   SSH policy block (v11) ....  20 bytes
 *   staff view key (v12) .....  16 bytes
 *   debug_on flag (v13) ......   1 byte
 *   spare ..................... 112 bytes
 *   total ..................... 512 bytes
 */
#pragma pack(push, 1)
struct sntipctlcfg {
    CHAR            recid[16];                      /* key: "SNTIPCTL"         */
    CHAR            version;                        /* struct version (13)     */
    CHAR            proxy_trust;                    /* 'Y'/'N'                 */
    struct snt_cidr proxy_cidrs[2];                 /* trusted proxy CIDRs     */
    CHAR            conn_limit;                     /* 'Y'/'N'                 */
    INT             conn_max;                       /* 1-1000                  */
    CHAR            log_mode;                       /* LOGM_* (legacy 'Y'/'N') */
    CHAR            usrip_on;                       /* 'Y'/'N'                 */
    INT             usrip_fld;                      /* 1-5                     */
    CHAR            bypass_key[16];                 /* BBS key name or empty   */
    struct snt_cidr whitelist[10];                  /* conn-limit whitelist    */
    CHAR            proxy_block;                    /* 'Y'/'N' require proxy   */

    /* ---- GeoIP Location block (added in struct version 8, v1.1.0) ---- */
    CHAR            geoip_on;                       /* 'Y'/'N'                 */
    INT             geoip_fld;                      /* profile field 1-5       */
    CHAR            geoip_provider;                 /* GEOPRV_* id             */
    CHAR            geoip_https;                    /* 'Y'/'N' use TLS         */
    INT             geoip_timeout;                  /* per-request seconds     */
    CHAR            geoip_cache_on;                 /* 'Y'/'N'                 */
    INT             geoip_cache_min;                /* cache TTL in minutes    */
    INT             geoip_retry;                    /* retries on failure 0-5  */
    CHAR            geoip_loglvl;                   /* GEOLOG_* verbosity      */
    CHAR            geoip_host[64];                 /* API host, e.g. ipwho.is */
    CHAR            geoip_key[80];                  /* API key/token or empty  */
    CHAR            geoip_format[48];               /* location format template*/

    /* ---- GeoIP split write-mode block (added in struct version 9) ---- */
    CHAR            geoip_split;                    /* 'Y'=split 'N'=combined  */
    INT             geoip_cty_fld;                  /* country field 1-5       */
    CHAR            geoip_cty_fmt;                  /* GEOCF_* full/code       */
    CHAR            geoip_cache_bytime;             /* 'Y'=time expiry 'N'=per-IP */

    /* ---- GeoIP state/region format (struct version 10, no size change) ----
     * Carved from the spare region, so the record stays 512 bytes and older
     * files read this byte as 0 (== GEORF_CODE, the historical behavior). */
    CHAR            geoip_reg_fmt;                  /* GEORF_* code/full       */

    /* ---- SSH policy block (struct version 11, v1.1.3) ----
     * Also carved from the spare region, so the record stays 512 bytes.  A
     * pre-v11 file reads these as zero bytes: not 'Y', hence every flag is
     * FALSE and SSH is left unmanaged, exactly as before this block existed. */
    CHAR            ssh_manage;                     /* 'Y'/'N' manage SSH      */
    CHAR            ssh_hdr;                        /* 'Y'/'N' parse PROXY hdr */
    CHAR            ssh_trust;                      /* 'Y'/'N'                 */
    CHAR            ssh_block;                      /* 'Y'/'N' require proxy   */
    struct snt_cidr ssh_cidrs[2];                   /* SSH trusted proxy CIDRs */

    /* ---- Staff view key (struct version 12, v2.0.0) ----
     * Carved from the spare region, so the record stays 512 bytes.  A pre-v12
     * file reads this as zero bytes (empty key); cfg_load defaults it to SYSOP
     * on migration so the /WHOSON staff view keeps working after an upgrade. */
    CHAR            staff_key[16];                  /* /WHOSON access key      */

    /* ---- Debug trace logging (struct version 13, v2.0.0) ----
     * Carved from the spare region, so the record stays 512 bytes.  A pre-v13
     * file reads this byte as zero (not 'Y'), so debug logging stays OFF after
     * an upgrade until the sysop turns it on -- exactly the safe default. */
    CHAR            debug_on;                        /* 'Y'/'N' debug trace log */

    CHAR            spare[112];                     /* pad to 512 bytes        */
};
#pragma pack(pop)

/*
 * Compile-time guard: the on-disk record must stay exactly 512 bytes so it
 * matches the length passed to dfaCreateSpec/dfaOpen and remains compatible
 * with existing SNTIPCTL.DAT files.  If the struct size ever drifts, this
 * declares an array with a negative size and the build fails here.
 */
typedef CHAR sntipctlcfg_is_512[(sizeof(struct sntipctlcfg) == 512) ? 1 : -1];

static DFAFILE             *sntbt = NULL;   /* SNTIPCTL.DAT file handle */
static struct sntipctlcfg   sntcfg;         /* in-memory config record  */

/*
 * The address lists live in further records of the same SNTIPCTL.DAT, each
 * found by its own recid key and padded to the file's fixed 512-byte record
 * length, so a list can grow without touching the main record:
 *
 *   "SNTPROXY"   the telnet and SSH trusted proxies, 10 each
 *   "SNTWL4"     the IPv4 whitelist, 50 entries
 *   "SNTIPV6WL"  the IPv6 whitelist, entries 1-25
 *   "SNTIPV6W2"  the IPv6 whitelist, entries 26-50
 *
 * The main record still holds the first SNT_REC_TRUSTED proxies of each
 * protocol and the first SNT_REC_WHITELIST IPv4 entries, which is all a
 * build from before these records knew about.  They are written there too,
 * so going back to such a build keeps those entries, and a .DAT from one is
 * read through them until these records are first saved.
 *
 * "SNTIPV6WL" is the IPv6 record earlier builds wrote with 10 entries; its
 * list now runs to 25 at the same offset, so the old record reads as its
 * first 10 entries with the rest empty.
 */
#define SNT_REC_TRUSTED    2           /* proxies per protocol, main record */
#define SNT_REC_WHITELIST  10          /* IPv4 whitelist, main record       */
#define SNT_V6_PER_REC     25          /* IPv6 entries per record           */

#pragma pack(push, 1)
struct snt_proxyrec {
    CHAR             recid[16];                          /* key: "SNTPROXY"     */
    CHAR             version;                            /* record version (1)  */
    struct snt_cidr  telnet[SNTIPCTL_MAX_TRUSTED];       /* 10 * 8 = 80 bytes   */
    struct snt_cidr  ssh[SNTIPCTL_MAX_TRUSTED];          /* 10 * 8 = 80 bytes   */
    CHAR             spare[512 - 17 - 160];
};
struct snt_wl4rec {
    CHAR             recid[16];                          /* key: "SNTWL4"       */
    CHAR             version;                            /* record version (1)  */
    struct snt_cidr  wl[SNTIPCTL_MAX_WHITELIST];         /* 50 * 8 = 400 bytes  */
    CHAR             spare[512 - 17 - 400];
};
struct sntip6cfg {
    CHAR             recid[16];                          /* "SNTIPV6WL"/"SNTIPV6W2" */
    CHAR             version;                            /* 1 = 10 entries, 2 = 25  */
    struct snt_cidr6 whitelist6[SNT_V6_PER_REC];         /* 25 * 17 = 425 bytes */
    CHAR             spare[512 - 17 - 425];
};
#pragma pack(pop)

/* Every record must match the length passed to dfaCreateSpec/dfaOpen. */
typedef CHAR snt_proxyrec_is_512[(sizeof(struct snt_proxyrec) == 512) ? 1 : -1];
typedef CHAR snt_wl4rec_is_512[(sizeof(struct snt_wl4rec) == 512) ? 1 : -1];
typedef CHAR sntip6cfg_is_512[(sizeof(struct sntip6cfg) == 512) ? 1 : -1];
typedef CHAR snt_v6_two_recs[(2 * SNT_V6_PER_REC == SNTIPCTL_MAX_WHITELIST6) ? 1 : -1];

/*
 * Key 0: recid[16] at offset 0, non-duplicate string key.
 * Passed to dfaCreateSpec at init so no separate .VIR file is needed.
 */
static struct dfaSegSpec snt_key0_segs[1] = {
    { 0, 16, DFAST_STRING, 0, '\0' }
};
static struct dfaKeySpec snt_key0 = { 0, 1, snt_key0_segs };

/* ======================================================================== */
/*   Forward declarations                                                    */
/* ======================================================================== */

static recv_fn_t *find_iat_recv(HMODULE hMod);
static recv_fn_t  patch_iat_recv(HMODULE hMod, recv_fn_t new_fn);
static GBOOL      cidr_list_match(ULONG ip, const struct snt_cidr *list, INT nlist);
static GBOOL      is_trusted_proxy(ULONG ip);
static GBOOL      is_ssh_trusted_proxy(ULONG ip);
static GBOOL      is_loopback(ULONG ip);
static INT        count_active_ip(const CHAR *ip);
static VOID       parse_gateway_config(CHAR *modname, INT modnamsiz, INT *maxip,
                                        CHAR *bypass, INT bypasssiz,
                                        CHAR *menu, INT menusiz);
static GBOOL      gw_has_bypass_key(const CHAR *bypass);
static GBOOL      gw_other_has_bypass_key(INT channel, const CHAR *bypass);
static INT        count_ip_in_mod(const CHAR *user_ip, INT target_state, const CHAR *bypass);
static VOID       build_ip_users(const CHAR *user_ip, INT target_state, CHAR *buf, INT bufsiz);
static GBOOL      sntipctl_gateway(VOID);
static VOID       build_log_path(const CHAR *subdir, CHAR *buf, INT bufsiz);
static VOID       sntipctl_log_event(const CHAR *subdir, const CHAR *userid, ULONG ip, const CHAR *event);
static VOID       log_event_line(const CHAR *subdir, const CHAR *userid, const CHAR *ipstr, const CHAR *event);
static VOID       log_apply_mode(VOID);
static VOID       snt_audit(const CHAR *subdir, const CHAR *userid, ULONG ip, const CHAR *event);
static VOID       snt_audit_s(const CHAR *subdir, const CHAR *userid, const CHAR *ipstr, const CHAR *event);
static VOID       snt_audit_sx(const CHAR *subdir, const CHAR *userid, const CHAR *ipstr,
                               const CHAR *file_event, const CHAR *audit_event);
static VOID       snt_audit_shocst(const CHAR *detail);
static VOID       dbglog(const CHAR *fmt, ...);
static GBOOL      debug_hook_installed(VOID);
static VOID       dbg_hexdump(const CHAR *label, const CHAR *buf, INT n);
static VOID       log_close_all(VOID);   /* defined with the log-handle cache,
                                          * below sntipctl_fin which calls it */

static GBOOL sntipctl_logon(VOID);
static VOID  sntipctl_hup(VOID);
static VOID  sntipctl_fin(VOID);
static GBOOL sntipctl_stt(VOID);

__declspec(dllexport) VOID      sntipctl_hdlcon(VOID);
__declspec(dllexport) INT       prx_consume_header(SOCKET skt, INT unum);
__declspec(dllexport) INT       prx_ssh_ready(SOCKET skt, INT unum);
__declspec(dllexport) int WINAPI prx_recv_hook(SOCKET s, char *buf, int len, int flags);
static INT        prx_grab_header_line(SOCKET skt, INT unum_for_log, CHAR *out, INT outsz);
static INT        prx_apply_header_line(const CHAR *hdr, INT unum);

static GBOOL cidr_match(ULONG ip, const struct snt_cidr *cidr);
static GBOOL parse_cidr(const CHAR *str, struct snt_cidr *out);
static VOID  cidr_to_str(const struct snt_cidr *cidr, CHAR *buf, INT bufsiz);
static GBOOL is_whitelisted(ULONG ip);
static GBOOL has_bypass_key(VOID);

static GBOOL cidr6_match(const UCHAR ip[16], const struct snt_cidr6 *cidr);
static GBOOL parse_cidr6(const CHAR *str, struct snt_cidr6 *out);
static VOID  cidr6_to_str(const struct snt_cidr6 *cidr, CHAR *buf, INT bufsiz);
static GBOOL is_whitelisted6(const CHAR *ip_text);
static VOID  cfg6_save(VOID);
static VOID  cfg6_load(VOID);
static VOID  cfg_lists_load(VOID);
static VOID  cfg_lists_save(VOID);

static VOID write_ip_to_profile(const CHAR *ip);
static VOID cfg_live_to_struct(VOID);
static VOID cfg_struct_to_live(VOID);
static VOID cfg_save(VOID);
static VOID cfg_load(VOID);
static VOID cfg_after_change(VOID);
static INT  sntipctl_gbl(VOID);
VOID snt_register_tvars(VOID);
static CHAR *snt_tv_version(VOID);

/* ---- settings editor (/TIP, or MENU=SYSOPMENU) ---- */
struct field;
static GBOOL ed_entry(VOID);
static VOID  ed_open(VOID);
static GBOOL ed_allowed(VOID);
static VOID  ed_showtop(VOID);
static VOID  ed_showsect(VOID);
static VOID  ed_setstatus(VOID);
static VOID  ed_fieldvalue(const struct field *f, CHAR *dst, INT dstsz);
static const CHAR *ed_rownote(const struct field *f);
static GBOOL ed_setfield(const struct field *f, const CHAR *input);
static VOID  ed_applyvalue(const struct field *f, const CHAR *value);
static VOID  ed_showchoices(const struct field *f);
static VOID  ed_load_row(INT idx);
static INT   ed_sectof(INT fld);
VOID         ed_build(VOID);

/* ---- GeoIP Location subsystem ---- */
struct geo_loc;                                      /* defined below              */
static VOID  geoip_start(VOID);
static VOID  geoip_stop(VOID);
static VOID  geoip_enqueue(INT channel, const CHAR *ip, const CHAR *userid);
static VOID  geoip_drain(VOID);                      /* rtkick target, main thread */
static unsigned __stdcall geoip_worker(VOID *arg);   /* background thread          */
static GBOOL geoip_http_get(const CHAR *host, const CHAR *path, GBOOL https,
                            INT timeout_s, CHAR *body, INT bodysz, INT *status);
static const CHAR *geoip_default_host(INT provider);
static GBOOL geoip_is_builtin_host(const CHAR *h);
static VOID  geoip_build_url(INT provider, const CHAR *ip, CHAR *host, INT hostsz,
                             CHAR *path, INT pathsz);
static GBOOL geoip_parse_body(INT provider, const CHAR *body, struct geo_loc *out);
static VOID  geo_format(const CHAR *fmt, const struct geo_loc *L, GBOOL inc_country,
                        CHAR *out, INT outsz);
static GBOOL geo_set_field(struct usracc *ua, INT fieldnum, const CHAR *val);
static VOID  geoip_apply(INT channel, const CHAR *userid, const struct geo_loc *L);
static VOID  geoip_log(INT level, const CHAR *userid, const CHAR *ip, const CHAR *event);
static GBOOL geo_cache_lookup(const CHAR *ip, struct geo_loc *out);
static VOID  geo_cache_store(const CHAR *ip, const struct geo_loc *L);
static GBOOL is_private_ip(const CHAR *ip);
static GBOOL json_get_str(const CHAR *body, const CHAR *key, CHAR *out, INT outsz);
static GBOOL json_get_bool_true(const CHAR *body, const CHAR *key);

/* ======================================================================== */
/*   Module interface block                                                  */
/* ======================================================================== */

struct module SNTIPCTL = {
    "",              /* descrp: filled from MDF at init              */
    sntipctl_logon,  /* lonrou: logon supplement                     */
    sntipctl_stt,    /* sttrou: menu entry + settings editor         */
    NULL,            /* stsrou: no status input yet                  */
    NULL,            /* injrou: no injoth handler                    */
    NULL,            /* lofrou: no logoff supplement                 */
    sntipctl_hup,    /* huprou: clear per-channel state on drop      */
    NULL,            /* mcurou: no midnight cleanup                  */
    NULL,            /* dlarou: no delete-account handler            */
    sntipctl_fin     /* finrou: restore hooks and free resources     */
};

/* ======================================================================== */
/*   Module initialization                                                   */
/* ======================================================================== */

/*
 * init__sntipctl -- Called by the BBS when SNTIPCTL.DLL is loaded.
 *
 * Opens the message file, reads configuration, resolves tcpipinf at
 * runtime, hooks hdlcon, and patches recv() in GALTNTD.DLL (or
 * GALTCPIP.DLL as fallback) for no-sleep proxy detection.
 */
VOID EXPORT
init__sntipctl(VOID)
{
    HMODULE hGaltcpip, hGaltntd;
    INT     i;

    shocst("Total IP Control " SNTIPCTL_VERSION, "");
    shocst("By SysopNetwork.com", "initializing");

    stzcpy(SNTIPCTL.descrp, gmdnam("SNTIPCTL.MDF"), MNMSIZ);
    cfgstt = register_module(&SNTIPCTL);

    /*
     * Initialize the log critical section now, before any early return, so
     * sntipctl_fin() can always call DeleteCriticalSection() safely.
     */
    InitializeCriticalSection(&log_cs);

    /* Initialize pending socket table -- no channels pending at startup. */
    for (i = 0; i < MAXNTERM; i++) {
        pending_skt[i]    = INVALID_SOCKET;
        pending_proto[i]  = SNT_PROTO_TELNET;
        snt_conn_proto[i] = SNT_PROTO_UNKNOWN;
        conn_ip_logged[i] = FALSE;
        absorb_count[i]   = 0;
        snt_real_ip[i][0] = '\0';
        early_stash_free(i);
    }


    /* Open the message file (one LEVEL6 block; the BBS builds the .MCV). */
    modmb = opnmsg("SNTIPCTL.MCV");
    if (modmb == NULL)
        shocst("Total IP Control", "WARNING: SNTIPCTL.MCV not found -- ensure SNTIPCTL.MSG is installed in the BBS directory");

    /* First-run defaults -- all features off.  Configure via /TIP. */
    proxy_trust_enabled = FALSE;
    proxy_block_enabled = FALSE;
    setmem((CHAR *)trusted_proxy_cidrs, sizeof(trusted_proxy_cidrs), 0);
    trusted_proxy_count = 0;
    ssh_manage_enabled  = FALSE;
    ssh_hdr_enabled     = FALSE;
    ssh_trust_enabled   = FALSE;
    ssh_block_enabled   = FALSE;
    setmem((CHAR *)ssh_proxy_cidrs, sizeof(ssh_proxy_cidrs), 0);
    ssh_proxy_count     = 0;
    conn_limit_enabled  = FALSE;
    conn_limit_max      = 1;
    log_mode            = LOGM_OFF;
    log_apply_mode();
    usrip_enabled       = FALSE;
    usrip_field         = 1;
    setmem((CHAR *)bypass_key,      sizeof(bypass_key),      0);
    stzcpy(staff_key, "SYSOP", sizeof(staff_key));  /* /WHOSON default access key */
    debug_enabled       = FALSE;                    /* debug trace off by default */
    setmem((CHAR *)whitelist_cidrs, sizeof(whitelist_cidrs), 0);
    setmem((CHAR *)whitelist6_cidrs, sizeof(whitelist6_cidrs), 0);
    whitelist6_count    = 0;

    /* GeoIP Location defaults -- disabled, ipwho.is, 24h cache.
     * Default write mode is SPLIT: city/state -> Address 3, country -> Address 4. */
    geoip_enabled   = FALSE;
    geoip_field     = 3;
    geoip_split     = TRUE;
    geoip_cty_field = 4;
    geoip_cty_fmt   = GEOCF_FULL;
    geoip_reg_fmt   = GEORF_CODE;
    geoip_provider  = GEOPRV_IPWHOIS;
    geoip_use_https = TRUE;
    geoip_timeout   = 5;
    geoip_cache_on     = TRUE;
    geoip_cache_bytime = TRUE;
    geoip_cache_min = 1440;
    geoip_retries   = 1;
    geoip_loglevel  = GEOLOG_NORMAL;
    setmem((CHAR *)geoip_host, sizeof(geoip_host), 0);  /* blank = use provider default host */
    setmem((CHAR *)geoip_key, sizeof(geoip_key), 0);
    stzcpy(geoip_format, "{city}, {region}, {country}", sizeof(geoip_format));

    /*
     * Create SNTIPCTL.DAT only on first run.
     *
     * Calling dfaCreateSpec with overwrite=FALSE when the file already exists
     * causes Btrieve to return status 59 ("file exists, Do Not Replace"),
     * which gserver.exe logs as a spurious "BTRIEVE CREATE ERROR 59" on every
     * subsequent startup.  We guard the call with a file-existence check so
     * Btrieve CREATE is only issued when the file is genuinely absent.
     */
    if (GetFileAttributesA("SNTIPCTL.DAT") == INVALID_FILE_ATTRIBUTES)
        dfaCreateSpec("SNTIPCTL.DAT", FALSE,
                      sizeof(struct sntipctlcfg), 1024, 0, 0, 1, &snt_key0, NULL);
    sntbt = dfaOpen("SNTIPCTL.DAT", (USHORT)sizeof(struct sntipctlcfg), NULL);
    if (sntbt == NULL)
        shocst("Total IP Control", "WARNING: SNTIPCTL.DAT could not be opened -- using built-in defaults");
    cfg_load();
    cfg_lists_load();  /* full proxy and IPv4 whitelist lists (SNTPROXY, SNTWL4) */
    cfg6_load();       /* IPv6 whitelist (SNTIPV6WL, SNTIPV6W2), empty if absent */
    ed_build();        /* the /TIP settings table                               */

    /*
     * Stamp the build into the trace, first line, before anything else can fail.
     * A trace that does not say which build produced it is a trace you cannot
     * reason about: every question of the form "is this the old behaviour or the
     * new?" needs this line to answer, and without it the only version the sysop
     * can see is the config editor's header (which is baked into the .MSG and so
     * goes stale across DLL-only builds).  Cheap insurance against a whole class
     * of wasted diagnosis.
     */
    dbglog("INIT: Total IP Control %s -- debug trace started", SNTIPCTL_VERSION);

    /* Log folders under TOTALIPCONTROL\ are created by the log writer the
     * first time it opens a file there (log_make_dirs), so nothing to do here. */

    if (proxy_trust_enabled)
        shocst("Total IP Control", spr("trusted proxy enforcement enabled (%d CIDR(s) configured)", trusted_proxy_count));
    if (proxy_block_enabled) {
        if (trusted_proxy_count > 0)
            shocst("Total IP Control", spr("require-trusted-proxy ENABLED -- direct/untrusted connections will be refused (%d trusted CIDR(s))", trusted_proxy_count));
        else
            shocst("Total IP Control", "require-trusted-proxy is ON but no trusted CIDRs are configured -- blocking is INACTIVE (fail-safe)");
    }
    if (ssh_manage_enabled) {
        shocst("Total IP Control", spr("SSH management enabled (%d trusted SSH CIDR(s) configured)", ssh_proxy_count));
        if (ssh_trust_enabled)
            shocst("Total IP Control", "SSH trusted proxy enforcement enabled");
        if (ssh_block_enabled) {
            if (ssh_proxy_count > 0)
                shocst("Total IP Control", "SSH require-trusted-proxy ENABLED -- direct/untrusted SSH connections will be refused");
            else
                shocst("Total IP Control", "SSH require-trusted-proxy is ON but no trusted SSH CIDRs are configured -- blocking is INACTIVE (fail-safe)");
        }
    }
    if (conn_limit_enabled)
        shocst("Total IP Control", spr("global connection limit enabled: max %d per IP", conn_limit_max));
    if (log_mode != LOGM_OFF)
        shocst("Total IP Control",
               spr("audit logging: %s",
                   log_mode == LOGM_AUDIT ? "Audit Trail only" :
                   log_mode == LOGM_LOG   ? "log files only (TOTALIPCONTROL)" :
                                            "Audit Trail + log files"));
    if (usrip_enabled)
        shocst("Total IP Control", spr("user profile IP recording enabled (field %d)", usrip_field));
    if (geoip_enabled) {
        /*
         * Not spr(): geoip_host is 64 bytes of sysop-entered text, and with the
         * fixed wording a full-length host reaches 119 of spr()'s 120-byte
         * buffer -- one character from taking the board down at boot.
         */
        CHAR geobuf[160];
        _snprintf(geobuf, sizeof(geobuf),
                  "GeoIP location lookups enabled (host %s, profile field %d)",
                  geoip_host[0] ? geoip_host : geoip_default_host(geoip_provider),
                  geoip_field);
        geobuf[sizeof(geobuf) - 1] = '\0';
        shocst("Total IP Control", "%s", geobuf);
    }

    /* Resolve tcpipinf at runtime. */
    hGaltcpip = GetModuleHandleA("GALTCPIP.DLL");
    if (hGaltcpip == NULL) {
        shocst("Total IP Control", "FATAL: GALTCPIP.DLL not loaded -- proxy detection disabled");
        return;
    }
    pp_tcpipinf = (struct tcpipinf **)GetProcAddress(hGaltcpip, "_tcpipinf");
    if (pp_tcpipinf == NULL) {
        shocst("Total IP Control", "FATAL: _tcpipinf symbol not found -- proxy detection disabled");
        return;
    }

    /*
     * A refused connection is closed through GALTCPIP's own clsskt() rather than
     * closesocket(), so its notification registrations and socket tables are
     * released as it closes -- see the note above snt_refuse_close.  Not fatal if
     * absent: we fall back to closesocket(), and the engine's own reset path
     * (rstchn -> tcprst -> uscauto) releases the tables regardless.
     */
    p_clsskt = (clsskt_fn_t)GetProcAddress(hGaltcpip, "_clsskt");
    if (p_clsskt == NULL)
        shocst("Total IP Control",
               "NOTE: GALTCPIP _clsskt not found -- refused connections will be "
               "closed with closesocket() instead");

    /* hdlcon must already be set by GALTNTD -- load order is required. */
    if (hdlcon == NULL) {
        shocst("Total IP Control", "FATAL: hdlcon is NULL -- SNTIPCTL must load AFTER GALTNTD in wgserv.cfg");
        return;
    }
    hcsave = hdlcon;
    hdlcon = sntipctl_hdlcon;

    /*
     * Patch recv() in GALTNTD.DLL first (preferred: that is where telnet
     * data is actually read).  Fall back to GALTCPIP.DLL if needed.
     *
     * real_recv records the original recv(); each patched slot keeps its own
     * copy for fin-time restoration.  SNTIPCTL.DLL's own calls to recv() bypass
     * the patched IATs via SNTIPCTL's unpatched entry.
     */
    {
        INT patched_ntd = 0;
        hGaltntd = GetModuleHandleA("GALTNTD.DLL");
        if (hGaltntd != NULL) {
            real_recv = patch_iat_recv(hGaltntd, prx_recv_hook);
            if (real_recv != NULL) patched_ntd = 1;
        }
        if (real_recv == NULL)
            real_recv = patch_iat_recv(hGaltcpip, prx_recv_hook);

        if (real_recv != NULL) {
            tnt_recv_hooked = TRUE;
            /* Remember the slot we patched so the debug trace can later check
             * whether our hook is still the value living there (a networking
             * module that patches recv() on connect could overwrite it).
             *
             * Take the slot pointer from the patch record, NOT by calling
             * find_iat_recv() again: that helper locates the recv slot by
             * matching its VALUE against WS2_32!recv, and we have just
             * overwritten the value with prx_recv_hook, so a re-scan would find
             * nothing and hand back NULL (which then reads as a bogus "hook
             * displaced").  patch_iat_recv recorded the real slot pointer, and
             * the telnet/tcpip patch is the first (and, at this point, only)
             * entry -- ssh.dll is patched later. */
            tnt_iat_slot = (iat_patch_count > 0)
                         ? iat_patches[iat_patch_count - 1].slot
                         : NULL;
            shocst("Total IP Control",
                   spr("recv hook installed in %s -- no-sleep mode",
                       patched_ntd ? "GALTNTD" : "GALTCPIP"));
            dbglog("INIT: recv hook installed in %s; slot=%p hook=%p",
                   patched_ntd ? "GALTNTD" : "GALTCPIP",
                   (void *)tnt_iat_slot, (void *)prx_recv_hook);
        } else {
            /*
             * The recv() hook could not be installed -- almost always a load-order
             * problem (SNTIPCTL must load AFTER GALTNTD so GALTNTD.DLL is present
             * for its recv() import to be patched).  We fall back to a best-effort
             * connect-time check (see sntipctl_hdlcon): it catches PROXY headers
             * that have already arrived, but can miss on a fast same-LAN hop and
             * cannot wait without blocking the scheduler.  Detection is degraded,
             * not off; correcting the load order restores reliable no-sleep
             * detection via the hook.
             */
            shocst("Total IP Control", "WARNING: recv() hook not installed -- using best-effort connect-time detection.");
            shocst("Total IP Control", "This can miss the PROXY header on fast local connections (logged with a (fallback) tag).");
            shocst("Total IP Control", "For reliable detection, load SNTIPCTL AFTER GALTNTD in wgserv.cfg, then restart.");
        }
    }

    /*
     * SSH PROXY header support.  SNSSH hands each accepted socket straight to
     * libssh (ssh_bind_accept_fd), so the bytes we must strip are read by
     * ssh.dll, not by SNSSH.DLL -- that is the module whose recv() we hook.
     * ssh.dll is a static import of SNSSH.DLL, so it is already in the process
     * as long as SNSSH loads before SNTIPCTL in wgserv.cfg (it does: the file is
     * ordered alphabetically).  ssh.dll imports recv by ordinal, which
     * find_iat_recv() resolves by comparing the bound address against
     * WS2_32!recv.
     *
     * The hook is installed unconditionally, but it is inert for any socket that
     * sntipctl_hdlcon has not registered in pending_skt[] -- and SSH sockets are
     * only ever registered when ssh_manage_enabled && ssh_hdr_enabled.  So a
     * Sysop can turn SSH header processing on and off in the config editor
     * without a BBS restart, and with the feature off libssh's reads run through
     * an ordinary pass-through call.
     */
    {
        HMODULE hSsh = GetModuleHandleA("ssh.dll");
        if (hSsh != NULL) {
            recv_fn_t ssh_orig = patch_iat_recv(hSsh, prx_recv_hook);
            if (ssh_orig != NULL) {
                ssh_recv_hooked = TRUE;
                if (real_recv == NULL) real_recv = ssh_orig;
                shocst("Total IP Control", "recv hook installed in ssh.dll -- SSH PROXY header support available");
            } else {
                shocst("Total IP Control", "WARNING: could not hook recv in ssh.dll -- SSH PROXY header processing unavailable");
            }
        } else if (ssh_manage_enabled && ssh_hdr_enabled) {
            shocst("Total IP Control", "WARNING: ssh.dll not loaded -- SSH PROXY header processing unavailable (load SNSSH before SNTIPCTL)");
        }
    }

    /*
     * Belt-and-suspenders telnet coverage (the WorldLink real-IP fix).
     *
     * The inbound telnet socket is normally read by GALTNTD (hooked above), but
     * this box also loads other transport modules that import recv() -- GALTCPIP
     * (the core TCP layer, otherwise only patched as a fallback), GALTNT and
     * GALTCPAT.  A packet capture proved the PROXY header does arrive on the
     * wire, yet with WorldLink's link up GALTNTD's hooked recv sometimes sees
     * only the telnet negotiation (the header already gone) -- consistent with a
     * different, unhooked module draining the freshly accepted socket first and
     * discarding the header.  Patch recv() in ALL of them, so the header is
     * stripped and the real IP applied no matter which module reads it first.
     * After this, every socket reader on the box that could touch a telnet fd is
     * hooked; if a PROXY header still never appears, it is not on the wire.
     *
     * Scope of what this exposes (READ THIS BEFORE PATCHING MORE MODULES): a
     * hooked read is inspected when it is for a channel registered in
     * pending_skt[], AND -- since the pre-hdlcon capture was added for WorldLink
     * -- when it is for a socket with no logged-on user, which is every read of
     * every socket these modules touch up to the moment its user reaches ACTUSR.
     * That is inert for anything that is not literally a PROXY header: such a
     * stream is identified in one MSG_PEEK and passed straight through untouched,
     * never delayed and never consumed (see prx_recv_hook).  But "inert" rests on
     * that identification staying strict, so do not loosen it.  Modules not
     * loaded are skipped silently.  GALTCPIP that was already fallback-patched
     * above is de-duplicated by slot in patch_iat_recv, so listing it again is
     * harmless.
     */
    {
        static const CHAR *extra_tnt_mods[] = { "GALTCPIP.DLL", "GALTNT.DLL", "GALTCPAT.DLL" };
        INT k;
        for (k = 0; k < (INT)(sizeof(extra_tnt_mods) / sizeof(extra_tnt_mods[0])); k++) {
            HMODULE hm = GetModuleHandleA(extra_tnt_mods[k]);
            if (hm == NULL) {
                dbglog("INIT: %s not loaded -- no extra telnet recv hook needed", extra_tnt_mods[k]);
                continue;
            }
            if (patch_iat_recv(hm, prx_recv_hook) != NULL) {
                shocst("Total IP Control", spr("recv hook also installed in %s (telnet coverage)", extra_tnt_mods[k]));
                dbglog("INIT: recv hook also installed in %s", extra_tnt_mods[k]);
            } else {
                dbglog("INIT: %s loaded but recv not patched (no recv import, already patched, or patch table full)",
                       extra_tnt_mods[k]);
            }
        }
    }

    shocst("Total IP Control", "hdlcon hook installed -- proxy detection active");

    /*
     * Start the GeoIP background worker + result-drain rtkick.  The
     * infrastructure is always created (it is idle and cheap when the feature
     * is off); actual lookups only occur when geoip_enabled is set.
     */
    geoip_start();

    /* Publish the named text variables used by SNTIPCTL.MSG. */
    snt_register_tvars();

    globalcmd(sntipctl_gbl);
}

/* ======================================================================== */
/*   IAT patch helpers                                                       */
/* ======================================================================== */

/*
 * find_iat_recv
 *
 * Locates the IAT slot for recv() (from WS2_32.dll or wsock32.dll) in hMod.
 * Returns a pointer to the slot so the caller can read or write the address,
 * or NULL if not found.
 */
static recv_fn_t *
find_iat_recv(HMODULE hMod)
{
    BYTE *base = (BYTE *)hMod;
    IMAGE_DOS_HEADER        *dos;
    IMAGE_NT_HEADERS        *nt;
    IMAGE_IMPORT_DESCRIPTOR *imp;
    DWORD rva;

    if (hMod == NULL) return NULL;
    dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    nt  = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (rva == 0) return NULL;

    for (imp = (IMAGE_IMPORT_DESCRIPTOR *)(base + rva); imp->Name != 0; imp++) {
        const char     *dllname = (const char *)(base + imp->Name);
        IMAGE_THUNK_DATA *thunk, *orig;

        if (_stricmp(dllname, "WS2_32.dll")  != 0 &&
            _stricmp(dllname, "wsock32.dll") != 0)
            continue;

        thunk = (IMAGE_THUNK_DATA *)(base + imp->FirstThunk);

        {
            /* Precompute the real recv address for ordinal/stripped matching. */
            recv_fn_t ws2recv = (recv_fn_t)GetProcAddress(
                GetModuleHandleA("WS2_32.DLL"), "recv");

            if (imp->OriginalFirstThunk != 0) {
                /* Match by import name or, for ordinal entries, by address. */
                orig = (IMAGE_THUNK_DATA *)(base + imp->OriginalFirstThunk);
                for (; orig->u1.Function != 0; orig++, thunk++) {
                    if (IMAGE_SNAP_BY_ORDINAL(orig->u1.Ordinal)) {
                        /* Imported by ordinal -- compare against known address. */
                        if (ws2recv != NULL &&
                            (recv_fn_t)(DWORD)thunk->u1.Function == ws2recv)
                            return (recv_fn_t *)&thunk->u1.Function;
                        continue;
                    }
                    {
                        IMAGE_IMPORT_BY_NAME *ibn =
                            (IMAGE_IMPORT_BY_NAME *)(base + orig->u1.AddressOfData);
                        if (_stricmp((const char *)ibn->Name, "recv") == 0)
                            return (recv_fn_t *)&thunk->u1.Function;
                    }
                }
            } else {
                /* OriginalFirstThunk stripped: match by current address. */
                if (ws2recv == NULL) continue;
                for (; thunk->u1.Function != 0; thunk++) {
                    if ((recv_fn_t)(DWORD)thunk->u1.Function == ws2recv)
                        return (recv_fn_t *)&thunk->u1.Function;
                }
            }
        }
    }
    return NULL;
}

/*
 * patch_iat_recv
 *
 * Replaces recv() in hMod's IAT with new_fn.  Returns the original address
 * (used as the real recv and for fin-time restoration) or NULL on failure.
 *
 * Every patched slot is recorded in iat_patches[] with its original value, so
 * sntipctl_fin() can restore all of them -- SNTIPCTL patches more than one
 * module (a telnet module plus ssh.dll).  A slot that is already ours is not
 * re-recorded, so a repeat call can never overwrite the saved original with
 * prx_recv_hook and leave a dangling pointer behind at shutdown.
 */
static recv_fn_t
patch_iat_recv(HMODULE hMod, recv_fn_t new_fn)
{
    recv_fn_t *slot = find_iat_recv(hMod);
    recv_fn_t  old_fn;
    DWORD      old_prot;
    INT        i;

    if (slot == NULL) return NULL;
    old_fn = *slot;
    if (old_fn == new_fn) return NULL;      /* already hooked -- nothing to do  */

    for (i = 0; i < iat_patch_count; i++)
        if (iat_patches[i].slot == slot) return NULL;   /* same slot, seen it   */
    if (iat_patch_count >= SNT_MAX_IAT_PATCH) return NULL;

    VirtualProtect(slot, sizeof(recv_fn_t), PAGE_READWRITE, &old_prot);
    *slot = new_fn;
    VirtualProtect(slot, sizeof(recv_fn_t), old_prot, &old_prot);

    iat_patches[iat_patch_count].slot = slot;
    iat_patches[iat_patch_count].orig = old_fn;
    iat_patch_count++;
    return old_fn;
}

/* ======================================================================== */
/*   Proxy detection                                                         */
/* ======================================================================== */

/*
 * pending_unum_for
 *
 * Maps a socket back to the channel that registered it for PROXY header
 * processing, or -1 if it is not pending.
 *
 * Fast path -- the socket belongs to the CURRENT channel.  This holds for every
 * SSH read (SNSSH's sktnfy() callback and the KEX pump both run under the
 * connecting channel's curusr) and for telnet whenever GALTNTD's recv fires from
 * hdlsock(), which calls curusr(usrnum) first.
 *
 * Cross-channel fallback (the WorldLink fix) -- when WorldLink's link is up,
 * GALTNTD's first recv for a freshly accepted telnet socket can fire while the
 * engine's current channel is a DIFFERENT session.  A packet capture proved the
 * PROXY header arrives and is ACKed, yet the current-channel test above missed
 * it, GALTNTD read the header bytes through unapplied, and the caller was shown
 * the gateway IP.  (Import dumps confirm GALTNTD's recv is the ONLY reader of
 * these sockets -- GALGSBL, the WorldLink modules and the engine import no
 * winsock -- so the consuming read does reach this hook; it just was not being
 * matched.)  So fall back to a scan of pending_skt[] for this handle.
 *
 * The stale-recycled-handle hazard that made the old code refuse to scan is
 * closed by requiring the engine to still agree the matched channel owns s
 * ((*pp_tcpipinf)[j].socket == s): a pending entry left behind for a handle the
 * OS has since reassigned to another channel fails that test, so we never steer
 * onto a live session's stream.  And prx_consume_header only PEEKs until it sees
 * a literal "PROXY " prefix -- its single destructive read happens only on a
 * valid header -- so even a wrong guess is non-destructive.
 */
static INT
pending_unum_for(SOCKET s)
{
    INT j, found;

    if (s == INVALID_SOCKET) return -1;

    /* Fast path: the current channel owns the pending socket. */
    if (usrnum >= 0 && usrnum < MAXNTERM && pending_skt[usrnum] == s)
        return usrnum;

    /*
     * Cross-channel fallback: the read fired under another channel's curusr
     * (WorldLink up).  Accept only a match the engine still agrees owns s.
     */
    found = -1;
    for (j = 0; j < MAXNTERM; j++) {
        if (pending_skt[j] != s) continue;
        if (pp_tcpipinf != NULL && j < nterms &&
            (*pp_tcpipinf)[j].socket == s) {
            found = j;
            break;
        }
    }
    if (found >= 0)
        dbglog("RECV-HOOK: skt=%d read under chan %02x but pending for chan %02x"
               " -- cross-channel match (WorldLink context)",
               (int)s, (usrnum >= 0 ? usrnum + 1 : 0), found + 1);
    return found;
}

/*
 * prx_recv_hook
 *
 * Installed in place of recv() in GALTNTD.DLL (or GALTCPIP.DLL) for telnet, and
 * in ssh.dll -- the libssh library that reads SNSSH's accepted sockets -- for
 * SSH.
 *
 * On the reading daemon's first non-peek recv() call for a pending socket, we
 * intercept, strip the PROXY header, and patch the real IP.  Subsequent recv()
 * calls for the same socket pass through immediately.  A socket that was never
 * registered by sntipctl_hdlcon is passed straight through, which is what makes
 * the hook inert when SSH header processing is switched off.
 *
 * usrnum is valid here: hdlsock() calls curusr(usrnum) before invoking any
 * socket event handler, so it is set to the channel being processed -- for SSH
 * that is SNSSH's sktnfy() callback, from which every libssh read is driven.
 */
__declspec(dllexport) int WINAPI
prx_recv_hook(SOCKET s, char *buf, int len, int flags)
{
    /*
     * Our caller's return address, captured before anything else can clobber it.
     * The IAT patch means a module's own recv() call lands here, so this is the
     * instruction after that module's call site -- which names the reader.  Only
     * ever consumed under debug_enabled; see snt_caller_module.
     */
    VOID *caller_ret = _ReturnAddress();

    if (!(flags & MSG_PEEK) && pp_tcpipinf != NULL) {

        INT unum = pending_unum_for(s);
        if (unum >= 0) {
            /*
             * prx_consume_header returns:
             *    1  -- a complete PROXY header was consumed (IP applied or, if
             *          the source is untrusted, discarded); stream is now clean
             *   -1  -- this is not a PROXY stream; nothing to do
             *    0  -- a PROXY header is still arriving; we must NOT let the
             *          daemon read the partial bytes (that would split the
             *          header and corrupt the stream -- for telnet the cause of
             *          both "real IP not restored" and broken arrow keys; for
             *          SSH it would garble the client's version exchange).
             */
            INT r = prx_consume_header(s, unum);
            dbglog("RECV-HOOK chan %02x: fired for pending skt=%d -> %s",
                   unum + 1, (int)s,
                   r == 1 ? "consumed (done)" :
                   r == 0 ? "header still arriving (WOULDBLOCK, will retry)" :
                            "not a PROXY stream (pass through)");
            if (r == 0) {
                /*
                 * Report "would block" so the daemon's non-blocking event loop
                 * simply retries the read on the next readable event, by which
                 * time more of the (tiny, sent-at-once) header has arrived.
                 * GALTNTD retries directly; libssh turns the WSAEWOULDBLOCK into
                 * SSH_AGAIN, which SNSSH's KEX pump treats as "need more data"
                 * and re-drives on the next notification.  pending_skt is left
                 * set so we try again.  This returns immediately -- still
                 * no-sleep, no polling thread.
                 */
                WSASetLastError(WSAEWOULDBLOCK);
                return SOCKET_ERROR;
            }
            pending_skt[unum] = INVALID_SOCKET;  /* done: consumed or not-proxy */
        } else if (len >= 6 && !socket_has_active_user(s)) {
            /*
             * Pre-hdlcon PROXY capture (the "WorldLink" fix).  The socket is NOT
             * one sntipctl_hdlcon has registered yet, but a hooked recv is about
             * to read it -- typically GALTNTD's own tnordt, woken by the read
             * notification tntincall registered before hdlcon was ever called.
             * That read runs BEFORE our connect handler and would consume the
             * PROXY header, leaving the deferred hook nothing to find, so the
             * caller shows the gateway IP.  See the early_stash note at the top
             * of this file for why hdlcon is not first.
             *
             * Grab the header here, keyed by the raw socket; sntipctl_hdlcon
             * applies the stashed real IP the moment it learns the channel.
             *
             * CRITICAL: this branch is NOT confined to the pre-hdlcon instant.
             * It fires on every read of any socket without a logged-on (ACTUSR)
             * user, which includes the whole login/password sequence -- by then
             * pending_skt has been cleared above, so a user's keystrokes land
             * here.  It may therefore hold the reader off ONLY for a stream it
             * has POSITIVELY identified as a PROXY header (grab == 0 or 1).
             * Anything it cannot positively identify (grab == -1 not a header,
             * grab == -2 too few bytes to tell) must pass straight through
             * untouched.  Getting this wrong swallows keystrokes: treating
             * "too few bytes" as "wait" would hold every Enter at the login
             * prompt, since an Enter keypress is just CR/LF -- which the grab's
             * leading-CR/LF strip reduces to zero usable bytes -- and report
             * it as WSAEWOULDBLOCK, so it never reached the daemon.
             */
            CHAR line[128];
            INT  g = prx_grab_header_line(s, -1, line, sizeof(line));
            if (g == 1) {
                early_stash_put(s, line);
                dbglog("EARLY-PROXY: grabbed PROXY header on NON-PENDING socket=%d "
                       "before hdlcon -- stashed, will apply the real IP at connect", (int)s);
                /*
                 * Name the reader that would have eaten it, and the state of the
                 * channel that owns the socket.  This is the evidence for the
                 * claim that hdlcon is not first: expect the caller to be
                 * GALTNTD (its own telnet reader, woken by the notification
                 * tntincall registers straight after bbscon) and the owning
                 * channel to be usrcls=VACANT(0) state=WCDICN(-30) -- i.e.
                 * bbscon has run and hdlcon has not.  Costs one GetModuleHandleEx
                 * per proxied connect, debug-only.
                 */
                if (debug_enabled) {
                    CHAR who[96];
                    INT  oc = snt_chan_for_socket(s);
                    snt_caller_module(caller_ret, who, sizeof(who));
                    if (oc >= 0)
                        dbglog("   EARLY-PROXY: read came from %s; owning chan %02x "
                               "usrcls=%d state=%d (VACANT=0 WCDICN=-30 => bbscon ran, "
                               "hdlcon has not)",
                               who, oc + 1, usroff(oc)->usrcls, usroff(oc)->state);
                    else
                        dbglog("   EARLY-PROXY: read came from %s; no channel owns "
                               "this socket yet", who);
                }
                /*
                 * The header is now off the wire and stashed; sntipctl_hdlcon
                 * applies the stashed real IP the moment it learns the channel.
                 * Do NOT return a synthetic WSAEWOULDBLOCK here.  The bytes that
                 * follow the header -- an SSH version banner, a telnet client's
                 * first data -- are already sitting in the socket buffer, and
                 * telling the reader "would block" while withholding readable
                 * data deadlocks any reader that only re-drives on a fresh
                 * readability notification.  libssh (SNSSH's KEX pump) is exactly
                 * such a reader: its FD_READ for this arrival was already
                 * consumed, no new byte comes in to re-arm it, and the channel
                 * hangs in WCDICN until the engine reaps it -- observed as ~12
                 * failed SSH connects before one raced through.  Fall through to
                 * a real recv() instead, exactly as the registered-channel path
                 * does after prx_consume_header eats a header: hand the reader
                 * whatever is next, or a genuine WSAEWOULDBLOCK the stack will
                 * re-arm correctly.  (Only g == 0 -- a header still arriving, no
                 * trailing bytes yet -- holds the reader off below.)
                 */
            }
            if (g == 0) {
                /* The full "PROXY " prefix IS present and the rest of the line is
                 * still arriving -- positively a header, so do NOT let the caller
                 * read the partial bytes (that would split it).  Retry later. */
                WSASetLastError(WSAEWOULDBLOCK);
                return SOCKET_ERROR;
            }
            /* g == -1 (not a PROXY stream) or g == -2 (too few bytes to tell):
             * never stall an unidentified stream -- fall through to a normal
             * read.  A header split within its first 6 bytes is given up on
             * rather than risk this; the capture proved the header arrives as a
             * single 46-byte segment well before hdlcon. */
        }
    }

    /* Call through SNTIPCTL.DLL's own unpatched IAT -- no recursion risk. */
    return recv(s, buf, len, flags);
}

/*
/*
 * prx_apply_header_line
 *
 * Parse a complete "PROXY ... \r\n" header line (hdr points at the leading 'P'
 * of "PROXY ") and apply the real client IP to channel unum, subject to the
 * channel's trusted-proxy policy (pending_proto[unum] selects telnet vs SSH).
 *
 * Shared by two callers so their behaviour is byte-for-byte identical: the
 * normal socket path (prx_consume_header) and the pre-hdlcon stash path (a
 * header GALTNTD's own reader took off the socket, via its read notification,
 * before sntipctl_hdlcon could register the channel -- see early_stash).  The
 * header bytes are already consumed by the time we get here, so the return is
 * always 1 (applied, or deliberately not applied when the proxy is untrusted or
 * the header is malformed).
 */
static INT
prx_apply_header_line(const CHAR *hdr, INT unum)
{
    CHAR           proto[16], src_ip[64], dst_ip[64];
    INT            src_port, dst_port, fields;
    struct in_addr real_ip;
    GBOOL          is_ssh;
    GBOOL          trust_on;
    INT            trust_count;
    const CHAR    *proto_name;

    if (pp_tcpipinf == NULL || unum < 0 || unum >= MAXNTERM) return 1;

    is_ssh      = (pending_proto[unum] == SNT_PROTO_SSH);
    trust_on    = is_ssh ? ssh_trust_enabled : proxy_trust_enabled;
    trust_count = is_ssh ? ssh_proxy_count   : trusted_proxy_count;
    proto_name  = is_ssh ? "SSH" : "telnet";

    /*
     * Trusted-proxy enforcement.  The header is consumed in all cases (so the
     * stream is clean for the reading daemon), but the real IP is only APPLIED
     * when the connecting proxy is trusted.  With enforcement off, every header
     * is applied -- i.e. PROXCLIP always runs.
     */
    if (trust_on && trust_count > 0 &&
        !(is_ssh ? is_ssh_trusted_proxy((*pp_tcpipinf)[unum].inaddr.s_addr)
                 : is_trusted_proxy    ((*pp_tcpipinf)[unum].inaddr.s_addr))) {
        if (log_mode != LOGM_OFF) {
            CHAR evtbuf[128];
            struct in_addr a;
            a.s_addr = (*pp_tcpipinf)[unum].inaddr.s_addr;
            _snprintf(evtbuf, sizeof(evtbuf),
                      "chan %02x: %s PROXY header from %s ignored -- not a trusted proxy",
                      unum + 1, proto_name, inet_ntoa(a));
            snt_audit("PROXCLIP LOGS", "(connecting)",
                      (*pp_tcpipinf)[unum].inaddr.s_addr, evtbuf);
            conn_ip_logged[unum] = TRUE;
        }
        if (debug_enabled) {
            struct in_addr a;
            a.s_addr = (*pp_tcpipinf)[unum].inaddr.s_addr;
            dbglog("   chan %02x: PROXY header IGNORED -- peer %s not a trusted "
                   "proxy (real IP NOT applied)", unum + 1, inet_ntoa(a));
        }
        return 1;                            /* consumed but not applied        */
    }

    /* Parse: "PROXY TCP4|TCP6 <src-ip> <dst-ip> <src-port> <dst-port>\r\n" */
    src_port = dst_port = 0;
    fields = sscanf(hdr, "PROXY %15s %63s %63s %d %d",
                    proto, src_ip, dst_ip, &src_port, &dst_port);
    if (fields < 5 ||
        (memcmp(proto, "TCP4", 4) != 0 && memcmp(proto, "TCP6", 4) != 0)) {
        shocst("Total IP Control", spr("chan %02x: bad PROXY header (fields=%d), consumed", unum + 1, fields));
        dbglog("   chan %02x: BAD PROXY header (fields=%d, proto=\"%.8s\"), consumed -- real IP NOT applied",
               unum + 1, fields, proto);
        return 1;
    }

    /*
     * IPv6 caller.  The engine's inaddr is 32-bit IPv4 only, so there is
     * nowhere to put a v6 address for the connection layer; we keep it in our
     * own per-channel text store (snt_real_ip) instead, and everything that
     * counts, records or looks the caller up reads it via snt_source_ip().
     *
     * inaddr is set to 0.0.0.0 -- the "unspecified" address -- rather than
     * being left holding the PROXY's address, which is what it would otherwise
     * keep.  0.0.0.0 is reserved and can never be a real client, so MBBS-side it
     * reads unambiguously as "this channel has no IPv4 address", which is the
     * truth.  Leaving the proxy's address there was actively worse than saying
     * nothing: it is indistinguishable from a genuine caller at that address, so
     * anything reading inaddr silently recorded the firewall as the user.
     *
     * The whitelist and trusted-proxy lists stay v4 and simply never match a v6
     * client (cidr_match rejects 0.0.0.0 against any real CIDR) -- the proxy
     * itself always reaches us over v4, so trust enforcement is unaffected.
     */
    if (memcmp(proto, "TCP6", 4) == 0) {
        struct in_addr mapped;
        INT            v6 = snt_v6_src_check(src_ip, &mapped);

        if (v6 < 0) {
            shocst("Total IP Control",
                   spr("chan %02x: bad IPv6 src in header, consumed", unum + 1));
            dbglog("   chan %02x: BAD IPv6 src \"%.46s\", consumed -- real IP NOT applied",
                   unum + 1, src_ip);
            return 1;
        }
        if (v6 == 0) {
            /* IPv4-mapped: rewrite as dotted quad and use the IPv4 path below. */
            stzcpy(src_ip, inet_ntoa(mapped), sizeof(src_ip));
            dbglog("   chan %02x: IPv4-mapped v6 src unwrapped to %s", unum + 1, src_ip);
        } else {
            stzcpy(snt_real_ip[unum], src_ip, sizeof(snt_real_ip[unum]));
            (*pp_tcpipinf)[unum].inaddr.s_addr = 0;
            if (log_mode != LOGM_OFF) {
                CHAR evtbuf[160];
                _snprintf(evtbuf, sizeof(evtbuf),
                          "chan %02x: %s PROXY header processed, real IPv6 %s",
                          unum + 1, proto_name, src_ip);
                snt_audit_s("PROXCLIP LOGS", "(connecting)", src_ip, evtbuf);
                conn_ip_logged[unum] = TRUE;
            }
            dbglog("   chan %02x: real IPv6 %s recorded (%s proxy)", unum + 1, src_ip, proto_name);
            return 1;
        }
    }

    /* IPv4 caller. */
    real_ip.s_addr = inet_addr(src_ip);
    if (real_ip.s_addr == INADDR_NONE) {
        shocst("Total IP Control", spr("chan %02x: bad src IP in header, consumed", unum + 1));
        return 1;
    }

    (*pp_tcpipinf)[unum].inaddr = real_ip;
    stzcpy(snt_real_ip[unum], src_ip, sizeof(snt_real_ip[unum]));  /* keep text copy in sync */

    dbglog("   chan %02x: real IPv4 %s applied to inaddr (%s proxy)",
           unum + 1, src_ip, proto_name);

    /*
     * The per-connection real-IP record is part of the audit trail, so it is
     * gated by the audit-logging mode.  In OFF mode nothing is emitted; AUDIT
     * writes only the BBS Audit Trail line; LOG writes only the PROXCLIP LOGS
     * file; BOTH writes both.  snt_audit() routes to whichever sinks are on.
     * This connect-time record is how proxied real IPs reach the trail, and
     * conn_ip_logged tells sntipctl_logon not to repeat it at login.
     */
    if (log_mode != LOGM_OFF) {
        CHAR evtbuf[128];
        _snprintf(evtbuf, sizeof(evtbuf),
                  "chan %02x: %s PROXY header processed, real IP %s",
                  unum + 1, proto_name, src_ip);
        snt_audit("PROXCLIP LOGS", "(connecting)", real_ip.s_addr, evtbuf);
        conn_ip_logged[unum] = TRUE;
    }
    return 1;
}

/*
 * prx_consume_header
 *
 * Peeks at the socket buffer.  If a PROXY Protocol v1 header is present,
 * consumes those bytes and patches tcpipinf[unum].inaddr with the real
 * caller IP.  If no valid header is found, the socket is left untouched.
 *
 * When trusted proxy enforcement is enabled, only processes the header if
 * the connecting IP matches a configured trusted proxy address.
 *
 * Which trusted list and enforcement flag apply is decided by the protocol the
 * channel was accepted on, recorded in pending_proto[] by sntipctl_hdlcon: the
 * telnet and SSH policies are configured independently and never share a list.
 */
/*
 * prx_grab_header_line
 *
 * Peek at a socket; if a complete "PROXY ...\r\n" header is present, copy it
 * (starting at the leading 'P' of "PROXY ", NUL-terminated) into out and
 * destructively consume exactly those bytes from the socket.  It stays
 * non-destructive until a full header is confirmed, so a stream that is not a
 * PROXY header is never disturbed.
 *   returns  1 = a complete header was consumed into out
 *            0 = the full "PROXY " prefix IS present but the rest of the line is
 *                still arriving.  This stream is positively a PROXY header, so a
 *                caller may safely hold the daemon off and retry.
 *           -1 = not a PROXY stream (or peer closed / socket error) -- pass through
 *           -2 = undetermined: too few bytes have arrived to tell yet.  The CALLER
 *                decides what this means, and the two callers differ:
 *                  - prx_consume_header (a channel hdlcon has registered) treats
 *                    it as "wait": that channel's very first read IS the header,
 *                    and the wait is latched off by pending_skt the moment we
 *                    resolve, so it cannot leak into the session.
 *                  - the pre-hdlcon capture in prx_recv_hook must NOT wait.  It
 *                    runs on every read of any not-yet-logged-on socket, so a
 *                    bare CR/LF (an Enter keypress at the login prompt, which
 *                    strips to zero usable bytes below) would otherwise be
 *                    reported as "header still arriving" and the keystroke would
 *                    never reach the daemon.
 * unum_for_log only labels the oversized-header warning; pass -1 when no channel
 * is assigned yet (the pre-hdlcon path uses the raw socket in the message).
 */
static INT
prx_grab_header_line(SOCKET skt, INT unum_for_log, CHAR *out, INT outsz)
{
    CHAR  hdr[128];             /* 107-byte max + \r\n + NUL fits easily */
    INT   n, hdr_start, avail, cmplen, hdr_end, i, linelen;
    GBOOL matches;              /* leading bytes are a prefix of "PROXY " */
    static const CHAR PFX[6] = { 'P','R','O','X','Y',' ' };

    /*
     * Peek (non-destructively) at whatever bytes have arrived so far.  We must
     * NOT let the daemon read any data until we have either consumed a full
     * PROXY header or confirmed the stream is not one -- otherwise a header
     * split across TCP reads would be half-consumed, corrupting the input
     * stream (no real IP, and garbled telnet/ANSI -> dead arrow keys).
     */
    n = recv(skt, hdr, (INT)(sizeof(hdr) - 1), MSG_PEEK);
    if (n == 0)
        return -1;   /* peer closed before sending anything -- let the daemon  */
                     /* read the EOF; reporting "wait" here would spin.         */
    if (n < 0) {
        if (WSAGetLastError() == WSAEWOULDBLOCK)
            return -2;                       /* nothing readable yet -- unknown  */
        return -1;   /* a real error (reset, etc.) -- let the daemon see it     */
    }
    hdr[n] = '\0';

    /* Skip leading \r/\n (some proxies/clients emit a stray CR/LF first). */
    hdr_start = 0;
    while (hdr_start < n && (hdr[hdr_start] == '\r' || hdr[hdr_start] == '\n'))
        hdr_start++;
    avail = n - hdr_start;

    /* Only a stream whose leading bytes ARE a prefix of "PROXY " is ever made
     * to wait, so a direct (non-proxy) client is never delayed by this check. */
    cmplen  = (avail < 6) ? avail : 6;
    matches = (GBOOL)(cmplen == 0 || memcmp(hdr + hdr_start, PFX, cmplen) == 0);

    /*
     * Trace the peeked bytes -- but ONLY where they are this module's business.
     *
     * A registered channel (unum_for_log >= 0) is traced as it always has been:
     * that path resolves on a connection's first read or two and then latches
     * itself off via pending_skt, so it only ever dumps the PROXY header or the
     * opening telnet negotiation -- which is the whole diagnostic value.
     *
     * The pre-hdlcon capture (unum_for_log < 0) is a different animal: it is
     * eligible for EVERY read of any socket without a fully logged-on user, and
     * it never latches off.  That is every keystroke between connect and login
     * -- where userids and PASSWORDS are typed -- and every read of a socket
     * that never becomes a BBS channel at all, such as WorldLink's link to its
     * hub, for as long as that link is up.  Dumping all of it wrote user
     * passwords and other boards' traffic into the debug log in plain text, and
     * buried the lines that matter.  So on that path, trace ONLY a positively
     * identified PROXY header; anything else is none of our business and is
     * passed through without a word.
     */
    if (unum_for_log >= 0 || (matches && avail >= 6))
        dbg_hexdump("peeked", hdr, n);

    if (!matches)
        return -1;                           /* definitely not a PROXY header   */
    if (avail < 6)
        return -2;   /* Not enough bytes to say either way.  NOTE avail can be 0 */
                     /* here -- an Enter keypress is exactly the CR/LF the strip */
                     /* above removes -- so this must stay "undetermined" and    */
                     /* never "wait", or a caller that holds the daemon off on    */
                     /* "wait" would swallow the keystroke.                       */

    /* Full "PROXY " prefix present.  Locate the \r\n line terminator. */
    hdr_end = -1;
    for (i = hdr_start; i < n - 1; i++) {
        if (hdr[i] == '\r' && hdr[i + 1] == '\n') {
            hdr_end = i + 2;
            break;
        }
    }
    if (hdr_end < 0) {
        /* Line not finished arriving.  Keep waiting unless the peek buffer is
         * full, in which case the header is malformed/oversized -- give up. */
        if (n >= (INT)(sizeof(hdr) - 1)) {
            if (unum_for_log >= 0)
                shocst("Total IP Control", spr("chan %02x: oversized/unterminated PROXY header, passing through", unum_for_log + 1));
            else
                shocst("Total IP Control", spr("skt %d: oversized/unterminated PROXY header, passing through", (int)skt));
            return -1;
        }
        return 0;
    }

    /* Destructively consume exactly the header bytes (including the \r\n). */
    recv(skt, hdr, hdr_end, 0);

    linelen = hdr_end - hdr_start;
    if (linelen >= outsz) linelen = outsz - 1;
    memcpy(out, hdr + hdr_start, linelen);
    out[linelen] = '\0';
    return 1;
}

/*
 * prx_consume_header
 *
 * Peeks at the socket buffer.  If a PROXY Protocol v1 header is present,
 * consumes those bytes and patches tcpipinf[unum].inaddr with the real
 * caller IP.  If no valid header is found, the socket is left untouched.
 *   return  0 = need more data (caller holds the daemon off and retries)
 *   return  1 = a complete header was consumed (applied or discarded)
 *   return -1 = not a PROXY stream (caller lets the daemon read normally)
 *
 * Which trusted list and enforcement flag apply is decided by the protocol the
 * channel was accepted on, recorded in pending_proto[] by sntipctl_hdlcon.
 */
__declspec(dllexport) INT
prx_consume_header(SOCKET skt, INT unum)
{
    CHAR line[128];
    INT  r;

    if (pp_tcpipinf == NULL) return -1;     /* can't process -- treat as done */
    if (unum < 0 || unum >= MAXNTERM) return -1;

    r = prx_grab_header_line(skt, unum, line, sizeof(line));
    if (r == -2) return 0;   /* Undetermined -> wait.  Right for a REGISTERED
                              * channel: its first read is the header, and
                              * pending_skt latches this path off as soon as we
                              * resolve, so the wait can never reach the session's
                              * keystrokes (unlike the pre-hdlcon path). */
    if (r != 1) return r;                    /* 0 = wait, -1 = not a PROXY stream */
    return prx_apply_header_line(line, unum);
}

/*
 * prx_ssh_ready
 *
 * A daemon that wants to cooperate instead of relying solely on the recv()
 * hook calls this BEFORE touching the socket's data, and skips this read
 * cycle entirely (waiting for the next readable notification) if it comes
 * back FALSE.  SNSSH is the reason this exists: libssh's own poll layer does
 * its own select() immediately before ever calling recv(), and treats ANY
 * negative recv() return -- WSAEWOULDBLOCK included, no exception made for
 * it -- as an unconditionally fatal socket exception, with no retry.  That
 * makes the recv()-hook's usual "fake WSAEWOULDBLOCK, try again later"
 * signal (see prx_recv_hook's r==0 case) fatal for an SSH session: libssh
 * has already committed to calling recv() by the time our hook can answer,
 * so no return value at that point can avoid killing it. The only way to
 * make libssh wait is to make sure it never asks in the first place -- if
 * SNSSH skips this cycle here, libssh's own select() sees nothing new this
 * time and quietly does nothing, rather than being told "readable" and then
 * contradicted at the recv() layer.
 *
 * Returns:
 *    1 = safe to read now -- nothing pending on this socket, or a header
 *        was JUST resolved by this very call (consumed/applied, or
 *        positively determined not to be one).  Any real bytes behind a
 *        freshly-consumed header are left in the socket for the caller's
 *        own subsequent recv() to pick up normally.
 *    0 = NOT safe yet -- a PROXY header has positively started arriving on
 *        this socket but is still incomplete.  Nothing has been consumed;
 *        ask again after the next readable notification.
 *
 * Reuses prx_consume_header's own header detection (gated the same way
 * prx_recv_hook gates it, by pending_skt[unum]), so a header resolved here
 * and one the recv() hook would otherwise have caught can never disagree --
 * this only ever runs that same resolution earlier, never a different one.
 * Safe to call on any socket, pending or not: a socket with nothing pending
 * costs nothing beyond the array check below.
 *
 * sntipctl_hdlcon may not have run for this channel yet when this is
 * called -- SNSSH's own read notification can fire before TIP's connect
 * handler gets its turn (see the early_stash notes above), which is
 * exactly the case pending_skt[unum] cannot answer, since TIP has not
 * learned about this channel at all yet.  This was the gap that let the
 * original bug keep reproducing even after this function was added: every
 * failure was on chan 01's FIRST-ever byte, at 0ms from bbscon, which is
 * precisely this window.  When pending_skt[unum] does not match, we fall
 * back to the same peek prx_recv_hook's own pre-hdlcon branch uses.  A
 * complete header found here is stashed via early_stash_put(), NOT applied
 * directly: prx_apply_header_line() needs pending_proto[unum], which only
 * sntipctl_hdlcon sets, so applying it here (before hdlcon has run) could
 * check the wrong protocol's trusted-proxy list.  sntipctl_hdlcon's
 * existing early_stash_take() picks it up and applies it correctly the
 * moment it runs, exactly as it already does for the WorldLink case.
 */
__declspec(dllexport) INT
prx_ssh_ready(SOCKET skt, INT unum)
{
    CHAR line[128];
    INT  g;

    if (pp_tcpipinf == NULL) return 1;          /* can't process -- don't stall */
    if (unum < 0 || unum >= MAXNTERM) return 1;

    if (pending_skt[unum] == skt) {
        return (prx_consume_header(skt, unum) != 0);
    }

    /* Not yet registered with TIP -- peek directly, same as prx_recv_hook's
     * own pre-hdlcon branch.  unum_for_log=-1 matches that branch's logging
     * discipline (trace only a positively-identified header on this path,
     * never arbitrary pre-login bytes -- see prx_grab_header_line's own
     * comment on why). */
    g = prx_grab_header_line(skt, -1, line, sizeof(line));
    if (g == 0) return 0;             /* positively a header, still incomplete */
    if (g == 1) early_stash_put(skt,line); /* complete -- hdlcon applies it */
    return 1;                         /* consumed, not-a-header, or undetermined */
}

/*
 * sntipctl_hdlcon
 *
 * The BBS "handle connect" vector, reached for every new connection on every
 * registered daemon -- GALTNTD calls it for telnet, and SNSSH reaches it via
 * bbscon() for SSH.
 *
 * Records the socket as pending for PROXY header processing, then hands
 * off to the next handler immediately via hcsave() -- no sleeping or polling.
 * When the daemon later calls recv() for this socket, prx_recv_hook fires
 * and consumes the PROXY header before the daemon sees any data.
 *
 * If the recv hook is unavailable (IAT patch failed), falls back to a
 * single non-blocking FIONREAD check as a best-effort measure.
 */
__declspec(dllexport) VOID
sntipctl_hdlcon(VOID)
{
    SOCKET         skt;
    struct svrinf *svr;
    GBOOL          is_telnet, is_ssh;
    CHAR           stashed[128];
    GBOOL          got_stash;

    if (pp_tcpipinf == NULL || usrnum < 0 || usrnum >= nterms) {
        hcsave();
        return;
    }

    skt = (*pp_tcpipinf)[usrnum].socket;

    /*
     * Collect any pre-hdlcon PROXY capture for this socket NOW, before any of the
     * refusal paths below can return early.  prx_recv_hook stashes a header it
     * grabbed from a socket that had no channel yet (the WorldLink routing-peek
     * path); this is the one point every exit from this function passes through,
     * so taking it here is what guarantees an entry cannot outlive the connect it
     * belongs to.  That matters concretely: a capture left behind by a connection
     * we then REFUSE would still be in the table when the OS recycles the handle,
     * and the next caller to land on that handle would be given the refused
     * connection's IP -- an IP a direct attacker chose, since the header is
     * grabbed before any trust check runs.  Whether we APPLY what we took is
     * decided below; only a channel we actually process headers for gets it, and
     * anything else is simply dropped here.
     */
    got_stash = early_stash_take(skt, stashed, sizeof(stashed));

    conn_ip_logged[usrnum] = FALSE;

    /*
     * Reset the real-IP text store at CONNECT, not just at hangup.  The engine
     * reassigns inaddr for every new session, so our parallel store must have
     * the same per-session lifecycle -- clearing it only in sntipctl_hup is not
     * enough, because a prior occupant's teardown can be skipped or race a fast
     * channel reuse, leaving a stale address that /myip and /whoson would then
     * show for the new user.  Cleared here so a session starts with no address
     * until its own PROXY header (if any) repopulates it; a direct connection
     * leaves it empty and snt_tv_ip falls back to the engine's inaddr.
     */
    snt_real_ip[usrnum][0] = '\0';

    /*
     * Identify the daemon that accepted this channel.  Every proxy policy below
     * is keyed off it: telnet and SSH are enforced independently, and Rlogin /
     * FTP / any other registered server is left entirely alone.
     */
    svr       = (*pp_tcpipinf)[usrnum].server;
    is_telnet = (GBOOL)(svr != NULL && svr->name != NULL &&
                        strcmp(svr->name, SNT_TELNET_SVRNAME) == 0);
    is_ssh    = (GBOOL)(svr != NULL && svr->name != NULL &&
                        strcmp(svr->name, SNT_SSH_SVRNAME) == 0);

    /* Record the connection type for SNTTIPCT now, unconditionally -- every
     * accepted channel gets one, regardless of whether PROXY header
     * processing is enabled (see snt_conn_proto's declaration comment).
     * Neither telnet nor SSH (WorldLink, Rlogin, FTP, ...) records UNKNOWN,
     * not a false TELNET. */
    snt_conn_proto[usrnum] = is_ssh    ? SNT_PROTO_SSH
                            : is_telnet ? SNT_PROTO_TELNET
                            : SNT_PROTO_UNKNOWN;

    /*
     * Debug trace: one line per connect, naming the daemon (so a WorldLink or
     * other module connecting is plainly visible in the same trail as telnet)
     * and -- crucially -- reporting whether our recv() hook is still installed
     * in the telnet module.  If hook=NO appears the instant another daemon
     * connects, that daemon knocked our hook out and that is why the real IP
     * stops being restored.
     */
    if (debug_enabled) {
        struct in_addr ra;
        struct sockaddr_in pn;
        INT pnlen = (INT)sizeof(pn);
        INT rawport = -1;
        ra.s_addr = (*pp_tcpipinf)[usrnum].inaddr.s_addr;
        /* getpeername gives the relay's source port -- the key that identifies
         * this exact TCP stream in a packet capture, so a failing connection in
         * the trace can be matched to its stream on the wire. */
        if (skt != INVALID_SOCKET &&
            getpeername(skt, (struct sockaddr *)&pn, &pnlen) == 0)
            rawport = (INT)ntohs(pn.sin_port);
        dbglog("CONNECT chan %02x: server=\"%s\" %s skt=%d raw-ip=%s raw-port=%d hook=%s",
               usrnum + 1,
               (svr != NULL && svr->name != NULL) ? svr->name : "(none)",
               is_telnet ? "TELNET" : is_ssh ? "SSH" : "other",
               (int)skt, inet_ntoa(ra), rawport,
               debug_hook_installed() ? "YES" : "NO (recv hook displaced!)");
    }

    /*
     * Require-trusted-proxy enforcement.  When enabled for the connecting
     * protocol (and at least one trusted proxy CIDR is configured for it),
     * refuse any connection whose raw source IP is not one of that protocol's
     * trusted proxies -- before the caller ever reaches a login prompt.
     *
     * The IP examined here is the RAW TCP peer IP (the proxy's address for a
     * relayed connection, or the client's own address for a direct one) -- it
     * has not yet been rewritten by the PROXY-header recv hook.  So:
     *   - relayed via a trusted proxy  -> raw IP is the trusted proxy -> allow
     *   - direct to the backend port   -> raw IP is the client        -> block
     *   - relayed via an unknown proxy -> raw IP is that proxy         -> block
     *
     * Loopback (local console) and connection-limit whitelist IPs are always
     * allowed so a misconfigured CIDR cannot lock the host or trusted admins
     * out.  An empty trusted list disables blocking entirely (fail-safe).
     *
     * No MBBS session exists yet, so a refused connection is torn down at the
     * socket level.  How that is done differs per protocol -- see the two
     * branches below.
     */
    {
        /*
         * The require-trusted-proxy block is enforced per protocol, against that
         * protocol's own trusted list.  Telnet uses proxy_block_enabled and the
         * telnet CIDRs; SSH uses ssh_block_enabled and the SSH CIDRs, and only
         * when ssh_manage_enabled gates it on.  Rlogin, FTP and every other
         * registered daemon are never refused here.
         *
         * This gates ONLY the block.  The per-IP connection limit, audit
         * logging, GeoIP, and profile-IP recording all live in the protocol-
         * agnostic logon path (sntipctl_logon) and rely only on the real client
         * IP, so they keep applying to every daemon unchanged.
         */
        GBOOL block_on = is_telnet ? (proxy_block_enabled && trusted_proxy_count > 0)
                       : is_ssh    ? (ssh_manage_enabled && ssh_block_enabled &&
                                      ssh_proxy_count > 0)
                                   : FALSE;

        if (block_on && skt != INVALID_SOCKET) {

            ULONG raw_ip = (*pp_tcpipinf)[usrnum].inaddr.s_addr;

            /*
             * Say why a connection we were prepared to block was let through.
             * Without this the trace records only refusals, so an unexpected
             * caller getting in looks like the block silently failing, and the
             * only way to tell a too-broad CIDR from a whitelist hit is to read
             * the source.  The exemptions are reported in the order the test
             * below applies them.
             */
            if (debug_enabled) {
                struct in_addr a;
                const CHAR    *why = NULL;
                a.s_addr = raw_ip;

                if (raw_ip == 0)                 why = "raw IP unknown";
                else if (is_loopback(raw_ip))    why = "loopback (local console)";
                else if (is_whitelisted(raw_ip)) why = "matches the connection-limit whitelist";
                else if (is_ssh ? is_ssh_trusted_proxy(raw_ip)
                                : is_trusted_proxy(raw_ip))
                                                 why = "matches a trusted proxy CIDR";
                if (why != NULL)
                    dbglog("   chan %02x: ALLOWED -- %s from %s %s "
                           "(require-trusted-proxy is ON)",
                           usrnum + 1, is_ssh ? "SSH" : "telnet", inet_ntoa(a), why);
            }

            if (raw_ip != 0 &&
                !is_loopback(raw_ip) &&
                !is_whitelisted(raw_ip) &&
                !(is_ssh ? is_ssh_trusted_proxy(raw_ip) : is_trusted_proxy(raw_ip))) {

                if (log_mode != LOGM_OFF) {
                    CHAR evtbuf[128];
                    struct in_addr a;
                    a.s_addr = raw_ip;
                    _snprintf(evtbuf, sizeof(evtbuf),
                              "chan %02x: direct/untrusted %s from %s refused -- require trusted proxy",
                              usrnum + 1, is_ssh ? "SSH" : "telnet", inet_ntoa(a));
                    snt_audit("DENIED CONNECTIONS", "(connecting)", raw_ip, evtbuf);
                }

                /*
                 * Trace it too.  This path returns without reaching any of the
                 * lines below, so without this the debug trace shows a CONNECT
                 * and then simply stops -- the connection appears to evaporate,
                 * with nothing saying we refused it on purpose.  A trace that
                 * goes quiet at the interesting moment is how this module's
                 * hardest bug stayed hidden for ten builds; do not make a reader
                 * cross-reference a different log to find out what happened.
                 */
                if (debug_enabled) {
                    struct in_addr a;
                    a.s_addr = raw_ip;
                    dbglog("   chan %02x: REFUSED at connect -- %s from %s is not a "
                           "trusted proxy (require-trusted-proxy is ON); connection dropped",
                           usrnum + 1, is_ssh ? "SSH" : "telnet", inet_ntoa(a));
                }

                pending_skt[usrnum] = INVALID_SOCKET;

                if (is_ssh) {
                    /*
                     * SSH must be refused differently from telnet, because by the
                     * time we get here SNSSH has ALREADY handed the socket to
                     * libssh (ssh_bind_accept_fd) -- we reach hdlcon from the
                     * bbscon() call that follows it.  libssh owns the descriptor
                     * from that point on and closes it itself in ssh_free().
                     * Closing it here, as the telnet path does, would leave libssh
                     * to close a descriptor the OS may already have reused for an
                     * unrelated connection.
                     *
                     * shutdown() instead tears down the CONNECTION while leaving
                     * the descriptor valid and owned by libssh.  The next read on
                     * it returns EOF, so SNSSH's key-exchange pump fails the
                     * session and runs its normal teardown (snssh_drop -> reap ->
                     * ssh_free + bbsdsc), releasing the channel and the socket
                     * exactly once.  That happens promptly: snssh_incall starts
                     * the key exchange itself on the line after bbscon() returns.
                     * We therefore also fall through to hcsave() rather than
                     * returning early: the channel must complete its normal
                     * connect so that teardown can unwind it.
                     *
                     * No refusal text is sent.  Nothing has been negotiated yet,
                     * so plaintext written now would land in the middle of the SSH
                     * version exchange and the client would report a protocol
                     * error rather than display it.  The refusal is recorded in
                     * the audit log instead; the client simply sees the connection
                     * close.
                     */
                    shutdown(skt, SD_BOTH);
                }
                else {
                    /*
                     * Telnet: refuse at the door.  This must run ahead of hcsave()
                     * (GALTNTD's own hdlcon).  If we let GALTNTD claim the channel
                     * first and only then closed the socket, both GALTNTD and
                     * GALTCPIP would still hold their own copy of the now-closed
                     * socket handle and would try to flush the login banner to it
                     * on the next scheduler cycle -- which is exactly what produced
                     * the audit-trail "TCP/IP ERROR ... SEND error 10038 (Socket
                     * operation on non-socket)" and the garbled trailing bytes
                     * after the refusal message.  By rejecting here and returning
                     * WITHOUT calling hcsave(), the channel is never activated and
                     * nothing is ever sent to the dead socket.
                     */
                    snt_send_msg(skt, PRXBLK);
                    snt_refuse_close(skt);   /* drain + close; never blocks */
                    (*pp_tcpipinf)[usrnum].socket = INVALID_SOCKET;
                    return;  /* refused at the door -- never hand off to GALTNTD */
                }

                hcsave();    /* SSH: let the channel connect so SNSSH can tear it down */
                return;
            }
        }
    }

    if (skt != INVALID_SOCKET) {
        /*
         * Register the socket for PROXY header processing, but only if the
         * module that will read it is actually hooked.
         *
         * SSH additionally requires the Sysop to have asked for it: registering
         * a socket whose reads we cannot intercept would strip nothing and would
         * merely suppress the connect-time connection-limit check below.  Telnet
         * (and anything else whose reads reach the patched telnet module) is
         * registered as it always has been.
         */
        GBOOL want_hdr = is_ssh
                       ? (ssh_manage_enabled && ssh_hdr_enabled && ssh_recv_hooked)
                       : tnt_recv_hooked;

        /*
         * A capture we are not going to apply was already released by the take at
         * the top; say so, because silently eating a header would otherwise look
         * exactly like the bug this whole path exists to fix.
         */
        if (got_stash && !want_hdr)
            dbglog("   chan %02x: pre-hdlcon PROXY header captured but header "
                   "processing is not enabled for this channel -- discarded", usrnum + 1);

        if (want_hdr) {
            /*
             * Register the deferred recv-hook as before -- it stays the backstop
             * that strips the header on GALTNTD's first recv whenever nothing
             * beat it to the bytes.  pending_proto must be set BEFORE any consume
             * so the right trusted-proxy policy applies.
             */
            pending_proto[usrnum] = is_ssh ? SNT_PROTO_SSH : SNT_PROTO_TELNET;
            pending_skt[usrnum]   = skt;

            /*
             * Pre-hdlcon capture (the "WorldLink" fix).  If GALTNTD's reader
             * already took the PROXY header off this socket before we ran,
             * prx_recv_hook stashed it by socket handle and the take at the top of
             * this function collected it.  Now that we know the channel, apply it
             * -- this is what recovers the real IP when WorldLink is up.
             * pending_proto is set above so the right trusted-proxy policy
             * applies (the trust check is deferred to here precisely because it
             * needs the channel).  On a hit the header is already off the wire,
             * so clear pending_skt: there is nothing left for the recv hook to do.
             *
             * On a miss we simply register and leave: the deferred recv hook
             * strips the header on the daemon's first read.  There is deliberately
             * no connect-time wait for a header that has not arrived yet.  A
             * connect-time wait was tried and did NOT beat WorldLink -- the
             * header is gone before hdlcon even runs, which
             * is what the stash above exists to catch -- so all it did was stall
             * the BBS's single cooperative scheduler for up to 40ms on every
             * connection whose first bytes had not landed yet.  That is every
             * silent direct client and every port scanner.  The deferred hook has
             * handled this correctly since 1.0.0 and costs nothing.
             */
            if (got_stash) {
                prx_apply_header_line(stashed, usrnum);
                pending_skt[usrnum] = INVALID_SOCKET;
                dbglog("   chan %02x: applied stashed pre-hdlcon PROXY header -- "
                       "real IP recovered (pre-hdlcon capture), skt=%d",
                       usrnum + 1, (int)skt);
            } else {
                dbglog("   chan %02x: registered pending skt=%d proto=%s -- awaiting recv-hook",
                       usrnum + 1, (int)skt, is_ssh ? "SSH" : "TELNET");
            }
        } else if (!is_ssh && !tnt_recv_hooked) {
            /*
             * Best-effort fallback, used ONLY when the recv() hook could not be
             * installed (almost always a wgserv.cfg load-order issue -- SNTIPCTL
             * must load AFTER GALTNTD).  A single non-blocking check right now: if
             * the PROXY header has already arrived it is parsed and the real IP
             * applied.  On a fast same-LAN hop the header may not be present yet,
             * in which case it is missed -- this path cannot wait without blocking
             * the scheduler, so it is a stopgap; the reliable path is the recv
             * hook (see the startup warning).  A successful parse is logged with a
             * "(fallback)" tag so the sysop can see this path is in use.  Never
             * run for SSH: with no hook there is no SSH header support, and a
             * destructive read here would steal bytes from libssh.
             */
            u_long avail = 0;
            ioctlsocket(skt, FIONREAD, &avail);
            dbglog("   chan %02x: FALLBACK path (no recv hook) skt=%d avail=%lu",
                   usrnum + 1, (int)skt, (unsigned long)avail);
            if (avail >= 6) {
                CHAR   hdr[128];
                INT    n, hdr_start, hdr_end, ii, fields;
                CHAR   proto[16], src_ip[64], dst_ip[64];
                INT    sp, dp;
                struct in_addr real_ip;

                n = recv(skt, hdr, (INT)(sizeof(hdr) - 1), MSG_PEEK);
                if (n >= 6) {
                    hdr[n] = '\0';
                    hdr_start = 0;
                    while (hdr_start < n && (hdr[hdr_start] == '\r' || hdr[hdr_start] == '\n'))
                        hdr_start++;
                    if ((n - hdr_start) >= 6 && memcmp(hdr + hdr_start, "PROXY ", 6) == 0) {
                        if (!proxy_trust_enabled || trusted_proxy_count == 0 ||
                            is_trusted_proxy((*pp_tcpipinf)[usrnum].inaddr.s_addr)) {
                            hdr_end = -1;
                            for (ii = 0; ii < n - 1; ii++) {
                                if (hdr[ii] == '\r' && hdr[ii + 1] == '\n') {
                                    hdr_end = ii + 2;
                                    break;
                                }
                            }
                            if (hdr_end > 0) {
                                recv(skt, hdr, hdr_end, 0);
                                hdr[hdr_end] = '\0';
                                sp = dp = 0;
                                fields = sscanf(hdr + hdr_start,
                                                "PROXY %15s %63s %63s %d %d",
                                                proto, src_ip, dst_ip, &sp, &dp);
                                if (fields >= 5 && memcmp(proto, "TCP6", 4) == 0) {
                                    /*
                                     * IPv6 caller.  This must behave EXACTLY as
                                     * prx_apply_header_line's v6 branch does --
                                     * validate first, unwrap an IPv4-mapped
                                     * address, record the text, and zero inaddr.
                                     *
                                     * Zeroing inaddr is not cosmetic here: leave
                                     * it holding the PROXY's address and the
                                     * v4-only whitelist at logon tests the
                                     * FIREWALL instead of the caller, so a
                                     * perfectly ordinary "don't limit my LAN"
                                     * entry would silently exempt every IPv6
                                     * user from the connection limit.
                                     */
                                    struct in_addr mapped;
                                    INT            v6 = snt_v6_src_check(src_ip, &mapped);

                                    if (v6 < 0) {
                                        dbglog("   chan %02x: BAD IPv6 src \"%.46s\" (fallback) -- NOT applied",
                                               usrnum + 1, src_ip);
                                    } else if (v6 == 0) {
                                        real_ip.s_addr = mapped.s_addr;
                                        (*pp_tcpipinf)[usrnum].inaddr = real_ip;
                                        stzcpy(snt_real_ip[usrnum], inet_ntoa(mapped),
                                               sizeof(snt_real_ip[usrnum]));
                                    } else {
                                        stzcpy(snt_real_ip[usrnum], src_ip, sizeof(snt_real_ip[usrnum]));
                                        (*pp_tcpipinf)[usrnum].inaddr.s_addr = 0;
                                        if (log_mode != LOGM_OFF) {
                                            CHAR evtbuf[160];
                                            _snprintf(evtbuf, sizeof(evtbuf),
                                                      "chan %02x: telnet PROXY header processed, real IPv6 %s (fallback)",
                                                      usrnum + 1, src_ip);
                                            snt_audit_s("PROXCLIP LOGS", "(connecting)", src_ip, evtbuf);
                                        }
                                    }
                                } else if (fields >= 5 && memcmp(proto, "TCP4", 4) == 0) {
                                    real_ip.s_addr = inet_addr(src_ip);
                                    if (real_ip.s_addr != INADDR_NONE) {
                                        (*pp_tcpipinf)[usrnum].inaddr = real_ip;
                                        stzcpy(snt_real_ip[usrnum], src_ip, sizeof(snt_real_ip[usrnum]));
                                        if (log_mode != LOGM_OFF) {
                                            CHAR evtbuf[128];
                                            _snprintf(evtbuf, sizeof(evtbuf),
                                                      "chan %02x: telnet PROXY header processed, real IP %s (fallback)",
                                                      usrnum + 1, src_ip);
                                            snt_audit("PROXCLIP LOGS", "(connecting)", real_ip.s_addr, evtbuf);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /*
     * Pre-login global connection-limit enforcement for non-proxy (direct)
     * connections whose real IP is already known at connect time.  Proxy
     * connections have pending_skt set here (the real IP is not resolved until
     * the recv hook consumes the PROXY header), so they are enforced later in
     * sntipctl_logon via byenow() instead.
     *
     * Restricted to telnet.  The refusal below closes the socket and returns
     * WITHOUT calling hcsave(), so GALTNTD never activates the channel and never
     * tries to send to the closed socket -- correct for telnet, but wrong for a
     * daemon that already owns the descriptor (see the SSH branch of the block
     * above).  SSH and every other protocol are limited at logon instead, by the
     * byenow() path in sntipctl_logon, which is where they have always been
     * enforced: pending_skt was previously set for every channel, so this
     * connect-time check never ran for them anyway.
     */
    if (is_telnet && pending_skt[usrnum] == INVALID_SOCKET) {

        ULONG  user_v4  = (*pp_tcpipinf)[usrnum].inaddr.s_addr;
        SOCKET skt_chk  = (*pp_tcpipinf)[usrnum].socket;
        CHAR   user_ip[46];

        snt_source_ip(usrnum, user_ip, sizeof(user_ip));

        /*
         * user_v4 gates this check and feeds the v4-only whitelist; user_ip is
         * the identity we count by.  An IPv6 caller has user_v4 == 0 and so is
         * not checked here at all -- they are limited at logon instead, which is
         * where every non-telnet protocol has always been enforced.
         */
        if (user_v4 != 0 && skt_chk != INVALID_SOCKET &&
            conn_limit_enabled &&
            !is_whitelisted(user_v4) &&
            count_active_ip(user_ip) >= conn_limit_max) {

            if (log_mode != LOGM_OFF) {
                CHAR evtbuf[128];
                _snprintf(evtbuf, sizeof(evtbuf),
                          "chan %02x: %s rejected at connect -- per-IP limit (%d max)",
                          usrnum + 1, user_ip, conn_limit_max);
                snt_audit_s("DENIED CONNECTIONS", "(connecting)", user_ip, evtbuf);
            }

            build_ip_users(user_ip, -1, tv_users, sizeof(tv_users));
            snt_send_msg(skt_chk, CLIMIT);
            snt_refuse_close(skt_chk);   /* drain + close; never blocks */
            (*pp_tcpipinf)[usrnum].socket = INVALID_SOCKET;
            pending_skt[usrnum] = INVALID_SOCKET;
            return;  /* refused -- never hand off to GALTNTD */
        }
    }

    /* Connection accepted -- hand off to GALTNTD's own hdlcon. */
    hcsave();
}

/* ======================================================================== */
/*   Connection limiting helpers                                             */
/* ======================================================================== */

/*
 * cidr_match
 *
 * Returns TRUE if ip falls within the given CIDR entry.
 * An all-zero entry is treated as "not set" and never matches.
 */
static GBOOL
cidr_match(ULONG ip, const struct snt_cidr *cidr)
{
    if (cidr->addr == 0 && cidr->mask == 0) return FALSE;
    return (ip & cidr->mask) == (cidr->addr & cidr->mask);
}

/*
 * parse_cidr
 *
 * Parses a CIDR string ("a.b.c.d/prefix" or bare "a.b.c.d" = /32) into a
 * struct snt_cidr.  Returns TRUE on success, FALSE on bad input.
 * The host bits of addr are zeroed to match the mask.
 */
static GBOOL
parse_cidr(const CHAR *str, struct snt_cidr *out)
{
    CHAR   buf[48];
    CHAR  *slash;
    ULONG  addr;
    INT    prefix;

    stzcpy(buf, str, sizeof(buf));
    slash = strchr(buf, '/');
    if (slash != NULL) {
        *slash = '\0';
        prefix = atoi(slash + 1);
        if (prefix < 0 || prefix > 32) return FALSE;
    } else {
        prefix = 32;
    }

    addr = inet_addr(buf);
    if (addr == (ULONG)INADDR_NONE) return FALSE;

    if (prefix == 0)
        out->mask = 0;
    else
        out->mask = htonl(0xFFFFFFFFu << (32 - prefix));
    out->addr = addr & out->mask;
    return TRUE;
}

/*
 * cidr_to_str
 *
 * Converts a struct snt_cidr to a human-readable string.
 * /32 entries are displayed as a bare IP address.
 * Empty entries display as "(not set)".
 */
static VOID
cidr_to_str(const struct snt_cidr *cidr, CHAR *buf, INT bufsiz)
{
    struct in_addr a;
    ULONG          m;
    INT            prefix;

    if (cidr->addr == 0 && cidr->mask == 0) {
        _snprintf(buf, bufsiz, "(not set)");
        return;
    }

    /* Count prefix bits from the mask (leftmost consecutive 1-bits). */
    m = ntohl(cidr->mask);
    for (prefix = 0; prefix < 32 && (m & (0x80000000u >> prefix)); prefix++)
        ;

    a.s_addr = cidr->addr;
    if (prefix == 32)
        _snprintf(buf, bufsiz, "%s", inet_ntoa(a));
    else
        _snprintf(buf, bufsiz, "%s/%d", inet_ntoa(a), prefix);
}

/*
 * cidr6_match
 *
 * Returns TRUE if the 16-byte IPv6 address ip falls within the given v6 CIDR.
 * A "not set" entry (prefix == 0) never matches.
 */
static GBOOL
cidr6_match(const UCHAR ip[16], const struct snt_cidr6 *cidr)
{
    INT  whole, bits;
    UCHAR mask;

    if (cidr->prefix == 0 || cidr->prefix > 128) return FALSE;

    whole = cidr->prefix / 8;    /* number of whole bytes that must match fully */
    bits  = cidr->prefix % 8;    /* leftover high bits in the next byte         */

    if (whole > 0 && memcmp(ip, cidr->addr, whole) != 0)
        return FALSE;
    if (bits != 0) {
        mask = (UCHAR)(0xFF << (8 - bits));
        if ((ip[whole] & mask) != (cidr->addr[whole] & mask))
            return FALSE;
    }
    return TRUE;
}

/*
 * parse_cidr6
 *
 * Parses "addr" or "addr/prefix" (prefix 1..128; bare address = /128) into a
 * struct snt_cidr6, zeroing host bits beyond the prefix.  Returns TRUE on
 * success.  A "::/0" (prefix 0) entry is rejected: it would match every v6
 * caller, and prefix 0 is our "not set" sentinel.
 */
static GBOOL
parse_cidr6(const CHAR *str, struct snt_cidr6 *out)
{
    CHAR   buf[64];
    CHAR  *slash;
    INT    prefix, whole, bits;
    UCHAR  tmp[16];

    stzcpy(buf, str, sizeof(buf));
    slash = strchr(buf, '/');
    if (slash != NULL) {
        *slash = '\0';
        prefix = atoi(slash + 1);
        if (prefix < 1 || prefix > 128) return FALSE;
    } else {
        prefix = 128;
    }

    if (inet_pton(AF_INET6, buf, tmp) != 1) return FALSE;

    /* Zero host bits beyond the prefix so stored addr is a clean network. */
    whole = prefix / 8;
    bits  = prefix % 8;
    if (bits != 0) {
        tmp[whole] = (UCHAR)(tmp[whole] & (0xFF << (8 - bits)));
        whole++;
    }
    { INT i; for (i = whole; i < 16; i++) tmp[i] = 0; }

    memcpy(out->addr, tmp, 16);
    out->prefix = (UCHAR)prefix;
    return TRUE;
}

/*
 * cidr6_to_str
 *
 * Renders a struct snt_cidr6 as text.  /128 entries show as a bare address;
 * unset entries show as "(not set)".
 */
static VOID
cidr6_to_str(const struct snt_cidr6 *cidr, CHAR *buf, INT bufsiz)
{
    CHAR tmp[46];

    if (cidr->prefix == 0) {
        _snprintf(buf, bufsiz, "(not set)");
        return;
    }
    if (inet_ntop(AF_INET6, (VOID *)cidr->addr, tmp, sizeof(tmp)) == NULL) {
        _snprintf(buf, bufsiz, "(invalid)");
        return;
    }
    if (cidr->prefix == 128)
        _snprintf(buf, bufsiz, "%s", tmp);
    else
        _snprintf(buf, bufsiz, "%s/%d", tmp, (INT)cidr->prefix);
}

/*
 * is_whitelisted6
 *
 * Returns TRUE if the caller's real IPv6 address (as text, e.g. from
 * snt_real_ip) matches any entry in the IPv6 connection-limit whitelist.
 * A v4 caller's text is not a valid v6 literal (inet_pton returns 0), so this
 * safely returns FALSE for v4 -- the v4 whitelist handles those.
 */
static GBOOL
is_whitelisted6(const CHAR *ip_text)
{
    UCHAR ip[16];
    INT   i;

    if (ip_text == NULL || ip_text[0] == '\0') return FALSE;
    if (inet_pton(AF_INET6, ip_text, ip) != 1) return FALSE;

    for (i = 0; i < SNTIPCTL_MAX_WHITELIST6; i++) {
        if (cidr6_match(ip, &whitelist6_cidrs[i]))
            return TRUE;
    }
    return FALSE;
}

/*
 * is_whitelisted
 *
 * Returns TRUE if ip matches any entry in the connection-limit whitelist.
 * Whitelisted IPs are never subject to connection limit enforcement.
 */
static GBOOL
is_whitelisted(ULONG ip)
{
    INT i;

    /*
     * 0.0.0.0 is never "an address that was whitelisted".  It is the marker we
     * put in inaddr for an IPv6 caller (no v4 address exists), and it is also
     * what an unresolved channel reads as -- neither is a caller a sysop could
     * have meant to list.  Without this, a whitelist entry of a bare "0.0.0.0"
     * or "0.0.0.0/32" (addr=0, mask=all-ones -- which survives cidr_match's
     * unset test) would match EVERY IPv6 caller and silently exempt the lot of
     * them from the connection limit.
     */
    if (ip == 0) return FALSE;

    for (i = 0; i < SNTIPCTL_MAX_WHITELIST; i++) {
        if (cidr_match(ip, &whitelist_cidrs[i]))
            return TRUE;
    }
    return FALSE;
}

/*
 * snt_haskey
 *
 * TRUE only when haskey() says the current user passes (1).  Compared with
 * == 1 rather than tested for truth, so no other return value -- e.g. a
 * "lock not defined" code -- can ever read as having the key.
 */
static GBOOL
snt_haskey(const CHAR *lock)
{
    return (GBOOL)(lock != NULL && lock[0] != '\0' && haskey(lock) == 1);
}

/*
 * has_bypass_key
 *
 * Returns TRUE if the current user holds SYSOP, MASTER, or the configured
 * bypass key.  SYSOP and MASTER are always checked regardless of the bypass
 * key setting.
 */
static GBOOL
has_bypass_key(VOID)
{
    return (GBOOL)(snt_haskey("SYSOP") || snt_haskey("MASTER") ||
                   snt_haskey(bypass_key));
}

/*
 * cidr_list_match
 *
 * Returns TRUE if ip matches any CIDR entry in the given list.  Unset (all-zero)
 * entries never match, so a partially filled list is safe to pass whole.
 */
static GBOOL
cidr_list_match(ULONG ip, const struct snt_cidr *list, INT nlist)
{
    INT i;
    for (i = 0; i < nlist; i++) {
        if (cidr_match(ip, &list[i]))
            return TRUE;
    }
    return FALSE;
}

/*
 * is_trusted_proxy
 *
 * Returns TRUE if ip matches any CIDR entry in the TELNET trusted proxy list.
 */
static GBOOL
is_trusted_proxy(ULONG ip)
{
    return cidr_list_match(ip, trusted_proxy_cidrs, SNTIPCTL_MAX_TRUSTED);
}

/*
 * is_ssh_trusted_proxy
 *
 * Returns TRUE if ip matches any CIDR entry in the SSH trusted proxy list.
 * Deliberately a separate list from the telnet one -- the two protocols may be
 * fronted by different proxies, and trusting a telnet relay must not implicitly
 * trust it to assert client IPs for SSH.
 */
static GBOOL
is_ssh_trusted_proxy(ULONG ip)
{
    return cidr_list_match(ip, ssh_proxy_cidrs, SNTIPCTL_MAX_TRUSTED);
}

/*
 * is_loopback
 *
 * Returns TRUE if ip is in the 127.0.0.0/8 loopback range.  Loopback covers
 * the local console / same-machine connections; these are always exempt from
 * require-trusted-proxy blocking so the BBS can never lock out its own host.
 * ip is in network byte order, so the first octet is the low-order byte.
 */
static GBOOL
is_loopback(ULONG ip)
{
    return (GBOOL)((ip & 0x000000FFu) == 127);
}

/*
 * count_active_ip
 *
 * Returns the number of fully logged-on sessions (ACTUSR) from the given
 * IPv4 address, excluding the current channel.  Used to enforce the global
 * per-IP connection limit at login time.
 */
static INT
count_active_ip(const CHAR *user_ip)
{
    CHAR theirs[46];
    INT  i, count = 0;

    if (user_ip == NULL || user_ip[0] == '\0') return 0;

    for (i = 0; i < hichp1; i++) {
        if (i == usrnum)                 continue;   /* skip self          */
        if (usroff(i)->usrcls != ACTUSR) continue;   /* must be logged on  */
        snt_source_ip(i, theirs, sizeof(theirs));
        if (strcmp(theirs, user_ip) != 0) continue;  /* must match caller  */
        count++;
    }
    return count;
}

/* ======================================================================== */
/*   BBS hook routines                                                       */
/* ======================================================================== */

/*
 * sntipctl_logon -- Called at every user logon.
 *
 * Enforces the global per-IP connection limit.  If the limit is exceeded,
 * displays the configured rejection message and disconnects the session.
 * By logon time the real IP is guaranteed resolved (the PROXY header was
 * consumed during the earlier telnet handshake).
 */
static GBOOL
sntipctl_logon(VOID)
{
    ULONG user_v4;      /* engine inaddr: v4-only checks (whitelist) still use it */
    CHAR  user_ip[46];  /* the caller's real address as text -- v4 or v6      */
    INT   count;

    if (pp_tcpipinf == NULL)
        return 0;

    user_v4 = (*pp_tcpipinf)[usrnum].inaddr.s_addr;
    snt_source_ip(usrnum, user_ip, sizeof(user_ip));

    if (debug_enabled) {
        struct in_addr a;
        const CHAR *uid = (usaptr != NULL && usaptr->userid[0] != '\0')
                          ? usaptr->userid : "(unknown)";
        a.s_addr = user_v4;
        dbglog("LOGON chan %02x: userid=%s inaddr=%s real-ip-store=%s",
               usrnum + 1, uid, inet_ntoa(a),
               (usrnum >= 0 && usrnum < MAXNTERM && snt_real_ip[usrnum][0])
                   ? snt_real_ip[usrnum] : "(none)");
    }

    if (conn_limit_enabled) {
        /*
         * Whitelist check: IPs/CIDRs in the whitelist are never subject to
         * the connection limit.  Both the v4 whitelist (matched on inaddr) and
         * the v6 whitelist (matched on the real IPv6 text) exempt the caller,
         * as do SYSOP/MASTER and the configured bypass key.  These checks occur
         * before the count so privileged users always get through.
         */
        if (debug_enabled && is_whitelisted6(user_ip))
            dbglog("LOGON chan %02x: %s exempt from connection limit "
                   "-- matches the IPv6 whitelist", usrnum + 1, user_ip);

        if (!is_whitelisted(user_v4) && !is_whitelisted6(user_ip) && !has_bypass_key()) {
            count = count_active_ip(user_ip);
            if (count >= conn_limit_max) {
                if (log_mode != LOGM_OFF) {
                    CHAR evtbuf[160];
                    const CHAR *uid = (usaptr != NULL && usaptr->userid[0] != '\0')
                                      ? usaptr->userid : "(unknown)";
                    _snprintf(evtbuf, sizeof(evtbuf),
                              "chan %02x: %s (%s) login rejected -- per-IP limit (%d active, %d max)",
                              usrnum + 1, uid, user_ip, count, conn_limit_max);
                    snt_audit_s("DENIED CONNECTIONS", uid, user_ip, evtbuf);
                }
                /*
                 * Disconnect the user with a message naming the other
                 * sessions already connected from this IP.
                 *
                 * We use byenow() -- the sanctioned MBBS "log off a user with
                 * a message" utility -- rather than writing to the socket
                 * ourselves.  This is important for two reasons:
                 *
                 *   1) Correct text.  byenow() sends CLIMIT through the
                 *      normal output channel, in order.  Writing it to the
                 *      socket by hand interleaved our bytes with the logon
                 *      output MBBS had already queued (the welcome banner,
                 *      the pager prompt, etc.), which scrambled the message
                 *      on the wire.
                 *
                 *   2) Clean teardown.  byenow() flushes the output buffer in
                 *      order and then sets the BYEBYE flag, so MBBS closes the
                 *      channel as part of its normal hangup processing on the
                 *      next cycle.  aschup() alone did not flag the channel for
                 *      logoff, which left the session "still connected" on the
                 *      BBS side.
                 *
                 * setmbk(modmb) selects our module's message file so byenow()
                 * can find CLIMIT; rstmbk() restores the previous block.
                 * N!SNTUSERS in CLIMIT names the other sessions.
                 */
                if (modmb != NULL) {
                    build_ip_users(user_ip, -1, tv_users, sizeof(tv_users));
                    /*
                     * No "(N)onstop, (Q)uit, or (C)ontinue?" prompt wedged into
                     * the middle of being disconnected: turn page pausing off
                     * at the transmitter, the engine's own idiom.  Nothing to
                     * restore -- the session is about to end.
                     */
                    btuxnf(usrnum, 0, 19);
                    setmbk(modmb);
                    byenow(CLIMIT);
                    rstmbk();
                }
                /*
                 * Return TRUE (not FALSE).  In the logon-routine cycler
                 * (cyclon -> lonstf), returning FALSE makes cyclon report
                 * "done logging on", which causes lonstf() to call
                 * go2mnu(JSTLON) -- drawing the Main Menu before the hangup is
                 * processed.  Returning TRUE makes cyclon report "continue",
                 * so the Main Menu is never drawn.  byenow() has already set
                 * the BYEBYE flag, so MBBS disconnects the user on the next
                 * scheduler cycle.
                 */
                return 1;
            }
        }
    }

    /*
     * Login access log -- "who connected and from where".  For EVERY successful
     * login, on ALL protocols (telnet, SSH, Rlogin, ...), record one clean line
     * in the dedicated TOTALIPCONTROL\LOGINS\ file: timestamp, userid, real IP,
     * and protocol.  By logon time the real IP is resolved (telnet's PROXY
     * header was consumed during the handshake; SSH and the rest are direct) and
     * the userid is known, so this is where every protocol gets a uniform entry.
     *
     * Two sinks per the audit mode:
     *   - log_to_file  -> the LOGINS access-log file (the main purpose here).
     *   - log_to_audit -> a live BBS Audit Trail line.  Telnet is skipped for
     *     the TRAIL only, because its real IP was already shown there at connect
     *     time (prx_consume_header); the LOGINS FILE still records telnet so the
     *     access log is complete.  An SSH session whose PROXY header was
     *     processed at connect time got the same trail line, and conn_ip_logged
     *     records that -- so it is skipped too, while a direct SSH login (no
     *     header, nothing logged at connect) still produces its trail line.
     */
    if (log_mode != LOGM_OFF && pp_tcpipinf != NULL) {
        struct svrinf *svr   = (*pp_tcpipinf)[usrnum].server;
        const CHAR    *proto = (svr != NULL && svr->name != NULL) ? svr->name : "TCP";
        const CHAR    *uid   = (usaptr != NULL && usaptr->userid[0] != '\0')
                               ? usaptr->userid : "(unknown)";
        GBOOL is_telnet = (svr != NULL && svr->name != NULL &&
                           strcmp(svr->name, SNT_TELNET_SVRNAME) == 0);
        GBOOL logged_at_connect = (GBOOL)(usrnum >= 0 && usrnum < MAXNTERM &&
                                          conn_ip_logged[usrnum]);

        if (log_to_file) {
            CHAR evtbuf[64];
            _snprintf(evtbuf, sizeof(evtbuf), "%s login", proto);
            log_event_line("LOGINS", uid, user_ip, evtbuf);
        }
        if (log_to_audit && !is_telnet && !logged_at_connect) {
            CHAR evtbuf[160];
            _snprintf(evtbuf, sizeof(evtbuf),
                      "chan %02x: %s login %s from %s",
                      usrnum + 1, proto, uid, user_ip);
            evtbuf[sizeof(evtbuf) - 1] = '\0';
            /* "%s" -- see snt_audit(): shocst()'s detail arg is a format string. */
            shocst("Total IP Control", "%s", evtbuf);
        }
    }

    /*
     * Record the real IP (post-proxy) to the user's profile field.
     * Only reached for sessions that passed the connection limit check.
     */
    if (usrip_enabled)
        write_ip_to_profile(user_ip);

    /*
     * Queue a GeoIP location lookup for this session.  This returns instantly
     * (the actual HTTP request runs on the worker thread), so login is never
     * delayed.  The userid is snapshotted here so the async result can be
     * matched back to this exact user even if the channel is later reused.
     */
    if (geoip_enabled && usaptr != NULL)
        geoip_enqueue(usrnum, user_ip, usaptr->userid);

    return 0;
}

/*
 * sntipctl_hup -- Called when a connection drops.
 *
 * Clears the pending socket entry to prevent a recycled socket handle
 * on a new connection from matching a stale entry.
 */
static VOID
sntipctl_hup(VOID)
{
    if (usrnum >= 0 && usrnum < MAXNTERM) {
        dbglog("HANGUP chan %02x", usrnum + 1);
        /* Drop any pre-hdlcon PROXY stash for this channel's socket so a
         * recycled handle on a later connection cannot pick up a stale entry. */
        if (pp_tcpipinf != NULL)
            early_stash_clear((*pp_tcpipinf)[usrnum].socket);
        pending_skt[usrnum]    = INVALID_SOCKET;
        pending_proto[usrnum]  = SNT_PROTO_TELNET;
        snt_conn_proto[usrnum] = SNT_PROTO_UNKNOWN;
        conn_ip_logged[usrnum] = FALSE;
        absorb_count[usrnum]   = 0;
        snt_real_ip[usrnum][0] = '\0';
    }
}

/*
 * sntipctl_fin -- Called when the BBS shuts down.
 *
 * Restores the recv() IAT entry and hdlcon to their original values so
 * the BBS can shut down cleanly without dangling function pointers.
 * Closes the message file.
 */
static VOID
sntipctl_fin(VOID)
{
    /*
     * Stop the GeoIP worker FIRST and join it, so the thread cannot still be
     * running (and touching module state) while the DLL is unloaded.
     */
    geoip_stop();

    /* Put every patched IAT slot back the way we found it (telnet + ssh.dll). */
    while (iat_patch_count > 0) {
        struct iat_patch *p = &iat_patches[--iat_patch_count];
        DWORD old_prot;
        VirtualProtect(p->slot, sizeof(recv_fn_t), PAGE_READWRITE, &old_prot);
        *p->slot = p->orig;
        VirtualProtect(p->slot, sizeof(recv_fn_t), old_prot, &old_prot);
        p->slot = NULL;
        p->orig = NULL;
    }
    real_recv       = NULL;
    tnt_recv_hooked = FALSE;
    ssh_recv_hooked = FALSE;

    if (hcsave != NULL) {
        hdlcon = hcsave;
        hcsave = NULL;
    }

    /*
     * Close the cached log handles BEFORE log_cs goes away -- log_close_all
     * takes it.  Safe here: geoip_stop() above has already joined the worker,
     * so nothing else can be writing.
     */
    log_close_all();

    DeleteCriticalSection(&log_cs);

    if (sntbt != NULL) {
        dfaClose(sntbt);
        sntbt = NULL;
    }

    if (modmb != NULL) {
        clsmsg(modmb);
        modmb = NULL;
    }
}

/* ======================================================================== */
/*   Audit logging                                                           */
/* ======================================================================== */

/*
 * Open-log-file cache.
 *
 * Every log line used to open its file, append one line, and close it again.
 * That is a full open/append/close cycle per line -- and on Windows an
 * on-access virus scanner gets a look at the file on every close.  The BBS
 * runs every channel on ONE cooperative thread, so all of that latency is time
 * the whole board is stopped, not just the channel being logged.  It was
 * measurable in a live trace: 13-18ms sat between consecutive log lines that
 * had nothing but a module lookup and a pointer write between them.
 *
 * So hold the handles open instead.  A line now costs an fputs plus an fflush.
 * The flush is deliberate, not an oversight: it keeps the one property that
 * made open/close-per-line attractive to begin with -- a log that is complete
 * and readable even if the module dies immediately after writing to it --
 * without paying for the open.  Only an OS-level crash can now lose a line.
 *
 * This is a small CACHE rather than a single handle because several files are
 * written interleaved (DEBUG, PROXCLIP LOGS, LOGINS, DENIED CONNECTIONS,
 * DENIED MODULE ACCESS, GEOIP LOGS) and one handle would just thrash between
 * them.  Slots are reclaimed least-recently-used, which is also what quietly
 * retires a file once its daily (or hourly, for DEBUG) name rolls over.
 *
 * log_cs serialises all of it -- geoip_log runs on the GeoIP worker thread, so
 * these handles really are shared across threads.
 */
#define SNT_LOGFP_SLOTS 6

struct log_fp {
    CHAR      path[MAX_PATH];
    FILE     *fp;                /* NULL = free slot                        */
    ULONGLONG used;              /* log_fp_tick at last use -- LRU ordering */
};
static struct log_fp log_fps[SNT_LOGFP_SLOTS];   /* static: fp starts NULL */
static ULONGLONG     log_fp_tick = 0;

/*
 * Create every parent directory of path (the final component is the file).
 * Runs only when a file is actually opened -- it used to run on every line.
 */
static VOID
log_make_dirs(const CHAR *path)
{
    CHAR tmp[MAX_PATH];
    INT  i;

    stzcpy(tmp, path, sizeof(tmp));
    for (i = 0; tmp[i] != '\0'; i++) {
        if (tmp[i] == '\\') {
            tmp[i] = '\0';
            CreateDirectoryA(tmp, NULL);
            tmp[i] = '\\';
        }
    }
}

/* Open, or reuse, an append handle for path.  Caller MUST hold log_cs. */
static FILE *
log_fp_get(const CHAR *path)
{
    INT i, victim = 0;

    for (i = 0; i < SNT_LOGFP_SLOTS; i++)
        if (log_fps[i].fp != NULL && strcmp(log_fps[i].path, path) == 0) {
            log_fps[i].used = ++log_fp_tick;
            return log_fps[i].fp;
        }

    /* Miss: take a free slot, else evict the least recently used one. */
    for (i = 0; i < SNT_LOGFP_SLOTS; i++) {
        if (log_fps[i].fp == NULL) { victim = i; break; }
        if (log_fps[i].used < log_fps[victim].used) victim = i;
    }
    if (log_fps[victim].fp != NULL) {
        fclose(log_fps[victim].fp);
        log_fps[victim].fp = NULL;
    }

    log_make_dirs(path);
    log_fps[victim].fp = fopen(path, "a");
    if (log_fps[victim].fp == NULL) {
        log_fps[victim].path[0] = '\0';
        return NULL;
    }
    stzcpy(log_fps[victim].path, path, sizeof(log_fps[victim].path));
    log_fps[victim].used = ++log_fp_tick;
    return log_fps[victim].fp;
}

/* Append one already-formatted line to path.  Takes log_cs itself. */
static VOID
log_write_line(const CHAR *path, const CHAR *line)
{
    FILE *fp;

    EnterCriticalSection(&log_cs);
    fp = log_fp_get(path);
    if (fp != NULL) {
        fputs(line, fp);
        fflush(fp);
    }
    LeaveCriticalSection(&log_cs);
}

/* Close every cached handle.  Called from fin, before log_cs is deleted. */
static VOID
log_close_all(VOID)
{
    INT i;

    EnterCriticalSection(&log_cs);
    for (i = 0; i < SNT_LOGFP_SLOTS; i++)
        if (log_fps[i].fp != NULL) {
            fclose(log_fps[i].fp);
            log_fps[i].fp      = NULL;
            log_fps[i].path[0] = '\0';
        }
    LeaveCriticalSection(&log_cs);
}

/*
 * build_log_path
 *
 * Writes the path of today's log file into buf.  The path is relative to
 * the BBS root (which is always the process working directory):
 *
 *   TOTALIPCONTROL\PROXCLIP LOGS\YYYY-MM-DD.LOG
 */
static VOID
build_log_path(const CHAR *subdir, CHAR *buf, INT bufsiz)
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    _snprintf(buf, bufsiz,
              "TOTALIPCONTROL\\%s\\%04d-%02d-%02d.LOG",
              subdir, st.wYear, st.wMonth, st.wDay);
}

/*
 * sntipctl_log_event
 *
 * Appends one line to today's audit log file.  Thread-safe via log_cs.
 *
 * Each line is formatted as:
 *   YYYY-MM-DD HH:MM:SS  <userid pad-20>  <ip pad-15>  <event>
 *
 * userid  -- user ID string, or a descriptive placeholder such as
 *            "(connecting)" for pre-login events.
 * ip      -- IPv4 address in network byte order.
 * event   -- free-form description of the event.
 */
static VOID
sntipctl_log_event(const CHAR *subdir, const CHAR *userid, ULONG ip, const CHAR *event)
{
    CHAR           ipbuf[20];
    unsigned char *b = (unsigned char *)&ip;

    _snprintf(ipbuf, sizeof(ipbuf), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    log_event_line(subdir, userid, ipbuf, event);
}

/*
 * log_event_line
 *
 * The shared file-writing core.  Takes the IP already formatted as a string so
 * the same line format serves both IPv4 callers (via sntipctl_log_event) and
 * IPv6 callers (via snt_audit_s), whose addresses cannot be reduced to a
 * 32-bit value.  IPv6 addresses are wider than the 15-char column and simply
 * push the event text right -- the line stays readable and correctly aligned
 * for the common IPv4 case.  Thread-safe via log_cs.
 */
static VOID
log_event_line(const CHAR *subdir, const CHAR *userid, const CHAR *ipstr, const CHAR *event)
{
    SYSTEMTIME     st;
    CHAR           logpath[MAX_PATH];
    /*
     * 768 so a long event survives the widest framing: timestamp (21) plus a
     * 29-character userid and a 45-character IPv6 address in their columns
     * leaves room for a ~600-character event -- e.g. the gateway denial's list
     * of active userids, a dozen of them at 29 characters each.
     */
    CHAR           line[768];

    if (!log_to_file) return;

    GetLocalTime(&st);
    build_log_path(subdir != NULL ? subdir : "PROXCLIP LOGS", logpath, sizeof(logpath));

    _snprintf(line, sizeof(line),
              "%04d-%02d-%02d %02d:%02d:%02d  %-20s  %-15s  %s\n",
              st.wYear, st.wMonth, st.wDay,
              st.wHour, st.wMinute, st.wSecond,
              userid != NULL ? userid : "(unknown)",
              ipstr  != NULL ? ipstr  : "",
              event  != NULL ? event  : "");

    log_write_line(logpath, line);
}

/*
 * log_apply_mode
 *
 * Derives the two independent logging sinks from log_mode.  Call after any
 * change to log_mode (config load, editor save, first-run defaults).
 */
static VOID
log_apply_mode(VOID)
{
    log_to_audit = (log_mode == LOGM_AUDIT || log_mode == LOGM_BOTH);
    log_to_file  = (log_mode == LOGM_LOG   || log_mode == LOGM_BOTH);
}

/*
 * Usable width of one Audit Trail detail field, including the terminator.
 * The engine stores it in a fixed on-disk record -- struct audEntry's
 * detail[AUDDETSIZ] with AUDDETSIZ == 128 (INC\AUDAPI.h) -- so 127 characters
 * is a hard ceiling we cannot raise, only stay inside.
 */
#define SNT_AUDIT_DETMAX 128

/*
 * snt_audit_shocst
 *
 * The module's ONLY path to shocst(), so two engine hazards are handled once
 * here instead of being re-remembered at every call site:
 *
 *   1. shocst()'s `detail` argument is a printf FORMAT string (SUMMARY.C ->
 *      audfFormatEntry() -> vsprintf).  Our text is built at runtime and
 *      carries userids and module names, so a stray '%' in one would consume a
 *      vararg that was never pushed.  Hence the literal "%s".
 *   2. That vsprintf targets a buffer of AUDDETSIZ*2 and the engine CATASTROs
 *      -- takes the whole board down -- at 256 characters or more.  Copying
 *      through a SNT_AUDIT_DETMAX buffer first bounds every caller to the
 *      field the engine would store anyway, so no call site can take the
 *      board down with an over-long line.
 *
 * stzcpy() truncates to the buffer and always terminates.
 */
static VOID
snt_audit_shocst(const CHAR *detail)
{
    CHAR adbuf[SNT_AUDIT_DETMAX];

    stzcpy(adbuf, detail != NULL ? detail : "", sizeof(adbuf));
    shocst("Total IP Control", "%s", adbuf);
}

/*
 * snt_audit
 *
 * Records one event to whichever audit sink(s) the current mode selects:
 *   - log_to_file  -> a line in today's TOTALIPCONTROL\<subdir> log file
 *   - log_to_audit -> a line in the BBS Audit Trail (via shocst)
 *
 * The caller builds a self-contained `event` string (including channel and IP
 * where those matter) so the Audit Trail line reads well on its own; the file
 * sink additionally records the userid and IP in their own columns.
 */
static VOID
snt_audit(const CHAR *subdir, const CHAR *userid, ULONG ip, const CHAR *event)
{
    if (log_to_file)
        sntipctl_log_event(subdir, userid, ip, event);
    if (log_to_audit)
        snt_audit_shocst(event);
}

/*
 * snt_audit_s -- string-IP variant of snt_audit.
 *
 * Identical routing (file + Audit Trail), but takes the IP as an already
 * formatted string.  Used for IPv6 callers, whose addresses have no 32-bit
 * form; also usable for any event where the caller already holds the IP text.
 */
static VOID
snt_audit_s(const CHAR *subdir, const CHAR *userid, const CHAR *ipstr, const CHAR *event)
{
    snt_audit_sx(subdir, userid, ipstr, event, event);
}

/*
 * snt_audit_sx -- two-text variant of snt_audit_s.
 *
 * The two sinks have very different ceilings, and for some events no single
 * string serves both.  The log file takes a long line; the Audit Trail's detail
 * is a fixed 128-byte field in an on-disk record (AUDDETSIZ, INC\AUDAPI.h) that
 * the engine truncates at 127 and CATASTROs past 255.  A list of userids cannot
 * fit it -- at the BBS maximum of 29 characters per userid, the surrounding
 * text alone passes 127 before the first name is printed.
 *
 * Such callers pass the full text as `file_event` and a self-contained short
 * form (a count, plus a pointer to the log) as `audit_event`.  Callers whose
 * text fits both use snt_audit_s(), which routes here with one string.
 */
static VOID
snt_audit_sx(const CHAR *subdir, const CHAR *userid, const CHAR *ipstr,
             const CHAR *file_event, const CHAR *audit_event)
{
    if (log_to_file)
        log_event_line(subdir, userid, ipstr, file_event);
    if (log_to_audit)
        snt_audit_shocst(audit_event);
}

/* ======================================================================== */
/*   Debug trace logging                                                     */
/*                                                                           */
/*   A verbose, self-contained diagnostic trace, gated by debug_enabled and  */
/*   entirely separate from the audit log (log_mode).  When on it records    */
/*   the full connection-processing path so a problem that only shows up on  */
/*   a live board -- e.g. another module displacing our recv() hook when it  */
/*   connects -- can be caught from the file trail alone.  Files are split   */
/*   per hour under a per-day folder:                                        */
/*        TOTALIPCONTROL\DEBUG\YYYY-MM-DD\HH.LOG                             */
/* ======================================================================== */

/*
 * debug_hook_installed
 *
 * TRUE iff the telnet module's recv() IAT slot still holds our prx_recv_hook.
 * If another module has overwritten it since startup, this returns FALSE --
 * which means GALTNTD's telnet reads are bypassing our PROXY-header stripper
 * and the real client IP will no longer be restored.  This is the single most
 * useful signal in the trace: a flip from TRUE to FALSE pinpoints exactly when
 * (and, by correlation with the surrounding connect lines, which module's
 * activity) knocked the hook out.
 */
static GBOOL
debug_hook_installed(VOID)
{
    return (GBOOL)(tnt_iat_slot != NULL && *tnt_iat_slot == prx_recv_hook);
}

/*
 * dbglog
 *
 * Append one timestamped line to the current hour's debug file.  No-op unless
 * debug_enabled.  Thread-safe via log_cs (shared with the audit-log writer).
 * The day folder is created on demand so a date rollover just starts a new
 * folder without a restart.  Kept deliberately robust: any failure to open the
 * file is swallowed -- a diagnostic aid must never disturb the live board.
 */
static VOID
dbglog(const CHAR *fmt, ...)
{
    SYSTEMTIME st;
    CHAR       dir[MAX_PATH];
    CHAR       path[MAX_PATH];
    CHAR       msg[512];
    CHAR       line[640];
    va_list    ap;

    if (!debug_enabled) return;

    va_start(ap, fmt);
    _vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    msg[sizeof(msg) - 1] = '\0';

    GetLocalTime(&st);

    /* Directories are created by log_write_line when it opens the file, not
     * here -- these three CreateDirectory calls used to run on every line. */
    _snprintf(dir, sizeof(dir), "TOTALIPCONTROL\\DEBUG\\%04d-%02d-%02d",
              st.wYear, st.wMonth, st.wDay);
    _snprintf(path, sizeof(path), "%s\\%02d.LOG", dir, st.wHour);

    _snprintf(line, sizeof(line), "%02d:%02d:%02d.%03d  %s\n",
              st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, msg);
    line[sizeof(line) - 1] = '\0';

    log_write_line(path, line);
}

/*
 * dbg_hexdump
 *
 * Trace the first n bytes of a buffer as one line of hex plus a printable
 * rendering -- used to show exactly what arrived on a socket (is it really a
 * "PROXY ..." header? was it already partly consumed?).  No-op unless debug is
 * on; n is clamped so the formatted line stays well within dbglog's buffer.
 */
static VOID
dbg_hexdump(const CHAR *label, const CHAR *buf, INT n)
{
    CHAR hex[3 * 48 + 1];
    CHAR asc[48 + 1];
    CHAR cnt[32];
    INT  i, hp = 0, total;

    if (!debug_enabled) return;
    if (n < 0) n = 0;
    total = n;
    if (n > 48) n = 48;

    /*
     * Say so when the dump is clipped.  It used to report the CLIPPED count as
     * though it were the total, which reads as a short read that never happened
     * -- an IPv6 PROXY header (~58 bytes) logged as "48 bytes" looks truncated
     * on the wire when it arrived complete.
     */
    if (total > n) _snprintf(cnt, sizeof(cnt), "%d of %d", n, total);
    else           _snprintf(cnt, sizeof(cnt), "%d", total);
    cnt[sizeof(cnt) - 1] = '\0';

    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)buf[i];
        hp += _snprintf(hex + hp, sizeof(hex) - hp, "%02x ", c);
        asc[i] = (c >= 0x20 && c < 0x7f) ? (CHAR)c : '.';
    }
    hex[hp] = '\0';
    asc[n]  = '\0';

    dbglog("      %s (%s bytes): %s| %s", label != NULL ? label : "data", cnt, hex, asc);
}

/* ======================================================================== */
/*   GeoIP Location                                                          */
/*                                                                           */
/*   At logon, the caller's approximate City / State / Country is looked up  */
/*   from their (real, post-proxy) IP address via an online geolocation      */
/*   provider and written to a configurable user profile field.             */
/*                                                                           */
/*   THREADING MODEL (why it is built this way)                             */
/*   --------------------------------------------------------------------    */
/*   The BBS runs a single cooperative scheduler thread; any blocking call   */
/*   made from a hook routine freezes the whole board.  An HTTP request can  */
/*   take seconds, so the lookup MUST NOT run on the main thread.            */
/*                                                                           */
/*   Instead:                                                                */
/*     - At logon (main thread) we snapshot the caller's IP (a plain 32-bit  */
/*       value) and userid into a request, and push it onto a queue.  The    */
/*       worker thread reads ONLY that inert snapshot -- never any BBS       */
/*       global (usrnum, tcpipinf, usaptr), which the engine reuses the      */
/*       instant a channel hangs up.                                         */
/*     - A background worker thread performs the WinHTTP request + JSON      */
/*       parse and pushes the formatted location onto a result queue.  It    */
/*       calls NO BBS SDK function (those are not thread-safe); its only     */
/*       outward action is file logging, which is guarded by log_cs.         */
/*     - A once-per-second rtkick() routine (geoip_drain, main thread) is    */
/*       the ONLY place results are applied: it writes the profile field via */
/*       updaccu(uacoff(channel)), re-checking the userid still matches the  */
/*       snapshot so a recycled channel is never written to the wrong user.  */
/*                                                                           */
/*   A per-IP cache (main-thread only) means repeat logins from the same IP  */
/*   cost zero API calls.  Private/reserved IPs are never looked up.  A      */
/*   failed lookup is logged and dropped -- it can never delay or block a    */
/*   user from logging in.                                                   */
/* ======================================================================== */

#define GEO_Q_MAX      64       /* request / result ring capacity           */
#define GEO_LOC_SZ     80       /* max formatted location string            */
#define GEO_BODY_SZ    4096     /* max JSON response body captured          */
#define GEO_UID_SZ     UIDSIZ   /* userid buffer size (30)                  */
#define GEO_CACHE_MAX  512      /* per-IP cache entries                     */

/*
 * Location components extracted from a provider response.  region is already
 * resolved to the US two-letter state code (or the full subdivision name
 * elsewhere).  Formatting into the profile field(s) happens later, on the main
 * thread, so it always uses the current write-mode / format settings.
 */
struct geo_loc {
    CHAR city[64];
    CHAR region[64];          /* full subdivision name (e.g. "Minnesota")   */
    CHAR regcode[16];         /* US 2-letter state code (e.g. "MN") or empty */
    CHAR country[64];         /* full country name                          */
    CHAR ccode[8];            /* two-letter ISO country code                */
};

/* Snapshot of everything the worker needs -- no BBS globals are referenced. */
struct geo_req {
    INT   channel;              /* originating channel (for result apply)   */
    CHAR  ip[46];               /* source IP as text (v4 or v6)             */
    CHAR  userid[GEO_UID_SZ];   /* userid at enqueue (revalidated on apply) */
    CHAR  host[64];             /* API host                                 */
    CHAR  path[192];            /* API request path (incl. IP and key)      */
    GBOOL https;                /* use TLS                                  */
    INT   timeout;             /* per-leg WinHTTP timeout (seconds)         */
    INT   provider;            /* GEOPRV_* id                              */
    INT   retries;             /* extra attempts after first failure        */
};

/* Completed lookup handed back to the main thread. */
struct geo_res {
    INT            channel;
    CHAR           ip[46];      /* source IP as text (v4 or v6) -- cache key */
    CHAR           userid[GEO_UID_SZ];
    GBOOL          ok;
    struct geo_loc loc;         /* extracted components                     */
};

static CRITICAL_SECTION geo_cs;                 /* guards both queues       */
static HANDLE geo_ev_work = NULL;               /* auto-reset: work queued  */
static HANDLE geo_ev_stop = NULL;               /* manual-reset: shutdown   */
static HANDLE geo_worker  = NULL;               /* the background thread    */
static GBOOL  geo_started = FALSE;

static struct geo_req geo_reqq[GEO_Q_MAX];
static INT geo_reqh = 0, geo_reqt = 0, geo_reqn = 0;
static struct geo_res geo_resq[GEO_Q_MAX];
static INT geo_resh = 0, geo_rest = 0, geo_resn = 0;

/* Per-IP cache -- accessed ONLY from the main thread (enqueue + drain). */
struct geo_cent {
    CHAR           ip[46];     /* "" = empty slot; text so v6 keys too      */
    ULONGLONG      expiry;     /* GetTickCount64() ms when entry expires    */
    struct geo_loc loc;        /* cached components                         */
};
static struct geo_cent geo_cache[GEO_CACHE_MAX];
static INT geo_cache_next = 0; /* round-robin eviction cursor               */

/*
 * is_private_ip
 *
 * Returns TRUE for IPs that a public GeoIP provider cannot resolve: RFC1918
 * private ranges, loopback, link-local, CGNAT, and 0.0.0.0.  These are never
 * looked up (it would waste an API call and always fail).  ip is in network
 * byte order, so b[0] is the first dotted octet.
 */
static GBOOL
is_private_ip(const CHAR *ipstr)
{
    ULONG          ip;
    unsigned char *b;

    if (ipstr == NULL || ipstr[0] == '\0') return TRUE;

    if (snt_ip_is_v6(ipstr)) {
        /*
         * IPv6 ranges a public geolocation service could never resolve.  The
         * comparisons are on text because that is the form we hold, and each
         * range is identified by its leading hex nibbles:
         *   ::1        loopback
         *   fc00::/7   unique local  (fc.. and fd..)
         *   fe80::/10  link-local    (fe8. fe9. fea. feb.)
         */
        if (strcmp(ipstr, "::1") == 0) return TRUE;
        if (_strnicmp(ipstr, "fc", 2) == 0 || _strnicmp(ipstr, "fd", 2) == 0) return TRUE;
        if (_strnicmp(ipstr, "fe8", 3) == 0 || _strnicmp(ipstr, "fe9", 3) == 0 ||
            _strnicmp(ipstr, "fea", 3) == 0 || _strnicmp(ipstr, "feb", 3) == 0) return TRUE;
        return FALSE;
    }

    ip = inet_addr(ipstr);
    if (ip == 0 || ip == (ULONG)INADDR_NONE) return TRUE;
    b = (unsigned char *)&ip;
    if (b[0] == 10)  return TRUE;                        /* 10.0.0.0/8       */
    if (b[0] == 127) return TRUE;                        /* 127.0.0.0/8      */
    if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return TRUE; /* 172.16/12   */
    if (b[0] == 192 && b[1] == 168) return TRUE;         /* 192.168.0.0/16   */
    if (b[0] == 169 && b[1] == 254) return TRUE;         /* 169.254.0.0/16   */
    if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return TRUE; /* 100.64/10  */
    return FALSE;
}

/*
 * geoip_log
 *
 * Appends one line to today's GEOIP LOGS file if the event's level is within
 * the configured verbosity.  CRT/Win32 only (fopen + log_cs) so it is safe to
 * call from BOTH the worker thread and the main thread.  Independent of the
 * global audit-logging toggle -- GeoIP has its own log level.
 */
static VOID
geoip_log(INT level, const CHAR *userid, const CHAR *ip, const CHAR *event)
{
    SYSTEMTIME     st;
    CHAR           logpath[MAX_PATH];
    CHAR           line[512];

    if (geoip_loglevel == GEOLOG_OFF || level > geoip_loglevel) return;

    GetLocalTime(&st);
    build_log_path("GEOIP LOGS", logpath, sizeof(logpath));

    /* %-15s still pads a v4 address to its column; a v6 one simply overruns it
     * and pushes the event text right, which is preferred to truncating it. */
    _snprintf(line, sizeof(line),
              "%04d-%02d-%02d %02d:%02d:%02d  %-20s  %-15s  %s\n",
              st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
              (userid != NULL && userid[0] != '\0') ? userid : "(geoip)",
              (ip != NULL && ip[0] != '\0') ? ip : "-",
              event != NULL ? event : "");

    log_write_line(logpath, line);
}

/*
 * json_get_str
 *
 * Minimal JSON string-value extractor: finds "key" : "value" in body and
 * copies value (with basic \-unescaping) into out.  Returns FALSE if the key
 * is absent or its value is not a string.  Sufficient for the small, known
 * provider responses; avoids pulling in a JSON library.  CRT only.
 */
static GBOOL
json_get_str(const CHAR *body, const CHAR *key, CHAR *out, INT outsz)
{
    CHAR        pat[64];
    const CHAR *p;
    INT         i = 0;

    out[0] = '\0';
    _snprintf(pat, sizeof(pat), "\"%s\"", key);
    p = strstr(body, pat);
    if (p == NULL) return FALSE;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p != ':') return FALSE;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p != '"') return FALSE;                 /* only string values       */
    p++;
    while (*p != '\0' && *p != '"' && i < outsz - 1) {
        if (*p == '\\' && p[1] != '\0') {
            p++;
            if      (*p == 'n') out[i++] = '\n';
            else if (*p == 't') out[i++] = '\t';
            else                out[i++] = *p;   /* \" \\ \/ and others      */
            p++;
        } else {
            out[i++] = *p++;
        }
    }
    out[i] = '\0';
    return TRUE;
}

/*
 * json_get_bool_true
 *
 * Returns TRUE only if body contains "key" : true.  Used for the provider
 * success/error indicator ("success":true for ipwho.is, "error":true for
 * ipapi.co).  CRT only.
 */
static GBOOL
json_get_bool_true(const CHAR *body, const CHAR *key)
{
    CHAR        pat[64];
    const CHAR *p;

    _snprintf(pat, sizeof(pat), "\"%s\"", key);
    p = strstr(body, pat);
    if (p == NULL) return FALSE;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p != ':') return FALSE;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    return (GBOOL)(strncmp(p, "true", 4) == 0);
}

/*
 * geo_join_clean
 *
 * Rebuilds raw as comma-separated segments, dropping empty/whitespace-only
 * segments and re-joining survivors with ", ".  This turns a template result
 * like "Minneapolis, , United States" (empty region) into a clean
 * "Minneapolis, United States".  No strtok (which has static state) so it is
 * safe on the worker thread.  CRT only.
 */
static VOID
geo_join_clean(const CHAR *raw, CHAR *out, INT outsz)
{
    const CHAR *p = raw;
    INT         oi = 0, first = 1;

    while (*p != '\0') {
        CHAR seg[GEO_LOC_SZ];
        INT  si = 0, L;

        while (*p == ' ') p++;                    /* skip leading spaces      */
        while (*p != '\0' && *p != ',') {
            if (si < (INT)sizeof(seg) - 1) seg[si++] = *p;
            p++;
        }
        seg[si] = '\0';
        L = si;
        while (L > 0 && seg[L - 1] == ' ') seg[--L] = '\0';  /* trim trailing */

        if (seg[0] != '\0') {
            INT k = 0;
            if (!first && oi < outsz - 2) { out[oi++] = ','; out[oi++] = ' '; }
            while (seg[k] != '\0' && oi < outsz - 1) out[oi++] = seg[k++];
            first = 0;
        }
        if (*p == ',') p++;
    }
    out[oi] = '\0';
}

/*
 * geoip_build_url  (MAIN THREAD, at enqueue)
 *
 * Builds the provider-specific host and request path for the given IP.  This
 * is the request-construction half of the provider abstraction: adding a
 * provider means adding a case here and a matching case in geoip_parse_body().
 * Runs on the main thread so it may read the live config globals safely.
 */
/*
 * geoip_default_host / geoip_is_builtin_host
 *
 * The API-host field is an optional override.  When it is blank, the effective
 * host is the selected provider's default, so switching providers "just works"
 * without the sysop editing the host.  geoip_is_builtin_host() recognizes any
 * of those default hostnames (and blank), so a stale default left in the field
 * -- e.g. "ipwho.is" carried over from before a provider change -- is treated as
 * "no override" rather than silently mis-routing the request.
 */
static const CHAR *
geoip_default_host(INT provider)
{
    switch (provider) {
    case GEOPRV_IPAPI:   return "ip-api.com";
    case GEOPRV_IPAPICO: return "ipapi.co";
    case GEOPRV_IPINFO:  return "ipinfo.io";
    default:             return "ipwho.is";
    }
}

static GBOOL
geoip_is_builtin_host(const CHAR *h)
{
    INT p;

    if (h[0] == '\0') return TRUE;
    /* Compare against every provider's default host (single source of truth --
     * geoip_default_host) so a new provider needs no change here. */
    for (p = GEOPRV_IPWHOIS; p <= GEOPRV_IPINFO; p++)
        if (_stricmp(h, geoip_default_host(p)) == 0) return TRUE;
    return FALSE;
}

static VOID
geoip_build_url(INT provider, const CHAR *ip, CHAR *host, INT hostsz, CHAR *path, INT pathsz)
{
    /*
     * The address goes into the URL path verbatim, v4 or v6 alike.  Colons are
     * legal in a path segment, so an IPv6 address needs no escaping, and all
     * four providers accept one -- verified live against each.
     */
    const CHAR *ipbuf = ip;

    /* Host: sysop override wins; otherwise the provider's default host. */
    if (geoip_host[0] != '\0')
        stzcpy(host, geoip_host, hostsz);
    else
        stzcpy(host, geoip_default_host(provider), hostsz);

    switch (provider) {
    case GEOPRV_IPAPI:
        /* ip-api.com: request only the fields we use. */
        _snprintf(path, pathsz,
                  "/json/%s?fields=status,country,countryCode,region,regionName,city",
                  ipbuf);
        break;
    case GEOPRV_IPAPICO:
        _snprintf(path, pathsz, "/%s/json/", ipbuf);
        break;
    case GEOPRV_IPINFO:
        /* ipinfo.io: standard /json endpoint.  A free-tier token is required
         * (each sysop supplies their own in the KEY field); the token unlocks
         * the more accurate probe-based city/region data. */
        if (geoip_key[0] != '\0')
            _snprintf(path, pathsz, "/%s/json?token=%s", ipbuf, geoip_key);
        else
            _snprintf(path, pathsz, "/%s/json", ipbuf);
        break;
    default: /* GEOPRV_IPWHOIS */
        if (geoip_key[0] != '\0')
            _snprintf(path, pathsz, "/%s?key=%s", ipbuf, geoip_key);
        else
            _snprintf(path, pathsz, "/%s", ipbuf);
        break;
    }
}

/*
 * us_state_abbrev
 *
 * Maps a full US state / territory name to its USPS two-letter code, or NULL if
 * unrecognized.  Some providers return only the full subdivision name (ipinfo.io
 * gives "Minnesota", not "MN"); this normalizes US regions so they render with
 * the two-letter code the other providers already supply.  Case-insensitive,
 * CRT only, so it is safe on the worker thread.
 */
static const CHAR *
us_state_abbrev(const CHAR *name)
{
    static const struct { const CHAR *name; const CHAR *ab; } tbl[] = {
        {"Alabama","AL"}, {"Alaska","AK"}, {"Arizona","AZ"}, {"Arkansas","AR"},
        {"California","CA"}, {"Colorado","CO"}, {"Connecticut","CT"},
        {"Delaware","DE"}, {"Florida","FL"}, {"Georgia","GA"}, {"Hawaii","HI"},
        {"Idaho","ID"}, {"Illinois","IL"}, {"Indiana","IN"}, {"Iowa","IA"},
        {"Kansas","KS"}, {"Kentucky","KY"}, {"Louisiana","LA"}, {"Maine","ME"},
        {"Maryland","MD"}, {"Massachusetts","MA"}, {"Michigan","MI"},
        {"Minnesota","MN"}, {"Mississippi","MS"}, {"Missouri","MO"},
        {"Montana","MT"}, {"Nebraska","NE"}, {"Nevada","NV"},
        {"New Hampshire","NH"}, {"New Jersey","NJ"}, {"New Mexico","NM"},
        {"New York","NY"}, {"North Carolina","NC"}, {"North Dakota","ND"},
        {"Ohio","OH"}, {"Oklahoma","OK"}, {"Oregon","OR"}, {"Pennsylvania","PA"},
        {"Rhode Island","RI"}, {"South Carolina","SC"}, {"South Dakota","SD"},
        {"Tennessee","TN"}, {"Texas","TX"}, {"Utah","UT"}, {"Vermont","VT"},
        {"Virginia","VA"}, {"Washington","WA"}, {"West Virginia","WV"},
        {"Wisconsin","WI"}, {"Wyoming","WY"}, {"District of Columbia","DC"},
        {"Puerto Rico","PR"}, {"Guam","GU"}, {"U.S. Virgin Islands","VI"},
        {"American Samoa","AS"}, {"Northern Mariana Islands","MP"},
    };
    INT i;

    if (name == NULL || name[0] == '\0') return NULL;
    for (i = 0; i < (INT)(sizeof(tbl) / sizeof(tbl[0])); i++)
        if (_stricmp(name, tbl[i].name) == 0) return tbl[i].ab;
    return NULL;
}

/*
 * cc2name
 *
 * Maps a two-letter ISO 3166-1 country code to a common English country name,
 * or NULL if unrecognized.  ipinfo.io returns only the code (no full name), so
 * this lets FULL country format render a real name for that provider.  Names
 * are plain ASCII (no accents) for terminal safety.  Case-insensitive, CRT only.
 */
static const CHAR *
cc2name(const CHAR *code)
{
    static const struct { const CHAR *cc; const CHAR *name; } tbl[] = {
        {"AD","Andorra"}, {"AE","United Arab Emirates"}, {"AF","Afghanistan"},
        {"AG","Antigua and Barbuda"}, {"AI","Anguilla"}, {"AL","Albania"},
        {"AM","Armenia"}, {"AO","Angola"}, {"AQ","Antarctica"},
        {"AR","Argentina"}, {"AS","American Samoa"}, {"AT","Austria"},
        {"AU","Australia"}, {"AW","Aruba"}, {"AX","Aland Islands"},
        {"AZ","Azerbaijan"},
        {"BA","Bosnia and Herzegovina"}, {"BB","Barbados"}, {"BD","Bangladesh"},
        {"BE","Belgium"}, {"BF","Burkina Faso"}, {"BG","Bulgaria"},
        {"BH","Bahrain"}, {"BI","Burundi"}, {"BJ","Benin"},
        {"BL","Saint Barthelemy"}, {"BM","Bermuda"}, {"BN","Brunei"},
        {"BO","Bolivia"}, {"BQ","Bonaire"}, {"BR","Brazil"},
        {"BS","Bahamas"}, {"BT","Bhutan"}, {"BV","Bouvet Island"},
        {"BW","Botswana"}, {"BY","Belarus"}, {"BZ","Belize"},
        {"CA","Canada"}, {"CC","Cocos Islands"}, {"CD","DR Congo"},
        {"CF","Central African Republic"}, {"CG","Congo"}, {"CH","Switzerland"},
        {"CI","Cote d'Ivoire"}, {"CK","Cook Islands"}, {"CL","Chile"},
        {"CM","Cameroon"}, {"CN","China"}, {"CO","Colombia"},
        {"CR","Costa Rica"}, {"CU","Cuba"}, {"CV","Cabo Verde"},
        {"CW","Curacao"}, {"CX","Christmas Island"}, {"CY","Cyprus"},
        {"CZ","Czechia"},
        {"DE","Germany"}, {"DJ","Djibouti"}, {"DK","Denmark"},
        {"DM","Dominica"}, {"DO","Dominican Republic"}, {"DZ","Algeria"},
        {"EC","Ecuador"}, {"EE","Estonia"}, {"EG","Egypt"},
        {"EH","Western Sahara"}, {"ER","Eritrea"}, {"ES","Spain"},
        {"ET","Ethiopia"},
        {"FI","Finland"}, {"FJ","Fiji"}, {"FK","Falkland Islands"},
        {"FM","Micronesia"}, {"FO","Faroe Islands"}, {"FR","France"},
        {"GA","Gabon"}, {"GB","United Kingdom"}, {"GD","Grenada"},
        {"GE","Georgia"}, {"GF","French Guiana"}, {"GG","Guernsey"},
        {"GH","Ghana"}, {"GI","Gibraltar"}, {"GL","Greenland"},
        {"GM","Gambia"}, {"GN","Guinea"}, {"GP","Guadeloupe"},
        {"GQ","Equatorial Guinea"}, {"GR","Greece"},
        {"GS","South Georgia and the South Sandwich Islands"},
        {"GT","Guatemala"}, {"GU","Guam"}, {"GW","Guinea-Bissau"},
        {"GY","Guyana"},
        {"HK","Hong Kong"}, {"HM","Heard Island and McDonald Islands"},
        {"HN","Honduras"}, {"HR","Croatia"},
        {"HT","Haiti"}, {"HU","Hungary"},
        {"ID","Indonesia"}, {"IE","Ireland"}, {"IL","Israel"},
        {"IM","Isle of Man"}, {"IN","India"}, {"IO","British Indian Ocean Territory"},
        {"IQ","Iraq"}, {"IR","Iran"}, {"IS","Iceland"}, {"IT","Italy"},
        {"JE","Jersey"}, {"JM","Jamaica"}, {"JO","Jordan"}, {"JP","Japan"},
        {"KE","Kenya"}, {"KG","Kyrgyzstan"}, {"KH","Cambodia"},
        {"KI","Kiribati"}, {"KM","Comoros"}, {"KN","Saint Kitts and Nevis"},
        {"KP","North Korea"}, {"KR","South Korea"}, {"KW","Kuwait"},
        {"KY","Cayman Islands"}, {"KZ","Kazakhstan"},
        {"LA","Laos"}, {"LB","Lebanon"}, {"LC","Saint Lucia"},
        {"LI","Liechtenstein"}, {"LK","Sri Lanka"}, {"LR","Liberia"},
        {"LS","Lesotho"}, {"LT","Lithuania"}, {"LU","Luxembourg"},
        {"LV","Latvia"}, {"LY","Libya"},
        {"MA","Morocco"}, {"MC","Monaco"}, {"MD","Moldova"},
        {"ME","Montenegro"}, {"MF","Saint Martin"}, {"MG","Madagascar"},
        {"MH","Marshall Islands"}, {"MK","North Macedonia"}, {"ML","Mali"},
        {"MM","Myanmar"}, {"MN","Mongolia"}, {"MO","Macao"},
        {"MP","Northern Mariana Islands"}, {"MQ","Martinique"}, {"MR","Mauritania"},
        {"MS","Montserrat"}, {"MT","Malta"}, {"MU","Mauritius"},
        {"MV","Maldives"}, {"MW","Malawi"}, {"MX","Mexico"},
        {"MY","Malaysia"}, {"MZ","Mozambique"},
        {"NA","Namibia"}, {"NC","New Caledonia"}, {"NE","Niger"},
        {"NF","Norfolk Island"}, {"NG","Nigeria"}, {"NI","Nicaragua"},
        {"NL","Netherlands"}, {"NO","Norway"}, {"NP","Nepal"},
        {"NR","Nauru"}, {"NU","Niue"}, {"NZ","New Zealand"},
        {"OM","Oman"},
        {"PA","Panama"}, {"PE","Peru"}, {"PF","French Polynesia"},
        {"PG","Papua New Guinea"}, {"PH","Philippines"}, {"PK","Pakistan"},
        {"PL","Poland"}, {"PM","Saint Pierre and Miquelon"}, {"PN","Pitcairn"},
        {"PR","Puerto Rico"}, {"PS","Palestine"}, {"PT","Portugal"},
        {"PW","Palau"}, {"PY","Paraguay"},
        {"QA","Qatar"},
        {"RE","Reunion"}, {"RO","Romania"}, {"RS","Serbia"},
        {"RU","Russia"}, {"RW","Rwanda"},
        {"SA","Saudi Arabia"}, {"SB","Solomon Islands"}, {"SC","Seychelles"},
        {"SD","Sudan"}, {"SE","Sweden"}, {"SG","Singapore"},
        {"SH","Saint Helena"}, {"SI","Slovenia"}, {"SJ","Svalbard and Jan Mayen"},
        {"SK","Slovakia"}, {"SL","Sierra Leone"}, {"SM","San Marino"},
        {"SN","Senegal"}, {"SO","Somalia"}, {"SR","Suriname"},
        {"SS","South Sudan"}, {"ST","Sao Tome and Principe"}, {"SV","El Salvador"},
        {"SX","Sint Maarten"}, {"SY","Syria"}, {"SZ","Eswatini"},
        {"TC","Turks and Caicos Islands"}, {"TD","Chad"},
        {"TF","French Southern Territories"}, {"TG","Togo"},
        {"TH","Thailand"}, {"TJ","Tajikistan"}, {"TK","Tokelau"},
        {"TL","Timor-Leste"}, {"TM","Turkmenistan"}, {"TN","Tunisia"},
        {"TO","Tonga"}, {"TR","Turkey"}, {"TT","Trinidad and Tobago"},
        {"TV","Tuvalu"}, {"TW","Taiwan"}, {"TZ","Tanzania"},
        {"UA","Ukraine"}, {"UG","Uganda"},
        {"UM","United States Minor Outlying Islands"}, {"US","United States"},
        {"UY","Uruguay"}, {"UZ","Uzbekistan"},
        {"VA","Vatican City"}, {"VC","Saint Vincent and the Grenadines"},
        {"VE","Venezuela"}, {"VG","British Virgin Islands"},
        {"VI","U.S. Virgin Islands"}, {"VN","Vietnam"}, {"VU","Vanuatu"},
        {"WF","Wallis and Futuna"}, {"WS","Samoa"},
        {"YE","Yemen"}, {"YT","Mayotte"},
        {"ZA","South Africa"}, {"ZM","Zambia"}, {"ZW","Zimbabwe"},
    };
    INT i;

    if (code == NULL || code[0] == '\0') return NULL;
    for (i = 0; i < (INT)(sizeof(tbl) / sizeof(tbl[0])); i++)
        if (_stricmp(code, tbl[i].cc) == 0) return tbl[i].name;
    return NULL;
}

/*
 * geoip_parse_body  (WORKER THREAD)
 *
 * Provider-specific response parser -- the second half of the provider
 * abstraction.  Extracts city / region / country / country-code into `out`,
 * choosing the US two-letter state code (or the full subdivision name
 * elsewhere) for region.  It does NOT format -- that happens on the main thread
 * (geo_format), so the current write-mode/format settings always apply.
 * Returns TRUE if any usable component was found.  CRT only (no BBS SDK).
 */
static GBOOL
geoip_parse_body(INT provider, const CHAR *body, struct geo_loc *out)
{
    CHAR regfull[64] = "", regcode[16] = "";

    memset(out, 0, sizeof(*out));

    switch (provider) {
    case GEOPRV_IPAPI: {
        CHAR st[16] = "";
        if (!json_get_str(body, "status", st, sizeof(st)) || _stricmp(st, "success") != 0)
            return FALSE;
        json_get_str(body, "city",        out->city,    sizeof(out->city));
        json_get_str(body, "region",      regcode,      sizeof(regcode)); /* US 2-letter */
        json_get_str(body, "regionName",  regfull,      sizeof(regfull));
        json_get_str(body, "countryCode", out->ccode,   sizeof(out->ccode));
        json_get_str(body, "country",     out->country, sizeof(out->country));
        break; }
    case GEOPRV_IPAPICO:
        if (json_get_bool_true(body, "error")) return FALSE;
        json_get_str(body, "city",         out->city,    sizeof(out->city));
        json_get_str(body, "region_code",  regcode,      sizeof(regcode));
        json_get_str(body, "region",       regfull,      sizeof(regfull));
        json_get_str(body, "country",      out->ccode,   sizeof(out->ccode));   /* 2-letter */
        json_get_str(body, "country_name", out->country, sizeof(out->country));
        break;
    case GEOPRV_IPINFO:
        /* ipinfo.io has no error flag on success; a bad token or unlocatable IP
         * simply omits city/region (the final has-any-component check catches
         * it).  region is the full subdivision name (no 2-letter code), and
         * country is the ISO code only -- no full country name is returned, so
         * FULL country-format mode renders the code for this provider. */
        json_get_str(body, "city",     out->city,    sizeof(out->city));
        json_get_str(body, "region",   regfull,      sizeof(regfull));
        json_get_str(body, "country",  out->ccode,   sizeof(out->ccode));   /* 2-letter */
        /* ipinfo returns no full country name; derive one from the code so FULL
         * country format shows a real name (falls back to the code if unknown). */
        {
            const CHAR *nm = cc2name(out->ccode);
            stzcpy(out->country, nm ? nm : out->ccode, sizeof(out->country));
        }
        break;
    default: /* GEOPRV_IPWHOIS */
        if (!json_get_bool_true(body, "success")) return FALSE;
        json_get_str(body, "city",         out->city,    sizeof(out->city));
        json_get_str(body, "region_code",  regcode,      sizeof(regcode));
        json_get_str(body, "region",       regfull,      sizeof(regfull));
        json_get_str(body, "country_code", out->ccode,   sizeof(out->ccode));
        json_get_str(body, "country",      out->country, sizeof(out->country));
        break;
    }

    /* When a US result carried only the full state name (ipinfo.io does), map
     * it to the two-letter code so the CODE format has something to show. */
    if (_stricmp(out->ccode, "US") == 0 && regcode[0] == '\0' && regfull[0] != '\0') {
        const CHAR *ab = us_state_abbrev(regfull);
        if (ab != NULL) stzcpy(regcode, ab, sizeof(regcode));
    }

    /* Store both forms; the main thread picks one per the State format setting.
     * region = full subdivision name (preferred). regcode = the US 2-letter
     * state code ONLY -- non-US subdivision codes ("BY", "ENG", ...) are opaque,
     * so regcode is left empty for them and CODE format falls back to the full
     * name at apply time (matching how non-US has always rendered). */
    if (regfull[0] != '\0')
        stzcpy(out->region, regfull, sizeof(out->region));
    else
        stzcpy(out->region, regcode, sizeof(out->region));
    if (_stricmp(out->ccode, "US") == 0)
        stzcpy(out->regcode, regcode, sizeof(out->regcode));
    else
        out->regcode[0] = '\0';

    return (GBOOL)(out->city[0] != '\0' || out->region[0] != '\0' || out->country[0] != '\0');
}

/*
 * geo_format
 *
 * Substitutes {city} {region} {country} {cc} in the template and drops empty
 * comma segments (geo_join_clean).  inc_country == FALSE renders {country} and
 * {cc} as empty -- used to build the city/state field in SPLIT write mode.
 * CRT only, so it is safe on either thread (but is only called on the main
 * thread here).
 */
static VOID
geo_format(const CHAR *fmt, const struct geo_loc *L, GBOOL inc_country, CHAR *out, INT outsz)
{
    CHAR        raw[160];
    const CHAR *p;
    INT         oi = 0;

    p = (fmt != NULL && fmt[0] != '\0') ? fmt : "{city}, {region}, {country}";
    while (*p != '\0' && oi < (INT)sizeof(raw) - 1) {
        const CHAR *sub = NULL;
        INT         adv = 0;
        if      (!strncmp(p, "{city}",    6)) { sub = L->city;    adv = 6; }
        else if (!strncmp(p, "{region}",  8)) { sub = L->region;  adv = 8; }
        else if (!strncmp(p, "{country}", 9)) { sub = inc_country ? L->country : ""; adv = 9; }
        else if (!strncmp(p, "{cc}",      4)) { sub = inc_country ? L->ccode   : ""; adv = 4; }
        if (sub != NULL) {
            p += adv;
            while (*sub != '\0' && oi < (INT)sizeof(raw) - 1) raw[oi++] = *sub++;
        } else {
            raw[oi++] = *p++;
        }
    }
    raw[oi] = '\0';
    geo_join_clean(raw, out, outsz);
}

/*
 * geoip_http_get  (WORKER THREAD)
 *
 * Performs one blocking WinHTTP GET.  Every WinHTTP leg is bounded by
 * timeout_s, and the read loop bails out if the shutdown event is signalled,
 * so this can never block the worker (or shutdown) indefinitely.  Returns TRUE
 * if a response body was read; *status receives the HTTP status code.  CRT +
 * WinHTTP only.
 */
static GBOOL
geoip_http_get(const CHAR *host, const CHAR *path, GBOOL https,
               INT timeout_s, CHAR *body, INT bodysz, INT *status)
{
    wchar_t       whost[128], wpath[256];
    HINTERNET     hS = NULL, hC = NULL, hR = NULL;
    GBOOL         ok = FALSE;
    DWORD         total = 0, tmo;
    INTERNET_PORT port;

    *status = 0;
    body[0] = '\0';
    if (host == NULL || host[0] == '\0') return FALSE;

    MultiByteToWideChar(CP_UTF8, 0, host, -1, whost, 128);
    MultiByteToWideChar(CP_UTF8, 0, (path != NULL && path[0]) ? path : "/", -1, wpath, 256);
    tmo  = (DWORD)((timeout_s > 0 ? timeout_s : 5) * 1000);
    port = https ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;

    hS = WinHttpOpen(L"SNTIPCTL/1.1 (Total IP Control)",
                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (hS == NULL) goto done;
    WinHttpSetTimeouts(hS, (int)tmo, (int)tmo, (int)tmo, (int)tmo);

    hC = WinHttpConnect(hS, whost, port, 0);
    if (hC == NULL) goto done;

    hR = WinHttpOpenRequest(hC, L"GET", wpath, NULL, WINHTTP_NO_REFERER,
                            WINHTTP_DEFAULT_ACCEPT_TYPES,
                            https ? WINHTTP_FLAG_SECURE : 0);
    if (hR == NULL) goto done;

    WinHttpAddRequestHeaders(hR, L"Accept: application/json",
                             (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD);

    if (!WinHttpSendRequest(hR, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) goto done;
    if (!WinHttpReceiveResponse(hR, NULL)) goto done;

    {
        DWORD st = 0, len = sizeof(st);
        if (WinHttpQueryHeaders(hR,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX, &st, &len, WINHTTP_NO_HEADER_INDEX))
            *status = (INT)st;
    }

    for (;;) {
        DWORD avail = 0, rd = 0;
        if (WaitForSingleObject(geo_ev_stop, 0) == WAIT_OBJECT_0) goto done;
        if (!WinHttpQueryDataAvailable(hR, &avail)) goto done;
        if (avail == 0) { ok = TRUE; break; }              /* end of body     */
        if (total + avail >= (DWORD)bodysz) avail = (DWORD)bodysz - 1 - total;
        if (avail == 0) { ok = TRUE; break; }              /* body cap hit    */
        if (!WinHttpReadData(hR, body + total, avail, &rd)) goto done;
        if (rd == 0) { ok = TRUE; break; }                 /* EOF             */
        total += rd;
    }
    body[total] = '\0';

done:
    if (hR != NULL) WinHttpCloseHandle(hR);
    if (hC != NULL) WinHttpCloseHandle(hC);
    if (hS != NULL) WinHttpCloseHandle(hS);
    return ok;
}

/*
 * geoip_worker  (BACKGROUND THREAD)
 *
 * Drains the request queue, performing one HTTP lookup per request (with
 * optional retries), and pushes successful results back to the main thread.
 * Touches NO BBS SDK function; logs via the thread-safe geoip_log().  Exits
 * promptly when geo_ev_stop is signalled.
 */
static unsigned __stdcall
geoip_worker(VOID *arg)
{
    HANDLE waits[2];

    (VOID)arg;
    waits[0] = geo_ev_stop;
    waits[1] = geo_ev_work;

    for (;;) {
        DWORD w = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
        if (w == WAIT_OBJECT_0) break;                     /* shutdown        */

        for (;;) {
            struct geo_req q;
            struct geo_res r;
            CHAR           body[GEO_BODY_SZ];
            INT            got = 0, attempt, status;

            if (WaitForSingleObject(geo_ev_stop, 0) == WAIT_OBJECT_0) return 0;

            EnterCriticalSection(&geo_cs);
            if (geo_reqn > 0) {
                q = geo_reqq[geo_reqh];
                geo_reqh = (geo_reqh + 1) % GEO_Q_MAX;
                geo_reqn--;
                got = 1;
            }
            LeaveCriticalSection(&geo_cs);
            if (!got) break;                               /* queue drained   */

            memset(&r, 0, sizeof(r));
            r.channel = q.channel;
            strncpy(r.ip, q.ip, sizeof(r.ip) - 1);
            strncpy(r.userid, q.userid, sizeof(r.userid) - 1);

            for (attempt = 0; attempt <= q.retries; attempt++) {
                if (WaitForSingleObject(geo_ev_stop, 0) == WAIT_OBJECT_0) return 0;
                status = 0;
                if (geoip_http_get(q.host, q.path, q.https, q.timeout,
                                   body, sizeof(body), &status)) {
                    if (status == 200) {
                        if (geoip_parse_body(q.provider, body, &r.loc)) {
                            r.ok = TRUE;
                            geoip_log(GEOLOG_NORMAL, q.userid, q.ip,
                                      "GeoIP lookup succeeded");
                        } else {
                            geoip_log(GEOLOG_ERRORS, q.userid, q.ip,
                                      "GeoIP response had no usable location");
                        }
                        break;                             /* 200 = definitive*/
                    } else {
                        CHAR e[80];
                        if (status == 429)
                            _snprintf(e, sizeof(e),
                                      "GeoIP rate limited (HTTP 429), attempt %d",
                                      attempt + 1);
                        else
                            _snprintf(e, sizeof(e),
                                      "GeoIP HTTP status %d, attempt %d",
                                      status, attempt + 1);
                        geoip_log(GEOLOG_ERRORS, q.userid, q.ip, e);
                    }
                } else {
                    CHAR e[80];
                    _snprintf(e, sizeof(e),
                              "GeoIP request failed (network/timeout), attempt %d",
                              attempt + 1);
                    geoip_log(GEOLOG_ERRORS, q.userid, q.ip, e);
                }
                /* Back off before a retry, but wake immediately on shutdown. */
                if (attempt < q.retries) {
                    if (WaitForSingleObject(geo_ev_stop, 500) == WAIT_OBJECT_0)
                        return 0;
                }
            }

            /* Only push a usable result; failures are logged and dropped. */
            if (r.ok) {
                EnterCriticalSection(&geo_cs);
                if (geo_resn < GEO_Q_MAX) {
                    geo_resq[geo_rest] = r;
                    geo_rest = (geo_rest + 1) % GEO_Q_MAX;
                    geo_resn++;
                }
                LeaveCriticalSection(&geo_cs);
            }
        }
    }
    return 0;
}

/*
 * geo_cache_lookup / geo_cache_store  (MAIN THREAD ONLY)
 *
 * Simple linear per-IP cache with per-entry expiry.  Only ever touched from
 * the main thread (geoip_enqueue and geoip_drain), so no locking is needed.
 */
static GBOOL
geo_cache_lookup(const CHAR *ip, struct geo_loc *out)
{
    INT       i;
    ULONGLONG now = GetTickCount64();
    if (ip == NULL || ip[0] == '\0') return FALSE;
    for (i = 0; i < GEO_CACHE_MAX; i++) {
        if (strcmp(geo_cache[i].ip, ip) == 0 && geo_cache[i].expiry > now) {
            *out = geo_cache[i].loc;
            return TRUE;
        }
    }
    return FALSE;
}

static VOID
geo_cache_store(const CHAR *ip, const struct geo_loc *L)
{
    INT       i, slot = -1;
    ULONGLONG now = GetTickCount64();
    ULONGLONG ttl = (ULONGLONG)(geoip_cache_min > 0 ? geoip_cache_min : 1440) * 60000ULL;

    if (ip == NULL || ip[0] == '\0') return;
    for (i = 0; i < GEO_CACHE_MAX; i++)          /* reuse existing entry      */
        if (strcmp(geo_cache[i].ip, ip) == 0) { slot = i; break; }
    if (slot < 0)                                 /* else an empty/expired one */
        for (i = 0; i < GEO_CACHE_MAX; i++)
            if (geo_cache[i].ip[0] == '\0' || geo_cache[i].expiry <= now) { slot = i; break; }
    if (slot < 0) {                               /* else round-robin evict    */
        slot = geo_cache_next;
        geo_cache_next = (geo_cache_next + 1) % GEO_CACHE_MAX;
    }
    stzcpy(geo_cache[slot].ip, ip, sizeof(geo_cache[slot].ip));
    /*
     * In per-IP mode (geoip_cache_bytime == FALSE) a known IP is never looked
     * up again, so the entry does not expire by time -- it lives until the slot
     * is reused or the BBS restarts.  In time mode it expires after the cache
     * duration.
     */
    geo_cache[slot].expiry = geoip_cache_bytime ? (now + ttl) : (ULONGLONG)-1;
    geo_cache[slot].loc    = *L;
}

/*
 * geo_set_field  (MAIN THREAD)
 *
 * Copies val into the numbered usracc field (1=usrad1..4=usrad4, 5=usrpho) but
 * only if the stored value actually differs.  Returns TRUE if it changed the
 * field (so the caller knows whether an updaccu() is needed).
 */
static GBOOL
geo_set_field(struct usracc *ua, INT fieldnum, const CHAR *val)
{
    CHAR *field;
    INT   maxlen;

    switch (fieldnum) {
    case 1: field = ua->usrad1; maxlen = NADSIZ; break;
    case 2: field = ua->usrad2; maxlen = NADSIZ; break;
    case 3: field = ua->usrad3; maxlen = NADSIZ; break;
    case 4: field = ua->usrad4; maxlen = NADSIZ; break;
    case 5: field = ua->usrpho; maxlen = PHOSIZ; break;
    default: return FALSE;
    }
    if (strncmp(field, val, maxlen - 1) == 0) return FALSE;   /* unchanged */
    stzcpy(field, val, maxlen);
    return TRUE;
}

/*
 * geoip_apply  (MAIN THREAD)
 *
 * Formats the location components and writes them to the user's profile
 * field(s), honouring the write mode:
 *   COMBINED -- the whole location (incl. country per the template) in one field.
 *   SPLIT    -- city/state in geoip_field and the country (full name or 2-letter
 *               code) in geoip_cty_field.
 * Applied only if the channel still holds the SAME user (userid) that requested
 * the lookup, so a recycled channel is never written to the wrong user.  A
 * single updaccu() persists the record if any field actually changed.
 */
static VOID
geoip_apply(INT channel, const CHAR *userid, const struct geo_loc *L)
{
    struct usracc *ua;
    CHAR           primary[GEO_LOC_SZ];
    GBOOL          changed = FALSE;

    if (channel < 0 || channel >= nterms) return;
    ua = uacoff(channel);
    if (ua == NULL) return;
    if (userid != NULL && userid[0] != '\0' && strcmp(ua->userid, userid) != 0)
        return;                                   /* channel reused -- skip    */

    /* Apply the State format choice here, on the main thread, so it always uses
     * the current setting: CODE swaps in the 2-letter code when one exists (US),
     * FULL keeps the full subdivision name.  Work on a local copy so {region}
     * substitution in geo_format() renders the chosen form. */
    {
        struct geo_loc lc = *L;
        if (geoip_reg_fmt == GEORF_CODE && lc.regcode[0] != '\0')
            stzcpy(lc.region, lc.regcode, sizeof(lc.region));

        if (geoip_split) {
            const CHAR *country = (geoip_cty_fmt == GEOCF_CODE) ? lc.ccode : lc.country;
            geo_format(geoip_format, &lc, FALSE, primary, sizeof(primary));   /* City, State */
            changed |= geo_set_field(ua, geoip_field, primary);
            /* Only write the country separately when it targets a different field
             * (guards against a misconfiguration that would clobber city/state). */
            if (geoip_cty_field != geoip_field)
                changed |= geo_set_field(ua, geoip_cty_field, country);
        } else {
            geo_format(geoip_format, &lc, TRUE, primary, sizeof(primary));    /* City, State, Country */
            changed |= geo_set_field(ua, geoip_field, primary);
        }
    }

    if (!changed) return;                         /* nothing new -- no write   */
    updaccu(ua);                                  /* persist without curusr()  */

    {
        CHAR  evt[160];
        CHAR  ip[46];
        snt_source_ip(channel, ip, sizeof(ip));
        if (geoip_split)
            _snprintf(evt, sizeof(evt),
                      "GeoIP stored: \"%s\" (field %d) + country (field %d)",
                      primary, geoip_field, geoip_cty_field);
        else
            _snprintf(evt, sizeof(evt), "GeoIP stored to field %d: %s",
                      geoip_field, primary);
        geoip_log(GEOLOG_NORMAL, ua->userid, ip, evt);
    }
}

/*
 * geoip_drain  (MAIN THREAD, rtkick target)
 *
 * Applies all pending results to their users' profile fields and updates the
 * cache, then re-arms itself for one second later.  This is the only place a
 * lookup result re-enters the BBS.
 *
 * The self-re-arm means one one-shot kick is always queued while running.  The
 * leading geo_started guard makes any kick that is dispatched after geoip_stop()
 * (which clears geo_started and deletes geo_cs) a harmless no-op -- it returns
 * before touching the freed critical section and does not re-arm.
 */
static VOID
geoip_drain(VOID)
{
    if (!geo_started) return;                     /* shutting down -- do nothing */

    for (;;) {
        struct geo_res r;
        INT            got = 0;

        EnterCriticalSection(&geo_cs);
        if (geo_resn > 0) {
            r = geo_resq[geo_resh];
            geo_resh = (geo_resh + 1) % GEO_Q_MAX;
            geo_resn--;
            got = 1;
        }
        LeaveCriticalSection(&geo_cs);
        if (!got) break;

        if (r.ok) {
            if (geoip_cache_on) geo_cache_store(r.ip, &r.loc);
            geoip_apply(r.channel, r.userid, &r.loc);
        }
    }

    if (geo_started) rtkick(1, geoip_drain);      /* re-arm for next second    */
}

/*
 * geoip_enqueue  (MAIN THREAD, from logon)
 *
 * Entry point for a GeoIP lookup.  Skips private/reserved IPs, serves cache
 * hits immediately, and otherwise snapshots a self-contained request for the
 * worker thread.  Returns instantly -- login is never delayed.
 */
static VOID
geoip_enqueue(INT channel, const CHAR *ip, const CHAR *userid)
{
    struct geo_req q;
    struct geo_loc loc;

    if (!geoip_enabled || !geo_started) return;

    if (ip == NULL || ip[0] == '\0' || is_private_ip(ip)) {
        geoip_log(GEOLOG_VERBOSE, userid, ip,
                  "GeoIP skipped (private/reserved/invalid IP)");
        return;
    }

    if (geoip_cache_on && geo_cache_lookup(ip, &loc)) {
        geoip_log(GEOLOG_VERBOSE, userid, ip, "GeoIP cache hit");
        geoip_apply(channel, userid, &loc);
        return;
    }
    if (geoip_cache_on)
        geoip_log(GEOLOG_VERBOSE, userid, ip, "GeoIP cache miss -- queuing lookup");

    memset(&q, 0, sizeof(q));
    q.channel  = channel;
    stzcpy(q.ip, ip, sizeof(q.ip));
    stzcpy(q.userid, userid != NULL ? userid : "", sizeof(q.userid));
    q.https    = geoip_use_https;
    q.timeout  = geoip_timeout;
    q.provider = geoip_provider;
    q.retries  = geoip_retries;
    geoip_build_url(geoip_provider, ip, q.host, sizeof(q.host), q.path, sizeof(q.path));

    EnterCriticalSection(&geo_cs);
    if (geo_reqn < GEO_Q_MAX) {
        geo_reqq[geo_reqt] = q;
        geo_reqt = (geo_reqt + 1) % GEO_Q_MAX;
        geo_reqn++;
        SetEvent(geo_ev_work);
        LeaveCriticalSection(&geo_cs);
    } else {
        LeaveCriticalSection(&geo_cs);
        geoip_log(GEOLOG_ERRORS, userid, ip,
                  "GeoIP request queue full -- lookup dropped");
    }
}

/*
 * geoip_start / geoip_stop
 *
 * geoip_start creates the worker thread, its signalling events, and arms the
 * result-drain rtkick.  Called once at init (the infrastructure is cheap when
 * idle and only actually does work when the feature is enabled).
 *
 * geoip_stop signals the worker, JOINS it (so the DLL is never unloaded out
 * from under a running thread), then tears down the events and critical
 * section.  Called from finrou on the main thread -- never from DllMain.
 */
static VOID
geoip_start(VOID)
{
    if (geo_started) return;

    geo_reqh = geo_reqt = geo_reqn = 0;
    geo_resh = geo_rest = geo_resn = 0;
    geo_cache_next = 0;
    memset(geo_cache, 0, sizeof(geo_cache));

    InitializeCriticalSection(&geo_cs);
    geo_ev_work = CreateEvent(NULL, FALSE, FALSE, NULL);   /* auto-reset      */
    geo_ev_stop = CreateEvent(NULL, TRUE,  FALSE, NULL);   /* manual-reset    */
    if (geo_ev_work == NULL || geo_ev_stop == NULL) {
        shocst("Total IP Control", "WARNING: GeoIP event objects failed -- lookups disabled");
        if (geo_ev_work) { CloseHandle(geo_ev_work); geo_ev_work = NULL; }
        if (geo_ev_stop) { CloseHandle(geo_ev_stop); geo_ev_stop = NULL; }
        DeleteCriticalSection(&geo_cs);
        return;
    }

    geo_worker = (HANDLE)_beginthreadex(NULL, 0, geoip_worker, NULL, 0, NULL);
    if (geo_worker == NULL) {
        shocst("Total IP Control", "WARNING: GeoIP worker thread failed -- lookups disabled");
        CloseHandle(geo_ev_work); geo_ev_work = NULL;
        CloseHandle(geo_ev_stop); geo_ev_stop = NULL;
        DeleteCriticalSection(&geo_cs);
        return;
    }

    geo_started = TRUE;
    rtkick(1, geoip_drain);                                /* start the drain */
}

static VOID
geoip_stop(VOID)
{
    if (!geo_started) return;

    geo_started = FALSE;                          /* stops drain re-arming     */
    SetEvent(geo_ev_stop);                        /* wake + tell worker to end */

    /*
     * Join the worker before freeing anything it might touch.  Each WinHTTP
     * leg is bounded by the configured timeout and the worker checks the stop
     * event between operations, so it exits promptly; the wait is unbounded
     * only as a guarantee that teardown never races a live thread.
     */
    WaitForSingleObject(geo_worker, INFINITE);
    CloseHandle(geo_worker); geo_worker = NULL;

    CloseHandle(geo_ev_work); geo_ev_work = NULL;
    CloseHandle(geo_ev_stop); geo_ev_stop = NULL;
    DeleteCriticalSection(&geo_cs);
}

/* ======================================================================== */
/*   User profile IP recording                                               */
/* ======================================================================== */

/*
 * write_ip_to_profile
 *
 * Writes the caller's real IPv4 address (in dotted-decimal notation) to
 * the configured field of the current user's profile record, then calls
 * updacc() to persist the change to the Btrieve user database.
 *
 * Called from sntipctl_logon() only for sessions that passed the connection
 * limit check.  usaptr must be valid at this point (user is authenticated).
 *
 * Field mapping:  1=usrad1  2=usrad2  3=usrad3  4=usrad4  5=usrpho
 */
static VOID
write_ip_to_profile(const CHAR *ip)
{
    CHAR  ipbuf[64];
    CHAR *field;
    INT   maxlen;

    if (usaptr == NULL || ip == NULL || ip[0] == '\0') return;

    switch (usrip_field) {
    case 1: field = usaptr->usrad1; maxlen = NADSIZ; break;
    case 2: field = usaptr->usrad2; maxlen = NADSIZ; break;
    case 3: field = usaptr->usrad3; maxlen = NADSIZ; break;
    case 4: field = usaptr->usrad4; maxlen = NADSIZ; break;
    case 5: field = usaptr->usrpho; maxlen = PHOSIZ; break;
    default: return;
    }

    /*
     * Render to fit the field rather than letting stzcpy clip: a clipped IPv6
     * address still looks like an address, so it would quietly put a wrong one
     * in the user's record.  See snt_ip_for_field -- long v6 becomes its /64.
     */
    snt_ip_for_field(ip, maxlen, ipbuf, sizeof(ipbuf));
    if (ipbuf[0] == '\0') {
        /* Unparseable and unrenderable -- headers are validated now, so this is
         * defensive only.  Never leave a stale value silently in place. */
        dbglog("   chan %02x: profile write skipped -- cannot render \"%s\" for field %d",
               usrnum + 1, ip, usrip_field);
        return;
    }
    if (strcmp(ipbuf, "IPv6") == 0 && log_mode != LOGM_OFF)
        snt_audit_s("PROXCLIP LOGS", usaptr->userid, ip,
                    spr("chan %02x: profile field %d is too short for an IPv6 address "
                        "-- wrote marker; use field 1-4 to record it in full",
                        usrnum + 1, usrip_field));

    stzcpy(field, ipbuf, maxlen);
    updacc();

    if (log_mode != LOGM_OFF)
        snt_audit_s("PROXCLIP LOGS", usaptr->userid, ip,
                    spr("chan %02x: IP %s recorded to profile field %d",
                        usrnum + 1, ipbuf, usrip_field));
}

/* ======================================================================== */
/*   Settings editor (/TIP, or a menu item with MENU=SYSOPMENU)              */
/*                                                                           */
/*   Two levels, like the Globals =gset menu: a list of six sections with    */
/*   their setting counts, then the chosen section's settings, numbered      */
/*   from 1.  The Sysop types a setting's number, sees its current value     */
/*   and what is allowed, and types a new one; a setting with fixed choices  */
/*   lists them by number.  ? at any prompt explains the setting, X goes     */
/*   back one step.  MASTER access.                                          */
/*   Every change applies at once, is saved to SNTIPCTL.DAT, and is noted    */
/*   in the Audit Trail with the Sysop's userid.                             */
/*                                                                           */
/*   All screen text lives in SNTIPCTL.MSG (LEVEL6, editable in CNF); the    */
/*   values reach it through the N!SNT... text variables below.              */
/* ======================================================================== */

/* Text-variable values for the editor screens (see snt_register_tvars). */
static CHAR tv_status[96];          /* N!SNTSTATUS   one-line summary       */
static CHAR tv_secnum[8];           /* N!SNTSECNUM   section number         */
static CHAR tv_secname[40];         /* N!SNTSECNAME  section name           */
static CHAR tv_seccnt[8];           /* N!SNTSECCNT   a count (see the MSG)  */
static CHAR tv_secinfo[40];         /* N!SNTSECINFO  "8 settings", "3 of 50 in use" */
static CHAR tv_page[16];            /* N!SNTPAGE     "page 2 of 5", or ""   */
static CHAR tv_cmds[24];            /* N!SNTCMDS     "N, P, H or X"         */
static CHAR tv_rowclr[12];          /* N!SNTROWCLR   colour for the value   */
static CHAR tv_rownote[48];         /* N!SNTROWNOTE  "(inactive: ...)"      */
static CHAR tv_rownum[8];           /* N!SNTROWNUM   setting number         */
static CHAR tv_rowname[32];         /* N!SNTROWNAME  setting name           */
static CHAR tv_rowval[112];         /* N!SNTROWVAL   its current value      */
static CHAR tv_hint[96];            /* N!SNTHINT     what may be entered    */
static CHAR tv_chnum[8];            /* N!SNTCHNUM    choice number          */
static CHAR tv_chname[16];          /* N!SNTCHNAME   choice name            */
static CHAR tv_chdesc[64];          /* N!SNTCHDESC   choice description     */

#define FT_YN      0                /* YES or NO (GBOOL)                    */
#define FT_NUM     1                /* number in a range (INT)              */
#define FT_KEY     2                /* BBS key name, stored upper case      */
#define FT_STR     3                /* text                                 */
#define FT_SECRET  4                /* text never shown on screen           */
#define FT_CIDR    5                /* IPv4 address or range                */
#define FT_CIDR6   6                /* IPv6 address or range                */
#define FT_LIST    7                /* one of a fixed list (INT or GBOOL)   */
#define FT_CACHE   8                /* GeoIP cache mode (two flags)         */

typedef struct choice {             /* one choice of a list setting         */
    const CHAR *key;                /*   what is shown and typed            */
    const CHAR *desc;               /*   short description in the list      */
    INT         value;              /*   value stored in the setting        */
} CHOICE;

typedef struct field {              /* one editable setting                 */
    const CHAR   *name;             /*   label on the settings screen       */
    INT           type;             /*   FT_xxx                             */
    VOID         *var;              /*   the live setting itself            */
    INT           size;             /*   sizeof the live setting            */
    INT           min, max;         /*   range of a number                  */
    const CHOICE *ch;               /*   choices of a list setting          */
    INT           nch;              /*   how many                           */
    const CHAR   *hint;             /*   what may be entered                */
    INT           help;             /*   help message (? at its prompt)     */
} FIELD;

#define NCH(c) ((INT)(sizeof(c) / sizeof((c)[0])))

static const CHOICE ynch[] = {
    { "YES", "", TRUE },
    { "NO",  "", FALSE }
};
static const CHOICE logch[] = {
    { "OFF",   "nothing is recorded",                 LOGM_OFF   },
    { "AUDIT", "the BBS Audit Trail only",            LOGM_AUDIT },
    { "LOG",   "daily files in TOTALIPCONTROL only",  LOGM_LOG   },
    { "BOTH",  "the Audit Trail and the files",       LOGM_BOTH  }
};
static const CHOICE fldch[] = {
    { "ADDRESS1", "address line 1",                   1 },
    { "ADDRESS2", "address line 2",                   2 },
    { "ADDRESS3", "address line 3",                   3 },
    { "ADDRESS4", "address line 4",                   4 },
    { "PHONE",    "phone number (15 characters)",     5 }
};
static const CHOICE prvch[] = {
    { "IPWHO.IS",   "ipwho.is (default)",             GEOPRV_IPWHOIS },
    { "IP-API.COM", "ip-api.com, free service is HTTP only", GEOPRV_IPAPI },
    { "IPAPI.CO",   "ipapi.co",                       GEOPRV_IPAPICO },
    { "IPINFO.IO",  "ipinfo.io",                      GEOPRV_IPINFO  }
};
static const CHOICE cachech[] = {
    { "OFF",  "look the address up at every logon",   GEOCM_OFF  },
    { "TIME", "remember results for Cache duration",   GEOCM_TIME },
    { "IP",   "remember each address until a restart", GEOCM_IP  }
};
static const CHOICE geologch[] = {
    { "OFF",     "no GeoIP log",                      GEOLOG_OFF     },
    { "ERRORS",  "failed lookups only",               GEOLOG_ERRORS  },
    { "NORMAL",  "each lookup and profile update",    GEOLOG_NORMAL  },
    { "VERBOSE", "everything, including cache use",   GEOLOG_VERBOSE }
};
static const CHOICE modech[] = {
    { "COMBINED", "the whole location in one field",  FALSE },
    { "SPLIT",    "city/state and country apart",     TRUE  }
};
static const CHOICE cfmtch[] = {
    { "FULL", "the name, e.g. United States",         GEOCF_FULL },
    { "CODE", "the two-letter code, e.g. US",         GEOCF_CODE }
};
static const CHOICE rfmtch[] = {
    { "CODE", "the two-letter code, e.g. MN",         GEORF_CODE },
    { "FULL", "the name, e.g. Minnesota",             GEORF_FULL }
};

/* Table-entry shorthands; each takes the live variable itself. */
#define F_YN(n, v, h)          { n, FT_YN,   &(v), sizeof(v), 0, 0, ynch, 2, "YES or NO", h }
#define F_NUM(n, v, lo, hi, t, h) { n, FT_NUM, &(v), sizeof(v), lo, hi, NULL, 0, t, h }
#define F_LIST(n, v, c, t, h)  { n, FT_LIST, &(v), sizeof(v), 0, 0, c, NCH(c), t, h }
#define F_TXT(n, ty, v, t, h)  { n, ty,      (v),  sizeof(v), 0, 0, NULL, 0, t, h }

#define HINT_IP4 "address or range (10.0.0.0/24), or - to clear"
#define HINT_IP6 "IPv6 address or range (2001:db8::/32), or - to clear"

/*
 * The single settings of each section, in the order they are shown.  The
 * address lists (trusted proxies, whitelists) are added after them by
 * ed_build(), one row per entry.
 */
static const FIELD gen_tmpl[] = {
    F_YN  ("Connection limit",          conn_limit_enabled, HCONLIM),
    F_NUM ("Max connections per IP",    conn_limit_max, 1, 1000, "1-1000", HMAXCON),
    F_LIST("Audit logging",             log_mode, logch, "OFF, AUDIT, LOG or BOTH", HLOGMODE),
    F_YN  ("Record IP in profile",      usrip_enabled, HUIPON),
    F_LIST("Profile field for IP",      usrip_field, fldch,
           "ADDRESS1-ADDRESS4 or PHONE", HUIPFLD),
    F_TXT ("Limit bypass key", FT_KEY,  bypass_key,
           "a BBS key name, or - for none", HBYPASS),
    F_TXT ("Staff key for /WHOSON", FT_KEY, staff_key,
           "a BBS key name, or - for Sysop only", HSTAFF),
    F_YN  ("Debug trace log",           debug_enabled, HDEBUG)
};
static const FIELD tel_tmpl[] = {
    F_YN  ("Trusted proxy only",        proxy_trust_enabled, HPRXTRU),
    F_YN  ("Block direct connections",  proxy_block_enabled, HPRXBLK)
};
static const FIELD geo_tmpl[] = {
    F_YN  ("GeoIP lookups",             geoip_enabled, HGEOON),
    F_LIST("Write mode",                geoip_split, modech, "COMBINED or SPLIT", HGEOMODE),
    F_LIST("City/state field",          geoip_field, fldch,
           "ADDRESS1-ADDRESS4 or PHONE", HGEOFLD),
    F_LIST("Country field",             geoip_cty_field, fldch,
           "ADDRESS1-ADDRESS4 or PHONE", HGEOCFLD),
    F_LIST("Country format",            geoip_cty_fmt, cfmtch, "FULL or CODE", HGEOCFMT),
    F_LIST("State format",              geoip_reg_fmt, rfmtch, "CODE or FULL", HGEORFMT),
    F_LIST("GeoIP provider",            geoip_provider, prvch,
           "IPWHO.IS, IP-API.COM, IPAPI.CO or IPINFO.IO", HGEOPRV),
    F_TXT ("API host", FT_STR,          geoip_host,
           "a host name, or - for the provider's own", HGEOHOST),
    F_TXT ("API key", FT_SECRET,        geoip_key,
           "the provider's key or token, or - to clear", HGEOKEY),
    F_YN  ("Use HTTPS",                 geoip_use_https, HGEOTLS),
    F_NUM ("Lookup timeout (seconds)",  geoip_timeout, 1, 60, "1-60", HGEOTMO),
    { "Cache", FT_CACHE, NULL, 0, 0, 0, cachech, NCH(cachech),
      "OFF, TIME or IP", HGEOCACH },
    F_NUM ("Cache duration (minutes)",  geoip_cache_min, 1, 44640, "1-44640", HGEODUR),
    F_NUM ("Retries on failure",        geoip_retries, 0, 5, "0-5", HGEORTY),
    F_LIST("GeoIP log level",           geoip_loglevel, geologch,
           "OFF, ERRORS, NORMAL or VERBOSE", HGEOLOG),
    F_TXT ("Location format", FT_STR,   geoip_format,
           "{city} {region} {country} {cc} and text, or - for the default", HGEOFMT)
};
static const FIELD ssh_tmpl[] = {
    F_YN  ("Manage SSH connections",    ssh_manage_enabled, HSSHMAN),
    F_YN  ("Read PROXY header",         ssh_hdr_enabled, HSSHHDR),
    F_YN  ("Trusted proxy only",        ssh_trust_enabled, HSSHTRU),
    F_YN  ("Block direct connections",  ssh_block_enabled, HSSHBLK)
};

/*
 * The full table, built once at startup by ed_build(): grouped by section,
 * numbered from 1 within each section.  The record layout does not depend
 * on this order.
 */
#define NFIELDS_MAX   (8 + 2 + SNTIPCTL_MAX_TRUSTED + SNTIPCTL_MAX_WHITELIST \
                       + SNTIPCTL_MAX_WHITELIST6 + NCH(geo_tmpl) + 4 + SNTIPCTL_MAX_TRUSTED)
#define NSECTIONS_MAX 6

static FIELD fields[NFIELDS_MAX];
static INT   nfields;
static CHAR  ed_names[NFIELDS_MAX][20];  /* names of generated rows        */
#define NFIELDS nfields

static struct {
    const CHAR *title;
    INT         first;              /* first field index (0-based)          */
    INT         count;
    INT         perpage;            /* rows per page; 0 = all on one screen */
} sections[NSECTIONS_MAX];
static INT nsections;
#define NSECTIONS nsections

static VOID
ed_section(const CHAR *title, INT perpage)
{
    sections[nsections].title   = title;
    sections[nsections].first   = nfields;
    sections[nsections].count   = 0;
    sections[nsections].perpage = perpage;
    nsections++;
}

static VOID
ed_add(const FIELD *tmpl, INT n)
{
    INT i;

    for (i = 0; i < n; i++) {
        fields[nfields++] = tmpl[i];
        sections[nsections - 1].count++;
    }
}

/* One row per entry of an address list: "<label> 1" .. "<label> n". */
static VOID
ed_add_list(const CHAR *label, INT type, VOID *base, INT elsize, INT n,
            const CHAR *hint, INT help)
{
    FIELD *f;
    INT    i;

    for (i = 0; i < n; i++) {
        f = &fields[nfields];
        sprintf(ed_names[nfields], "%s %d", label, i + 1);
        setmem((CHAR *)f, sizeof(*f), 0);
        f->name = ed_names[nfields];
        f->type = type;
        f->var  = (CHAR *)base + i * elsize;
        f->size = elsize;
        f->hint = hint;
        f->help = help;
        nfields++;
        sections[nsections - 1].count++;
    }
}

/* Build the settings table and its sections (once, at startup). */
VOID
ed_build(VOID)
{
    nfields = nsections = 0;
    ed_section("General Settings", 0);
    ed_add(gen_tmpl, NCH(gen_tmpl));
    ed_section("Telnet Trusted Proxies", 0);
    ed_add(tel_tmpl, NCH(tel_tmpl));
    ed_add_list("Trusted proxy", FT_CIDR, trusted_proxy_cidrs, sizeof(struct snt_cidr),
                SNTIPCTL_MAX_TRUSTED, HINT_IP4, HPRXIP);
    ed_section("IPv4 Whitelist", 10);
    ed_add_list("Entry", FT_CIDR, whitelist_cidrs, sizeof(struct snt_cidr),
                SNTIPCTL_MAX_WHITELIST, HINT_IP4, HWL4);
    ed_section("IPv6 Whitelist", 10);
    ed_add_list("Entry", FT_CIDR6, whitelist6_cidrs, sizeof(struct snt_cidr6),
                SNTIPCTL_MAX_WHITELIST6, HINT_IP6, HWL6);
    ed_section("GeoIP Location", 0);
    ed_add(geo_tmpl, NCH(geo_tmpl));
    ed_section("SSH Settings", 0);
    ed_add(ssh_tmpl, NCH(ssh_tmpl));
    ed_add_list("Trusted proxy", FT_CIDR, ssh_proxy_cidrs, sizeof(struct snt_cidr),
                SNTIPCTL_MAX_TRUSTED, HINT_IP4, HSSHIP);
}

/* Pages in section s (1 unless it is paged). */
static INT
ed_npages(INT s)
{
    INT pp = sections[s].perpage;

    return pp > 0 ? (sections[s].count + pp - 1) / pp : 1;
}

#define ROWVALW    42               /* widest value shown in a settings row */
                                    /* (keeps rows clear of the host's      */
                                    /* automatic wrap near column 80)       */

                                    /* editor states (usrptr->substt; 0 is  */
                                    /* menu entry, see sntipctl_stt)        */
#define ST_TOP     1                /*   at the list of sections            */
#define ST_SECT    2                /*   at one section's settings          */
#define ST_VALUE   3                /*   entering a new value               */
#define ST_CHOICE  4                /*   picking one of a setting's choices */

static INT   ed_sect[MAXNTERM];     /* section shown, per channel           */
static INT   ed_spage[MAXNTERM];    /* page of that section, per channel    */
static INT   ed_fld[MAXNTERM];      /* setting being edited, per channel    */
static GBOOL ed_menushown;          /* a screen with its prompt just shown? */

/* A list or yes/no setting's stored value; GBOOL and INT settings both occur. */
static INT
ed_getint(const FIELD *f)
{
    if (f->size == (INT)sizeof(GBOOL))
        return *(const GBOOL *)f->var;
    return *(const INT *)f->var;
}

static VOID
ed_setint(const FIELD *f, INT v)
{
    if (f->size == (INT)sizeof(GBOOL))
        *(GBOOL *)f->var = (GBOOL)v;
    else
        *(INT *)f->var = v;
}

/* Index of the choice set now, or -1 if the stored value is not one of them. */
static INT
ed_curchoice(const FIELD *f)
{
    INT i, v;

    if (f->type == FT_CACHE)
        v = !geoip_cache_on ? GEOCM_OFF : geoip_cache_bytime ? GEOCM_TIME : GEOCM_IP;
    else
        v = (f->type == FT_YN) ? (ed_getint(f) ? TRUE : FALSE) : ed_getint(f);
    for (i = 0; i < f->nch; i++)
        if (f->ch[i].value == v)
            return i;
    return -1;
}

static VOID
ed_fieldvalue(const FIELD *f, CHAR *dst, INT dstsz)
{
    INT i;

    switch (f->type) {
    case FT_YN:
    case FT_LIST:
    case FT_CACHE:
        i = ed_curchoice(f);
        stzcpy(dst, i >= 0 ? f->ch[i].key : "?", dstsz);
        break;
    case FT_NUM:
        _snprintf(dst, dstsz - 1, "%d", *(const INT *)f->var);
        dst[dstsz - 1] = '\0';
        break;
    case FT_KEY:
        stzcpy(dst, ((const CHAR *)f->var)[0] != '\0' ? (const CHAR *)f->var : "(none)", dstsz);
        break;
    case FT_SECRET:
        stzcpy(dst, ((const CHAR *)f->var)[0] != '\0' ? "(set)" : "(not set)", dstsz);
        break;
    case FT_CIDR:
        cidr_to_str((const struct snt_cidr *)f->var, dst, dstsz);
        break;
    case FT_CIDR6:
        if (((const struct snt_cidr6 *)f->var)->prefix == 0)
            stzcpy(dst, "(not set)", dstsz);
        else
            cidr6_to_str((const struct snt_cidr6 *)f->var, dst, dstsz);
        break;
    default:                        /* FT_STR                               */
        if (((const CHAR *)f->var)[0] != '\0')
            stzcpy(dst, (const CHAR *)f->var, dstsz);
        else if (f->var == geoip_host) {
            _snprintf(dst, dstsz - 1, "%s (provider's own)",
                      geoip_default_host(geoip_provider));
            dst[dstsz - 1] = '\0';
        }
        else
            stzcpy(dst, "(blank)", dstsz);
        break;
    }
}

/*
 * A short remark shown after a setting's value when the setting cannot have
 * its effect right now, so the menu never looks more protective than it is.
 * NULL when there is nothing to say.
 */
static const CHAR *
ed_rownote(const FIELD *f)
{
    if (f->var == &proxy_trust_enabled && proxy_trust_enabled && trusted_proxy_count == 0)
        return "no proxy listed: every header ignored";
    if (f->var == &proxy_block_enabled && proxy_block_enabled && trusted_proxy_count == 0)
        return "inactive: no proxy listed";
    if (f->var == &ssh_hdr_enabled || f->var == &ssh_trust_enabled ||
        f->var == &ssh_block_enabled) {
        if (!ssh_manage_enabled)
            return "not used: Manage SSH is NO";
        if (f->var == &ssh_hdr_enabled && ssh_hdr_enabled && !ssh_recv_hooked)
            return "inactive until the BBS restarts";
        if (f->var == &ssh_trust_enabled && ssh_trust_enabled && ssh_proxy_count == 0)
            return "no proxy listed: every header ignored";
        if (f->var == &ssh_block_enabled && ssh_block_enabled && ssh_proxy_count == 0)
            return "inactive: no proxy listed";
    }
    if (f->var == &geoip_cty_field && !geoip_split)
        return "not used with COMBINED";
    if (f->var == &geoip_cache_min && !(geoip_cache_on && geoip_cache_bytime))
        return "not used: Cache is not TIME";
    return NULL;
}

/* Section a setting (0-based field index) belongs to. */
static INT
ed_sectof(INT fld)
{
    INT s;

    for (s = 0; s < NSECTIONS; s++)
        if (fld >= sections[s].first && fld < sections[s].first + sections[s].count)
            return s;
    return 0;
}

/* Fill the row text variables for setting idx (0-based field index). */
static VOID
ed_load_row(INT idx)
{
    const FIELD *f = &fields[idx];

    sprintf(tv_rownum, "%d", idx - sections[ed_sectof(idx)].first + 1);
    stzcpy(tv_rowname, f->name, sizeof(tv_rowname));
    ed_fieldvalue(f, tv_rowval, sizeof(tv_rowval));
    stzcpy(tv_hint, f->hint, sizeof(tv_hint));
}

/*
 * The colour a value is shown in on the settings screen (N!SNTROWCLR):
 * YES bright green, NO and OFF plain, anything not set dim, other values
 * bright white.  Only the screen uses it; the value text never changes.
 */
static const CHAR *
ed_valcolor(const CHAR *val)
{
    if (strcmp(val, "YES") == 0)                     return "\x1b[1;32m";
    if (strcmp(val, "NO") == 0 || strcmp(val, "OFF") == 0) return "\x1b[0;37m";
    if (val[0] == '(')                               return "\x1b[1;30m";
    return "\x1b[1;37m";
}

/* What the section list says about section s (N!SNTSECINFO). */
static VOID
ed_secinfo(INT s)
{
    INT  ncidr = 0, used = 0, i;
    CHAR v[64];

    for (i = 0; i < sections[s].count; i++) {    /* address rows, and set  */
        const FIELD *f = &fields[sections[s].first + i];
        if (f->type != FT_CIDR && f->type != FT_CIDR6)
            continue;
        ncidr++;
        ed_fieldvalue(f, v, sizeof(v));
        if (v[0] != '(')
            used++;
    }
    if (sections[s].perpage > 0)                 /* an address list         */
        _snprintf(tv_secinfo, sizeof(tv_secinfo) - 1, "%d of %d in use", used,
                  sections[s].count);
    else if (ncidr > 0)                          /* settings + proxy list   */
        _snprintf(tv_secinfo, sizeof(tv_secinfo) - 1, "%d settings, %d prox%s",
                  sections[s].count - ncidr, used, used == 1 ? "y" : "ies");
    else
        _snprintf(tv_secinfo, sizeof(tv_secinfo) - 1, "%d settings", sections[s].count);
    tv_secinfo[sizeof(tv_secinfo) - 1] = '\0';
}

/* One-line summary for the top of the settings screen. */
static VOID
ed_setstatus(VOID)
{
    CHAR ssh[24], lim[24];

    if (!tnt_recv_hooked) {
        stzcpy(tv_status, "telnet recv hook NOT installed - see Audit Trail",
               sizeof(tv_status));
        return;
    }
    if (ssh_manage_enabled)
        _snprintf(ssh, sizeof(ssh) - 1, "%d prox%s", ssh_proxy_count,
                  ssh_proxy_count == 1 ? "y" : "ies");
    else
        stzcpy(ssh, "off", sizeof(ssh));
    ssh[sizeof(ssh) - 1] = '\0';
    if (conn_limit_enabled)
        _snprintf(lim, sizeof(lim) - 1, "%d per IP", conn_limit_max);
    else
        stzcpy(lim, "off", sizeof(lim));
    lim[sizeof(lim) - 1] = '\0';
    _snprintf(tv_status, sizeof(tv_status) - 1,
              "telnet %d prox%s; SSH %s; limit %s; GeoIP %s",
              trusted_proxy_count, trusted_proxy_count == 1 ? "y" : "ies",
              ssh, lim, geoip_enabled ? "on" : "off");
    tv_status[sizeof(tv_status) - 1] = '\0';
}

/* The list of sections, with the prompt. */
static VOID
ed_showtop(VOID)
{
    INT s;

    ed_setstatus();
    prfmsg(TOPHDR);
    for (s = 0; s < NSECTIONS; s++) {
        sprintf(tv_secnum, "%d", s + 1);
        stzcpy(tv_secname, sections[s].title, sizeof(tv_secname));
        sprintf(tv_seccnt, "%d", sections[s].count);
        ed_secinfo(s);
        prfmsg(TOPROW);
    }
    prfmsg(TOPFTR);
    sprintf(tv_seccnt, "%d", NSECTIONS);
    prfmsg(TOPPRMT);
    ed_menushown = TRUE;
}

/* The channel's current section (its current page), and the prompt. */
static VOID
ed_showsect(VOID)
{
    const CHAR *note;
    INT         s, pg, np, k, i, from, to, room;

    s = ed_sect[usrnum];
    if (s < 0 || s >= NSECTIONS)
        s = ed_sect[usrnum] = 0;
    np = ed_npages(s);
    pg = ed_spage[usrnum];
    if (pg < 0 || pg >= np)
        pg = ed_spage[usrnum] = 0;
    if (sections[s].perpage > 0) {
        from = pg * sections[s].perpage;
        to   = from + sections[s].perpage;
        if (to > sections[s].count)
            to = sections[s].count;
        sprintf(tv_page, "page %d of %d", pg + 1, np);
    } else {
        from = 0;
        to   = sections[s].count;
        tv_page[0] = '\0';
    }

    stzcpy(tv_secname, sections[s].title, sizeof(tv_secname));
    prfmsg(MAINHDR);
    for (k = from; k < to; k++) {
        i = sections[s].first + k;
        ed_load_row(i);
        stzcpy(tv_rowclr, ed_valcolor(tv_rowval), sizeof(tv_rowclr));
        tv_rownote[0] = '\0';
        if ((note = ed_rownote(&fields[i])) != NULL) {
            _snprintf(tv_rownote, sizeof(tv_rownote) - 1, "(%s)", note);
            tv_rownote[sizeof(tv_rownote) - 1] = '\0';
        }
        /* a long value is shortened here (shown in full when edited), so
         * value and note together stay clear of the host's wrap column */
        room = ROWVALW - (tv_rownote[0] != '\0' ? (INT)strlen(tv_rownote) + 1 : 0);
        if (room < 8)
            room = 8;
        if ((INT)strlen(tv_rowval) > room)
            strcpy(tv_rowval + room - 3, "...");
        prfmsg(SETROW);
    }
    prfmsg(np > 1 ? MAINFTRP : MAINFTR);
    sprintf(tv_seccnt, "%d", sections[s].count);
    stzcpy(tv_cmds, np > 1 ? "N, P, H or X" : "H or X", sizeof(tv_cmds));
    prfmsg(PROMPT);
    ed_menushown = TRUE;
}

/* List a setting's choices, numbered, and prompt for one. */
static VOID
ed_showchoices(const FIELD *f)
{
    INT i;

    prfmsg(CHOICES);
    for (i = 0; i < f->nch; i++) {
        sprintf(tv_chnum, "%d", i + 1);
        stzcpy(tv_chname, f->ch[i].key, sizeof(tv_chname));
        stzcpy(tv_chdesc, f->ch[i].desc, sizeof(tv_chdesc));
        prfmsg(CHROW);
    }
    sprintf(tv_chnum, "%d", f->nch);
    prfmsg(CHOICEP);
}

/* Apply a new value to a setting; FALSE (and nothing changed) if not valid. */
static GBOOL
ed_setfield(const FIELD *f, const CHAR *input)
{
    CHAR *s = (CHAR *)f->var;
    INT   i, n;

    switch (f->type) {
    case FT_YN:
    case FT_LIST:
    case FT_CACHE:
        for (i = 0; i < f->nch; i++)
            if (sameas((CHAR *)input, (CHAR *)f->ch[i].key))
                break;
        if (i == f->nch && f->type == FT_YN) {
            if (sameas((CHAR *)input, "Y"))      i = 0;
            else if (sameas((CHAR *)input, "N")) i = 1;
        }
        if (i == f->nch)
            return FALSE;
        if (f->type == FT_CACHE) {
            geoip_cache_on     = (GBOOL)(f->ch[i].value != GEOCM_OFF);
            geoip_cache_bytime = (GBOOL)(f->ch[i].value != GEOCM_IP);
        } else {
            ed_setint(f, f->ch[i].value);
        }
        return TRUE;
    case FT_NUM:
        n = atoi(input);
        if (input[0] == '\0' || strspn(input, "0123456789") != strlen(input) ||
            n < f->min || n > f->max)
            return FALSE;
        *(INT *)f->var = n;
        return TRUE;
    case FT_CIDR: {
        struct snt_cidr c;
        if (sameas((CHAR *)input, "-")) {
            setmem((CHAR *)f->var, f->size, 0);
            return TRUE;
        }
        /* A /0 range parses to the all-zero "not set" value; refuse it
         * rather than silently storing nothing. */
        if (!parse_cidr(input, &c) || c.mask == 0)
            return FALSE;
        *(struct snt_cidr *)f->var = c;
        return TRUE;
    }
    case FT_CIDR6: {
        struct snt_cidr6 c;
        if (sameas((CHAR *)input, "-")) {
            setmem((CHAR *)f->var, f->size, 0);
            return TRUE;
        }
        if (!parse_cidr6(input, &c))
            return FALSE;
        *(struct snt_cidr6 *)f->var = c;
        return TRUE;
    }
    default:                        /* FT_KEY, FT_STR, FT_SECRET            */
        if (sameas((CHAR *)input, "-")) {
            setmem(s, f->size, 0);
            return TRUE;
        }
        if ((INT)strlen(input) >= f->size || strpbrk(input, "\r\n") != NULL)
            return FALSE;
        if (f->type == FT_KEY && strchr(input, ' ') != NULL)
            return FALSE;
        setmem(s, f->size, 0);
        stzcpy(s, input, f->size);
        if (f->type == FT_KEY)
            strupr(s);
        return TRUE;
    }
}

/* Set, save and report a new value, then show the menu again. */
static VOID
ed_applyvalue(const FIELD *f, const CHAR *value)
{
    if (!ed_setfield(f, value)) {
        stzcpy(tv_hint, f->hint, sizeof(tv_hint));
        prfmsg(BADVAL);
        return;
    }
    cfg_after_change();
    if (f->type == FT_CIDR6)
        cfg6_save();
    else
        cfg_save();
    shocst("Total IP Control", "%s changed %s: %s", usaptr->userid,
           sections[ed_sectof(ed_fld[usrnum])].title, f->name);
    /* SSH header processing needs ssh.dll's recv() hooked, which only
     * happens at startup: say so when it has just been switched on. */
    if ((f->var == &ssh_manage_enabled || f->var == &ssh_hdr_enabled) &&
        ssh_manage_enabled && ssh_hdr_enabled && !ssh_recv_hooked)
        shocst("Total IP Control",
               "SSH PROXY header processing is ON but ssh.dll is not hooked -- "
               "restart the BBS (SNSSH must load before SNTIPCTL)");
    stzcpy(tv_rowname, f->name, sizeof(tv_rowname));
    prfmsg(SAVED);
    ed_sect[usrnum] = ed_sectof(ed_fld[usrnum]);
    if (sections[ed_sect[usrnum]].perpage > 0)
        ed_spage[usrnum] = (ed_fld[usrnum] - sections[ed_sect[usrnum]].first)
                           / sections[ed_sect[usrnum]].perpage;
    ed_showsect();
}

/*
 * Open the settings editor on the list of sections: from /TIP, or from a menu
 * item whose command line is MENU=SYSOPMENU.  The caller has already checked
 * access and selected our message block.
 */
static VOID
ed_open(VOID)
{
    usrptr->state  = cfgstt;
    usrptr->substt = ST_TOP;
    ed_sect[usrnum] = 0;
    btuxnf(usrnum, 0, 19);          /* no "More?" pauses in the editor     */
    ed_showtop();
    outprf(usrnum);
}

/* MASTER access, as for /TIP. */
static GBOOL
ed_allowed(VOID)
{
    return (GBOOL)((usrptr->flags & MASTER) != 0);
}

/*
 * Editor input (sttrou with substt != 0).  ed_open() has already shown the
 * list of sections and set ST_TOP; this handles every line typed after that.
 */
static GBOOL
ed_entry(VOID)
{
    CHAR line[INPSIZ];
    INT  n, s;

    if (modmb == NULL) {
        rstrxf();
        return 0;
    }

    /*
     * Swallow the spurious "/" and empty calls MBBS delivers right after a
     * global command returns 1.  Only those are absorbed; a real keystroke
     * ends the absorbing and is handled normally.
     */
    if (absorb_count[usrnum] > 0) {
        if (!margc || margv[0] == NULL || *margv[0] == '\0' || *margv[0] == '/') {
            absorb_count[usrnum]--;
            return 1;
        }
        absorb_count[usrnum] = 0;
    }

    btuxnf(usrnum, 0, 19);          /* no "More?" pauses on these screens  */
    setmbk(modmb);

    /*
     * The whole line as typed (rstrin() puts back the spaces the BBS took out
     * when it split the line into words), trimmed at both ends, so values such
     * as the location format can contain spaces.
     */
    rstrin();
    stzcpy(line, skpwht(input), sizeof(line));
    unpad(line);

    ed_menushown = FALSE;
    s = ed_sect[usrnum];
    if (s < 0 || s >= NSECTIONS)
        s = ed_sect[usrnum] = 0;

    switch (usrptr->substt) {
    case ST_TOP:                    /* the list of sections                */
        if (sameas(line, "?")) {
            ed_showtop();
        } else if (sameas(line, "X") || sameas(line, "Q")) {
            prfmsg(LEAVE);
            outprf(usrnum);
            rstmbk();
            rstrxf();               /* the user's own paging again          */
            condex();
            return 0;
        } else if (sameas(line, "H")) {
            prfmsg(HELPMENU);
        } else if (line[0] != '\0' && strspn(line, "0123456789") == strlen(line)
                && (n = atoi(line)) >= 1 && n <= NSECTIONS) {
            ed_sect[usrnum]  = n - 1;
            ed_spage[usrnum] = 0;
            usrptr->substt = ST_SECT;
            ed_showsect();
        } else if (line[0] != '\0') {
            prfmsg(BADSEL);
        }
        break;

    case ST_SECT:                   /* one section's settings              */
        if (sameas(line, "?")) {
            ed_showsect();
        } else if (sameas(line, "X") || sameas(line, "Q")) {
            usrptr->substt = ST_TOP;
            ed_showtop();
        } else if (sameas(line, "N") || sameas(line, "P")) {
            n = ed_npages(s);       /* pages wrap around; one page: redraw */
            ed_spage[usrnum] = (ed_spage[usrnum] + (sameas(line, "N") ? 1 : n - 1)) % n;
            ed_showsect();
        } else if (sameas(line, "H")) {
            prfmsg(HELPMENU);
        } else if ((line[0] == 'H' || line[0] == 'h')
                && (n = atoi(skpwht(line + 1))) >= 1 && n <= sections[s].count) {
            ed_load_row(sections[s].first + n - 1);   /* "H 2": help on one */
            prfmsg(fields[sections[s].first + n - 1].help);
        } else if (line[0] != '\0' && strspn(line, "0123456789") == strlen(line)
                && (n = atoi(line)) >= 1 && n <= sections[s].count) {
            const FIELD *f = &fields[sections[s].first + n - 1];

            ed_fld[usrnum] = sections[s].first + n - 1;
            ed_load_row(ed_fld[usrnum]);
            if (f->nch > 0) {
                usrptr->substt = ST_CHOICE;
                ed_showchoices(f);
            } else {
                usrptr->substt = ST_VALUE;
                prfmsg(ASKVAL);
            }
        } else if (line[0] != '\0') {
            prfmsg(BADSEL);
        }
        break;

    case ST_VALUE: {
        const FIELD *f = &fields[ed_fld[usrnum]];

        if (sameas(line, "?")) {
            prfmsg(f->help);
            prfmsg(ASKVAL);
            break;
        }
        usrptr->substt = ST_SECT;
        if (line[0] == '\0')
            ed_showsect();          /* blank: keep the current value       */
        else
            ed_applyvalue(f, line);
        break;
    }

    case ST_CHOICE: {               /* a list setting: number or name      */
        const FIELD *f = &fields[ed_fld[usrnum]];

        if (sameas(line, "?")) {
            prfmsg(f->help);
            ed_showchoices(f);
            break;
        }
        usrptr->substt = ST_SECT;
        if (line[0] == '\0')
            ed_showsect();          /* blank: keep the current value       */
        else if (strspn(line, "0123456789") == strlen(line) &&
                 (n = atoi(line)) >= 1 && n <= f->nch)
            ed_applyvalue(f, f->ch[n - 1].key);
        else
            ed_applyvalue(f, line); /* the choice typed by name            */
        break;
    }

    default:                        /* unknown state: back to the sections */
        usrptr->substt = ST_TOP;
        ed_showtop();
        break;
    }

    /* back at a list: finish with its prompt unless the screen had it */
    if (!ed_menushown) {
        if (usrptr->substt == ST_TOP) {
            sprintf(tv_seccnt, "%d", NSECTIONS);
            prfmsg(TOPPRMT);
        } else if (usrptr->substt == ST_SECT) {
            sprintf(tv_seccnt, "%d", sections[ed_sect[usrnum]].count);
            stzcpy(tv_cmds, ed_npages(ed_sect[usrnum]) > 1 ? "N, P, H or X" : "H or X",
                   sizeof(tv_cmds));
            prfmsg(PROMPT);
        }
    }
    outprf(usrnum);
    rstmbk();
    return 1;
}

/*
 * cfg_live_to_struct
 *
 * Copies the current in-memory configuration variables into sntcfg so the
 * record is ready to be written to SNTIPCTL.DAT.
 */
static VOID
cfg_live_to_struct(VOID)
{
    INT i;

    setmem(&sntcfg, sizeof(sntcfg), 0);
    stzcpy(sntcfg.recid, "SNTIPCTL", sizeof(sntcfg.recid));
    sntcfg.version     = 13;
    sntcfg.proxy_trust = proxy_trust_enabled ? 'Y' : 'N';
    sntcfg.proxy_block = proxy_block_enabled ? 'Y' : 'N';
    for (i = 0; i < SNT_REC_TRUSTED; i++)
        sntcfg.proxy_cidrs[i] = trusted_proxy_cidrs[i];
    sntcfg.conn_limit  = conn_limit_enabled ? 'Y' : 'N';
    sntcfg.conn_max    = conn_limit_max;
    sntcfg.log_mode    = (CHAR)log_mode;
    sntcfg.usrip_on    = usrip_enabled  ? 'Y' : 'N';
    sntcfg.usrip_fld   = usrip_field;
    stzcpy(sntcfg.bypass_key, bypass_key, sizeof(sntcfg.bypass_key));
    stzcpy(sntcfg.staff_key,  staff_key,  sizeof(sntcfg.staff_key));
    sntcfg.debug_on = debug_enabled ? 'Y' : 'N';   /* struct version 13 */
    for (i = 0; i < SNT_REC_WHITELIST; i++)
        sntcfg.whitelist[i] = whitelist_cidrs[i];

    /* GeoIP Location block (struct version 8). */
    sntcfg.geoip_on       = geoip_enabled   ? 'Y' : 'N';
    sntcfg.geoip_fld      = geoip_field;
    sntcfg.geoip_provider = (CHAR)geoip_provider;
    sntcfg.geoip_https    = geoip_use_https ? 'Y' : 'N';
    sntcfg.geoip_timeout  = geoip_timeout;
    sntcfg.geoip_cache_on = geoip_cache_on  ? 'Y' : 'N';
    sntcfg.geoip_cache_min = geoip_cache_min;
    sntcfg.geoip_retry    = geoip_retries;
    sntcfg.geoip_loglvl   = (CHAR)geoip_loglevel;
    stzcpy(sntcfg.geoip_host,   geoip_host,   sizeof(sntcfg.geoip_host));
    stzcpy(sntcfg.geoip_key,    geoip_key,    sizeof(sntcfg.geoip_key));
    stzcpy(sntcfg.geoip_format, geoip_format, sizeof(sntcfg.geoip_format));
    sntcfg.geoip_split   = geoip_split ? 'Y' : 'N';
    sntcfg.geoip_cty_fld = geoip_cty_field;
    sntcfg.geoip_cty_fmt = (CHAR)geoip_cty_fmt;
    sntcfg.geoip_reg_fmt = (CHAR)geoip_reg_fmt;
    sntcfg.geoip_cache_bytime = geoip_cache_bytime ? 'Y' : 'N';

    /* SSH policy block (struct version 11). */
    sntcfg.ssh_manage = ssh_manage_enabled ? 'Y' : 'N';
    sntcfg.ssh_hdr    = ssh_hdr_enabled    ? 'Y' : 'N';
    sntcfg.ssh_trust  = ssh_trust_enabled  ? 'Y' : 'N';
    sntcfg.ssh_block  = ssh_block_enabled  ? 'Y' : 'N';
    for (i = 0; i < SNT_REC_TRUSTED; i++)
        sntcfg.ssh_cidrs[i] = ssh_proxy_cidrs[i];
}

/*
 * cfg_struct_to_live
 *
 * Applies the values in sntcfg (just read from SNTIPCTL.DAT) to the
 * in-memory configuration variables.  Validates ranges before applying.
 */
static VOID
cfg_struct_to_live(VOID)
{
    INT i;

    proxy_trust_enabled = (sntcfg.proxy_trust == 'Y') ? TRUE : FALSE;
    proxy_block_enabled = (sntcfg.proxy_block == 'Y') ? TRUE : FALSE;
    for (i = 0; i < SNT_REC_TRUSTED; i++)
        trusted_proxy_cidrs[i] = sntcfg.proxy_cidrs[i];
    conn_limit_enabled = (sntcfg.conn_limit == 'Y') ? TRUE : FALSE;
    if (sntcfg.conn_max >= 1 && sntcfg.conn_max <= 1000)
        conn_limit_max = sntcfg.conn_max;
    /*
     * Audit-logging mode.  v10 stores a LOGM_* code (0..3).  A v9-or-earlier
     * record stored 'Y'/'N' in this byte; those ASCII values (0x59/0x4E) fall
     * outside 0..3, so we detect and migrate them: legacy 'Y' (files + trail)
     * maps to LOGM_BOTH to preserve prior behavior, legacy 'N' to LOGM_OFF.
     */
    if (sntcfg.log_mode >= LOGM_OFF && sntcfg.log_mode <= LOGM_BOTH)
        log_mode = sntcfg.log_mode;
    else if (sntcfg.log_mode == 'Y')
        log_mode = LOGM_BOTH;
    else
        log_mode = LOGM_OFF;
    log_apply_mode();
    usrip_enabled = (sntcfg.usrip_on == 'Y') ? TRUE : FALSE;
    if (sntcfg.usrip_fld >= 1 && sntcfg.usrip_fld <= 5)
        usrip_field = sntcfg.usrip_fld;
    stzcpy(bypass_key, sntcfg.bypass_key, sizeof(bypass_key));
    stzcpy(staff_key,  sntcfg.staff_key,  sizeof(staff_key));  /* empty on pre-v12; cfg_load defaults */
    /* Debug trace flag (struct version 13).  A pre-v13 record has a zero byte
     * here, which is not 'Y', so debug logging reads OFF -- the safe default. */
    debug_enabled = (sntcfg.debug_on == 'Y') ? TRUE : FALSE;
    for (i = 0; i < SNT_REC_WHITELIST; i++)
        whitelist_cidrs[i] = sntcfg.whitelist[i];

    trusted_proxy_count = 0;
    for (i = 0; i < SNTIPCTL_MAX_TRUSTED; i++)
        if (trusted_proxy_cidrs[i].addr != 0 || trusted_proxy_cidrs[i].mask != 0)
            trusted_proxy_count++;

    /* GeoIP Location block (struct version 8), with range/default guards. */
    geoip_enabled   = (sntcfg.geoip_on == 'Y') ? TRUE : FALSE;
    if (sntcfg.geoip_fld >= 1 && sntcfg.geoip_fld <= 5)
        geoip_field = sntcfg.geoip_fld;
    if (sntcfg.geoip_provider >= 0 && sntcfg.geoip_provider <= GEOPRV_IPINFO)
        geoip_provider = sntcfg.geoip_provider;
    geoip_use_https = (sntcfg.geoip_https == 'Y') ? TRUE : FALSE;
    if (sntcfg.geoip_timeout >= 1 && sntcfg.geoip_timeout <= 60)
        geoip_timeout = sntcfg.geoip_timeout;
    geoip_cache_on  = (sntcfg.geoip_cache_on == 'Y') ? TRUE : FALSE;
    if (sntcfg.geoip_cache_min >= 1 && sntcfg.geoip_cache_min <= 44640)
        geoip_cache_min = sntcfg.geoip_cache_min;
    if (sntcfg.geoip_retry >= 0 && sntcfg.geoip_retry <= 5)
        geoip_retries = sntcfg.geoip_retry;
    if (sntcfg.geoip_loglvl >= GEOLOG_OFF && sntcfg.geoip_loglvl <= GEOLOG_VERBOSE)
        geoip_loglevel = sntcfg.geoip_loglvl;
    stzcpy(geoip_host,   sntcfg.geoip_host,   sizeof(geoip_host));
    stzcpy(geoip_key,    sntcfg.geoip_key,    sizeof(geoip_key));
    stzcpy(geoip_format, sntcfg.geoip_format, sizeof(geoip_format));
    /* Normalize a blank or built-in-default host to empty so the effective host
     * tracks the selected provider (also heals legacy records that stored a
     * forced "ipwho.is" default under a non-default provider). */
    if (geoip_is_builtin_host(geoip_host)) geoip_host[0] = '\0';
    if (geoip_format[0] == '\0') stzcpy(geoip_format, "{city}, {region}, {country}", sizeof(geoip_format));

    geoip_split = (sntcfg.geoip_split == 'Y') ? TRUE : FALSE;
    if (sntcfg.geoip_cty_fld >= 1 && sntcfg.geoip_cty_fld <= 5)
        geoip_cty_field = sntcfg.geoip_cty_fld;
    if (sntcfg.geoip_cty_fmt == GEOCF_FULL || sntcfg.geoip_cty_fmt == GEOCF_CODE)
        geoip_cty_fmt = sntcfg.geoip_cty_fmt;
    /* State/region format: a zeroed byte from a record written before this field
     * existed maps to GEORF_CODE (0), preserving the historical 2-letter output. */
    if (sntcfg.geoip_reg_fmt == GEORF_CODE || sntcfg.geoip_reg_fmt == GEORF_FULL)
        geoip_reg_fmt = sntcfg.geoip_reg_fmt;
    /* Cache mode: only 'N' means per-IP; anything else (incl. a zeroed byte
     * from a pre-v9 record) means the historical time-based expiry. */
    geoip_cache_bytime = (sntcfg.geoip_cache_bytime == 'N') ? FALSE : TRUE;

    /*
     * SSH policy block (struct version 11).  A pre-v11 record has zero bytes
     * here, which are not 'Y', so every flag comes back FALSE and the CIDR list
     * is empty -- SSH is left unmanaged, exactly as it was before v1.1.3.  No
     * migration step is needed.
     */
    ssh_manage_enabled = (sntcfg.ssh_manage == 'Y') ? TRUE : FALSE;
    ssh_hdr_enabled    = (sntcfg.ssh_hdr    == 'Y') ? TRUE : FALSE;
    ssh_trust_enabled  = (sntcfg.ssh_trust  == 'Y') ? TRUE : FALSE;
    ssh_block_enabled  = (sntcfg.ssh_block  == 'Y') ? TRUE : FALSE;
    for (i = 0; i < SNT_REC_TRUSTED; i++)
        ssh_proxy_cidrs[i] = sntcfg.ssh_cidrs[i];

    ssh_proxy_count = 0;
    for (i = 0; i < SNTIPCTL_MAX_TRUSTED; i++)
        if (ssh_proxy_cidrs[i].addr != 0 || ssh_proxy_cidrs[i].mask != 0)
            ssh_proxy_count++;
}

/*
 * cfg_after_change
 *
 * Brings every value derived from the settings back in step after the editor
 * changes one: the proxy and whitelist counts, the two logging sinks, and the
 * GeoIP rules that depend on more than one setting.
 */
static VOID
cfg_after_change(VOID)
{
    INT i;

    trusted_proxy_count = ssh_proxy_count = whitelist6_count = 0;
    for (i = 0; i < SNTIPCTL_MAX_TRUSTED; i++) {
        if (trusted_proxy_cidrs[i].addr != 0 || trusted_proxy_cidrs[i].mask != 0)
            trusted_proxy_count++;
        if (ssh_proxy_cidrs[i].addr != 0 || ssh_proxy_cidrs[i].mask != 0)
            ssh_proxy_count++;
    }
    for (i = 0; i < SNTIPCTL_MAX_WHITELIST6; i++)
        if (whitelist6_cidrs[i].prefix != 0)
            whitelist6_count++;

    log_apply_mode();

    /* A provider's own host is stored as blank, so the host follows the
     * provider when it changes. */
    if (geoip_is_builtin_host(geoip_host))
        geoip_host[0] = '\0';
    /* ip-api.com's free service is HTTP only; a key unlocks HTTPS. */
    if (geoip_provider == GEOPRV_IPAPI && geoip_key[0] == '\0')
        geoip_use_https = FALSE;
    if (geoip_format[0] == '\0')
        stzcpy(geoip_format, "{city}, {region}, {country}", sizeof(geoip_format));
}

/*
 * cfg_save
 *
 * Persists current in-memory configuration to SNTIPCTL.DAT.
 * Uses a separate key-only record to position the Btrieve cursor so that
 * sntcfg (already filled by cfg_live_to_struct) is not overwritten by the
 * acquire step.
 */
static VOID
cfg_save(VOID)
{
    struct sntipctlcfg key;

    if (sntbt == NULL) {
        shocst("Total IP Control", "WARNING: cfg_save -- SNTIPCTL.DAT is not open");
        return;
    }

    cfg_live_to_struct();

    /*
     * Use a separate key buffer so dfaAcqEQ does not overwrite sntcfg.
     * We only need the recid field filled for the lookup.
     */
    setmem(&key, sizeof(key), 0);
    stzcpy(key.recid, "SNTIPCTL", sizeof(key.recid));

    dfaSetBlk(sntbt);
    if (!(dfaAcqEQ(&key, &key, 0) ? dfaUpdateDup(&sntcfg) : dfaInsertDup(&sntcfg)))
        shocst("Total IP Control", "WARNING: settings could not be saved to SNTIPCTL.DAT");
    dfaRstBlk();

    cfg_lists_save();
}

/*
 * cfg_load
 *
 * Reads the SNTIPCTL.DAT record and applies it to the in-memory variables.
 * On first run (record not found) inserts a record with the current defaults
 * so the record always exists for subsequent cfg_save() calls.
 */
static VOID
cfg_load(VOID)
{
    if (sntbt == NULL) return;

    setmem(&sntcfg, sizeof(sntcfg), 0);
    stzcpy(sntcfg.recid, "SNTIPCTL", sizeof(sntcfg.recid));

    dfaSetBlk(sntbt);
    if (dfaAcqEQ(&sntcfg, &sntcfg, 0)) {
        if (sntcfg.version >= 9 && sntcfg.version <= 13) {
            /*
             * v9..v13 share an identical byte layout for every field the older
             * versions had.  v10 only reinterprets the audit-logging byte (LOGM_*
             * vs legacy 'Y'/'N'), v11 carves the SSH block out of the spare area,
             * v12 carves the staff view key out of the spare area, and v13 carves
             * a debug-trace flag out of it -- so on an older record those newer
             * bytes read as zero, which cfg_struct_to_live() maps to "SSH
             * unmanaged" / empty key / debug OFF (the prior behavior).  Those
             * legacy mappings happen there; here we only top up the v12 staff-key
             * default and rewrite the record at the current version.
             */
            cfg_struct_to_live();
            if (sntcfg.version < 13) {
                /* Older record: top up any newer-block defaults, then rewrite it
                 * at the current version.  Staff view key (v12) reads empty on a
                 * pre-v12 record -> default to SYSOP so /WHOSON works out of the
                 * box.  Debug flag (v13) reads OFF on a pre-v13 record, which is
                 * the intended default, so it needs no top-up. */
                if (sntcfg.version < 12)
                    stzcpy(staff_key, "SYSOP", sizeof(staff_key));
                dfaDelete();
                cfg_live_to_struct();
                dfaInsertV(&sntcfg, (USHORT)sizeof(sntcfg));
                shocst("Total IP Control", "settings migrated to v2.0.0 -- existing settings preserved");
            } else {
                shocst("Total IP Control", "settings loaded from SNTIPCTL.DAT");
            }
        } else if (sntcfg.version == 7 || sntcfg.version == 8) {
            /*
             * Forward-migrate a version 7 or 8 record.  Each newer block was
             * appended after the previous layout (carved from the old spare
             * area), so an older record is a byte-compatible prefix of the
             * current one -- every existing field sits at the same offset.  We
             * therefore PRESERVE all existing settings via cfg_struct_to_live()
             * (bytes that did not exist in the old version read as zero and are
             * ignored by the range guards), then apply defaults for the blocks
             * that record did not have, and rewrite it as version 11.
             */
            cfg_struct_to_live();

            if (sntcfg.version == 7) {
                /* v7 predates the whole GeoIP block -- default it. */
                geoip_enabled   = FALSE;
                geoip_field     = 3;
                geoip_provider  = GEOPRV_IPWHOIS;
                geoip_use_https = TRUE;
                geoip_timeout   = 5;
                geoip_cache_on  = TRUE;
                geoip_cache_min = 1440;
                geoip_retries   = 1;
                geoip_loglevel  = GEOLOG_NORMAL;
                geoip_host[0] = '\0';   /* blank = use provider default host */
                geoip_key[0] = '\0';
                stzcpy(geoip_format, "{city}, {region}, {country}", sizeof(geoip_format));
            }

            /*
             * The split write-mode block is new in v9.  Choose the default that
             * PRESERVES each record's existing behavior:
             *   - v7 predates GeoIP (disabled, never wrote a field), so the new
             *     SPLIT default is fine -- it only takes effect once the Sysop
             *     enables and configures GeoIP.
             *   - v8 already wrote the whole location into a SINGLE field.
             *     Defaulting it to SPLIT would begin writing the country into a
             *     second field (Address 4) and alter the first field on the next
             *     login, so keep it COMBINED to preserve the prior behavior.
             */
            geoip_split        = (sntcfg.version == 7) ? TRUE : FALSE;
            geoip_cty_field    = 4;
            geoip_cty_fmt      = GEOCF_FULL;
            geoip_reg_fmt      = GEORF_CODE;
            geoip_cache_bytime = TRUE;      /* new in v9 -- historical time mode */

            /*
             * The SSH block is new in v11.  These bytes lay in the old spare area,
             * so they should already read as zero; default them explicitly rather
             * than trust that, since anything non-zero there would silently switch
             * on an SSH policy the Sysop never configured.  Off preserves the
             * pre-v1.1.3 behavior of leaving SSH alone.
             */
            ssh_manage_enabled = FALSE;
            ssh_hdr_enabled    = FALSE;
            ssh_trust_enabled  = FALSE;
            ssh_block_enabled  = FALSE;
            setmem((CHAR *)ssh_proxy_cidrs, sizeof(ssh_proxy_cidrs), 0);
            ssh_proxy_count    = 0;

            /* Staff view key is new in v12 -- default it so /WHOSON works. */
            stzcpy(staff_key, "SYSOP", sizeof(staff_key));

            dfaDelete();
            cfg_live_to_struct();
            dfaInsertV(&sntcfg, (USHORT)sizeof(sntcfg));
            shocst("Total IP Control", "settings migrated to v2.0.0 -- existing settings preserved");
        } else {
            /*
             * Record exists but was written by an incompatible older build.
             * Delete it and insert fresh defaults.
             */
            dfaDelete();
            cfg_live_to_struct();
            dfaInsertV(&sntcfg, (USHORT)sizeof(sntcfg));
            shocst("Total IP Control", "settings format updated; defaults applied to new fields");
        }
    } else {
        /* First run: write the default values that were set before cfg_load(). */
        cfg_live_to_struct();
        dfaInsertV(&sntcfg, (USHORT)sizeof(sntcfg));
        shocst("Total IP Control", "first run: default settings written to SNTIPCTL.DAT");
    }
    dfaRstBlk();
}

/*
 * rec_read / rec_write
 *
 * Read or write one 512-byte record of SNTIPCTL.DAT by its recid (the first
 * 16 bytes of every record).  The lookup key is copied into a local buffer:
 * a DFA key must be in writable memory.  rec_write updates the record if it
 * exists and inserts it otherwise, and reports failure instead of abending.
 */
static GBOOL
rec_read(VOID *rec, const CHAR *recid)
{
    CHAR  buf[512];
    GBOOL ok;

    if (sntbt == NULL) return FALSE;
    setmem(buf, sizeof(buf), 0);
    stzcpy(buf, recid, 16);
    dfaSetBlk(sntbt);
    ok = dfaAcqEQ(buf, buf, 0);
    dfaRstBlk();
    if (ok)
        memcpy(rec, buf, sizeof(buf));
    return ok;
}

static GBOOL
rec_write(VOID *rec)
{
    CHAR  key[512];
    GBOOL ok;

    if (sntbt == NULL) return FALSE;
    setmem(key, sizeof(key), 0);
    memcpy(key, rec, 16);
    dfaSetBlk(sntbt);
    ok = dfaAcqEQ(key, key, 0) ? dfaUpdateDup(rec) : dfaInsertDup(rec);
    dfaRstBlk();
    if (!ok)
        shocst("Total IP Control", "WARNING: could not save %s to SNTIPCTL.DAT", (CHAR *)rec);
    return ok;
}

/*
 * cfg_lists_load
 *
 * Read the full trusted-proxy and IPv4 whitelist lists.  Runs after
 * cfg_load(), which has already filled the first entries from the main
 * record; if a list record is missing (a .DAT from an earlier build) those
 * stay, and the record is written the first time a setting is saved.
 */
static VOID
cfg_lists_load(VOID)
{
    struct snt_proxyrec pr;
    struct snt_wl4rec   wr;
    INT                 i;

    if (rec_read(&pr, "SNTPROXY") && pr.version == 1) {
        for (i = 0; i < SNTIPCTL_MAX_TRUSTED; i++) {
            trusted_proxy_cidrs[i] = pr.telnet[i];
            ssh_proxy_cidrs[i]     = pr.ssh[i];
        }
    }
    if (rec_read(&wr, "SNTWL4") && wr.version == 1) {
        for (i = 0; i < SNTIPCTL_MAX_WHITELIST; i++)
            whitelist_cidrs[i] = wr.wl[i];
    }
    cfg_after_change();             /* the counts */
}

/* Write the full trusted-proxy and IPv4 whitelist lists (from cfg_save). */
static VOID
cfg_lists_save(VOID)
{
    struct snt_proxyrec pr;
    struct snt_wl4rec   wr;
    INT                 i;

    setmem((CHAR *)&pr, sizeof(pr), 0);
    stzcpy(pr.recid, "SNTPROXY", sizeof(pr.recid));
    pr.version = 1;
    for (i = 0; i < SNTIPCTL_MAX_TRUSTED; i++) {
        pr.telnet[i] = trusted_proxy_cidrs[i];
        pr.ssh[i]    = ssh_proxy_cidrs[i];
    }
    rec_write(&pr);

    setmem((CHAR *)&wr, sizeof(wr), 0);
    stzcpy(wr.recid, "SNTWL4", sizeof(wr.recid));
    wr.version = 1;
    for (i = 0; i < SNTIPCTL_MAX_WHITELIST; i++)
        wr.wl[i] = whitelist_cidrs[i];
    rec_write(&wr);
}

/* recid of IPv6 whitelist record part 0 (entries 1-25) or 1 (26-50) */
static const CHAR *
cfg6_recid(INT part)
{
    return part == 0 ? "SNTIPV6WL" : "SNTIPV6W2";
}

/*
 * cfg6_load
 *
 * Reads the IPv6 whitelist from its two records.  A missing record (a .DAT
 * from before the IPv6 whitelist, or before it grew to 50) or an unknown
 * version leaves its entries empty -- the safe default.  Nothing is inserted
 * on load; the records are written on the first cfg6_save().
 */
static VOID
cfg6_load(VOID)
{
    struct sntip6cfg r;
    INT              part, i;

    setmem((CHAR *)whitelist6_cidrs, sizeof(whitelist6_cidrs), 0);
    for (part = 0; part < 2; part++) {
        if (!rec_read(&r, cfg6_recid(part)) || r.version < 1 || r.version > 2)
            continue;
        for (i = 0; i < SNT_V6_PER_REC; i++)
            whitelist6_cidrs[part * SNT_V6_PER_REC + i] = r.whitelist6[i];
    }
    cfg_after_change();             /* the count */
    if (whitelist6_count > 0)
        shocst("Total IP Control",
               spr("IPv6 whitelist loaded (%d CIDR(s))", whitelist6_count));
}

/* Persists the IPv6 whitelist to its two records. */
static VOID
cfg6_save(VOID)
{
    struct sntip6cfg r;
    INT              part, i;

    for (part = 0; part < 2; part++) {
        setmem((CHAR *)&r, sizeof(r), 0);
        stzcpy(r.recid, cfg6_recid(part), sizeof(r.recid));
        r.version = 2;
        for (i = 0; i < SNT_V6_PER_REC; i++)
            r.whitelist6[i] = whitelist6_cidrs[part * SNT_V6_PER_REC + i];
        rec_write(&r);
    }
}

/* ======================================================================== */
/*   Named text variables                                                    */
/*                                                                           */
/*   Published to the host so every SNTIPCTL.MSG message can show dynamic    */
/*   values the sysop can reword and reorder freely in the CNF LEVEL6 block   */
/*   (a text variable appears in message text as the byte sequence            */
/*   0x01 <justify> <width+32> NAME 0x01).  The per-caller values (IP, user,  */
/*   module, time on line, connection type) are LIVE: they are computed from  */
/*   snt_tv_chan -- the channel the current message row is about -- so one    */
/*   variable serves both "my own" and "another user's" rows.  /WHOSON sets   */
/*   snt_tv_chan per row before each prfmsg(); /MYIP and the default leave it */
/*   at -1, which resolves to the calling channel.  The rest return a buffer  */
/*   filled just before the message that uses it.                             */
/*                                                                           */
/*   Names are SNT-prefixed because text variables are global to the whole    */
/*   BBS; keep each within the 15-char TVRSIZ limit.                          */
/* ======================================================================== */

INT snt_tv_chan = -1;      /* target channel for the vars; -1 = usrnum */

INT
snt_tv_target(VOID)
{
    if (snt_tv_chan >= 0 && snt_tv_chan < nterms) return snt_tv_chan;
    return usrnum;
}

static CHAR *
snt_tv_ip(VOID)                   /* the channel's (real, post-proxy) IP       */
{
    static CHAR buf[46];          /* INET6_ADDRSTRLEN                          */
    INT            c = snt_tv_target();
    struct in_addr a;

    buf[0] = '\0';
    /*
     * Prefer our text store: it holds the true caller address for both v4 and
     * v6.  For a v6 client the engine's inaddr cannot represent it at all; for
     * a v4 proxied client the text copy equals inaddr.  Fall back to inaddr for
     * direct (non-proxy) clients, whose real IP the engine records natively.
     */
    if (c >= 0 && c < MAXNTERM && snt_real_ip[c][0] != '\0') {
        stzcpy(buf, snt_real_ip[c], sizeof(buf));
    } else if (pp_tcpipinf != NULL && c >= 0 && c < nterms) {
        a.s_addr = (*pp_tcpipinf)[c].inaddr.s_addr;
        stzcpy(buf, inet_ntoa(a), sizeof(buf));
    }
    return buf;
}

/*
 * snt_tv_ip_short -- the channel's IP, abbreviated for the /WHOSON list.
 *
 * IPv4 is already short (max 15 chars) and is returned as-is.  IPv6 can run to
 * 39 chars, which is what was blowing the /whoson row past 80 columns and
 * wrapping TOL onto the next line.  Abbreviate to "<first hextet>..<last
 * hextet>" (e.g. "2607..d22a") -- short, and still enough to recognize/compare
 * at a glance -- rather than a blind char-count truncation, which would just
 * chop the tail off and always show the same leading hextets for a whole
 * prefix of addresses.
 */
static CHAR *
snt_tv_ip_short(VOID)
{
    static CHAR buf[24];
    CHAR       *full = snt_tv_ip();
    CHAR       *first_colon, *last_colon;
    INT         firstlen;

    first_colon = strchr(full, ':');
    if (first_colon == NULL) {                  /* IPv4 -- already short */
        stzcpy(buf, full, sizeof(buf));
        return buf;
    }

    last_colon = strrchr(full, ':');
    firstlen   = (INT)(first_colon - full);
    if (last_colon == first_colon || firstlen > 4) {
        stzcpy(buf, full, sizeof(buf));          /* unexpected shape -- show as-is */
        return buf;
    }

    sprintf(buf, "%.*s..%.4s", firstlen, full, last_colon + 1);
    return buf;
}

static CHAR *
snt_tv_userid(VOID)               /* the channel's user ID                     */
{
    static CHAR    buf[UIDSIZ];
    INT            c = snt_tv_target();
    struct usracc *uap;

    buf[0] = '\0';
    if (c >= 0 && c < nterms) {
        uap = uacoff(c);
        if (uap != NULL)
            stzcpy(buf, uap->userid, sizeof(buf));
    }
    return buf;
}

static CHAR *
snt_tv_module(VOID)               /* name of the module the channel is in      */
{
    static CHAR buf[MNMSIZ + 1];
    INT         c = snt_tv_target();
    INT         st;

    stzcpy(buf, "Main Menu", sizeof(buf));
    if (c >= 0 && c < nterms) {
        st = usroff(c)->state;
        if (st >= 0 && st < nmods && module[st] != NULL &&
            module[st]->descrp[0] != '\0')
            stzcpy(buf, module[st]->descrp, sizeof(buf));
    }
    return buf;
}

static CHAR *
snt_tv_tol(VOID)                  /* time on line, e.g. "1h 3m" / "14m"        */
{
    static CHAR buf[16];
    INT         c = snt_tv_target();
    ULONG       secs, h, m;

    if (c < 0 || c >= nterms) { stzcpy(buf, "0m", sizeof(buf)); return buf; }

    /* lngtck is a seconds counter; tckonl is its value when the user logged on. */
    secs = (lngtck >= usroff(c)->tckonl) ? (lngtck - usroff(c)->tckonl) : 0;
    h    = secs / 3600;
    m    = (secs % 3600) / 60;
    if (h > 0) sprintf(buf, "%luh %lum", h, m);
    else       sprintf(buf, "%lum", m);
    return buf;
}

/*
 * snt_tv_conntype -- "Telnet", "SSH", or "" for the /WHOSON N!SNTTIPCT column.
 *
 * Reads snt_conn_proto[], not pending_proto[] -- see that array's declaration
 * comment for why the two cannot be shared.  Returns "" rather than a false
 * "Telnet" for a channel that never went through our hdlcon as telnet or SSH
 * (a WorldLink network link, for instance).  The width of the column is the
 * calling message's business (its justify/width byte), not padded here.
 *
 * Named SNTTIPCT, not TIPCT: text variables are global to the whole BBS and
 * findtvar() returns the FIRST registration of a name, so a generic name can
 * be silently shadowed by another module's variable of the same name.
 *
 * Like every text variable it can only follow a row in a report that sets
 * snt_tv_chan, i.e. our own /WHOSON.  Another module's report that embeds it
 * gets the viewing user's own value on every row -- true of any module's
 * text variables, since they take no arguments.
 */
CHAR *
snt_tv_conntype(VOID)
{
    INT  c = snt_tv_target();
    CHAR proto = (c >= 0 && c < MAXNTERM) ? snt_conn_proto[c] : SNT_PROTO_UNKNOWN;

    if (proto == SNT_PROTO_SSH)    return "SSH";
    if (proto == SNT_PROTO_TELNET) return "Telnet";
    return "";
}

/*
 * snt_tv_version -- the RUNNING build's version string.
 *
 * Exists so message text never has to carry a hand-typed version number: a
 * version typed into SNTIPCTL.MSG goes stale with the first DLL-only build.
 * Fed from SNTVER.H, it cannot disagree with the DLL that is actually loaded.
 * Use N!SNTVER in the .MSG rather than typing a version.
 */
static CHAR *
snt_tv_version(VOID)
{
    static CHAR buf[24];

    stzcpy(buf, SNTIPCTL_VERSION, sizeof(buf));
    return buf;
}

/* Buffer-backed variables: each returns a value filled just before use. */
static CHAR *tv_get_users(VOID)   { return tv_users;   }
static CHAR *tv_get_maxip(VOID)   { return tv_maxip;   }
static CHAR *tv_get_status(VOID)  { return tv_status;  }
static CHAR *tv_get_secnum(VOID)  { return tv_secnum;  }
static CHAR *tv_get_secname(VOID) { return tv_secname; }
static CHAR *tv_get_seccnt(VOID)  { return tv_seccnt;  }
static CHAR *tv_get_secinfo(VOID) { return tv_secinfo; }
static CHAR *tv_get_page(VOID)    { return tv_page;    }
static CHAR *tv_get_cmds(VOID)    { return tv_cmds;    }
static CHAR *tv_get_rowclr(VOID)  { return tv_rowclr;  }
static CHAR *tv_get_rownote(VOID) { return tv_rownote; }
static CHAR *tv_get_rownum(VOID)  { return tv_rownum;  }
static CHAR *tv_get_rowname(VOID) { return tv_rowname; }
static CHAR *tv_get_rowval(VOID)  { return tv_rowval;  }
static CHAR *tv_get_hint(VOID)    { return tv_hint;    }
static CHAR *tv_get_chnum(VOID)   { return tv_chnum;   }
static CHAR *tv_get_chname(VOID)  { return tv_chname;  }
static CHAR *tv_get_chdesc(VOID)  { return tv_chdesc;  }

/*
 * snt_register_tvars -- register every N!SNTxxx text variable.
 *
 * Checks findtvar() for each name BEFORE registering it.  Text variables are
 * global to the whole BBS with no duplicate-name protection from the engine
 * (see snt_tv_conntype), so a name already taken by another loaded module
 * would otherwise fail silently --
 * this puts it in the Audit Trail at boot instead, where it can be measured
 * rather than guessed at.
 */
VOID
snt_register_tvars(VOID)
{
    static const struct {
        const CHAR *name;
        CHAR      *(*fn)(VOID);
    } vars[] = {
        { "SNTIP",      snt_tv_ip },
        { "SNTIPSHORT", snt_tv_ip_short },
        { "SNTUSERID",  snt_tv_userid },
        { "SNTMODULE",  snt_tv_module },
        { "SNTTOL",     snt_tv_tol },
        { "SNTVER",     snt_tv_version },
        { "SNTTIPCT",   snt_tv_conntype },
        { "SNTUSERS",   tv_get_users },     /* CLIMIT, IPGDNY            */
        { "SNTMAXIP",   tv_get_maxip },     /* IPGDNY                    */
        { "SNTSTATUS",  tv_get_status },    /* the settings editor ...   */
        { "SNTSECNUM",  tv_get_secnum },
        { "SNTSECNAME", tv_get_secname },
        { "SNTSECCNT",  tv_get_seccnt },
        { "SNTSECINFO", tv_get_secinfo },
        { "SNTPAGE",    tv_get_page },
        { "SNTCMDS",    tv_get_cmds },
        { "SNTROWCLR",  tv_get_rowclr },
        { "SNTROWNOTE", tv_get_rownote },
        { "SNTROWNUM",  tv_get_rownum },
        { "SNTROWNAME", tv_get_rowname },
        { "SNTROWVAL",  tv_get_rowval },
        { "SNTHINT",    tv_get_hint },
        { "SNTCHNUM",   tv_get_chnum },
        { "SNTCHNAME",  tv_get_chname },
        { "SNTCHDESC",  tv_get_chdesc },
    };
    INT i;

    for (i = 0; i < (INT)(sizeof(vars) / sizeof(vars[0])); i++) {
        if (findtvar((CHAR *)vars[i].name) != -1) {
            shocst("Total IP Control",
                   spr("WARNING: N!%s is already registered by another "
                       "module -- ours will not take effect", vars[i].name));
        }
        register_textvar(vars[i].name, vars[i].fn);
    }
}

/*
 * sntipctl_gbl
 *
 * Global command handler.  Registered via globalcmd() and called for every
 * user input on every channel.  Returns 1 if the command was consumed, 0 to
 * pass the input through to normal BBS processing.
 *
 * Triggers:  /MYIP     (any user -- shows their own real IP)
 *            /WHOSON   (staff -- who's online, gated by the staff view key)
 *            /TIP      (Master access required -- settings editor)
 */
static INT
sntipctl_gbl(VOID)
{
    if (!margc) return 0;

    /* ---- /MYIP: show the caller their own (real, post-proxy) IP ---- */
    if (sameas(margv[0], "/MYIP")) {
        if (modmb == NULL || pp_tcpipinf == NULL) return 0;
        setmbk(modmb);
        snt_tv_chan = -1;                                  /* the caller */
        prfmsg(MYIP);
        outprf(usrnum);
        rstmbk();
        return 1;
    }

    /* ---- /WHOSON: staff who's-online view (gated by the staff view key) ---- */
    if (sameas(margv[0], "/WHOSON")) {
        INT i;

        if (modmb == NULL) return 0;

        /* SYSOP/MASTER always have access; otherwise the configured staff key. */
        if (!(snt_haskey("SYSOP") || snt_haskey("MASTER") || snt_haskey(staff_key))) {
            setmbk(modmb);
            prfmsg(NOACCESS);
            outprf(usrnum);
            rstmbk();
            return 1;
        }

        setmbk(modmb);

        prfmsg(WHOHDR);
        outprf(usrnum);
        for (i = 0; i < hichp1; i++) {
            /*
             * ACTUSR alone (logged on and at/past the main menu) misses a
             * caller still going through a post-login sequence -- ads,
             * bulletins, and similar "supplemental logon" modules run under
             * usrcls SUPLON, and new-account signup runs under SUPIPG
             * (MAJORBBS.H) -- both AFTER a real userid is confirmed, just
             * before ACTUSR, so they are listed too.  (Their IP and
             * connection type are known from the raw connect, long before
             * login.)  ONLINE (before a userid exists) and BBSPRV (internal)
             * are excluded -- there is no real caller identity to show for
             * either.
             */
            switch (usroff(i)->usrcls) {
            case ACTUSR:
            case SUPLON:
            case SUPIPG:
                break;
            default:
                continue;
            }
            snt_tv_chan = i;                              /* this row is about channel i */
            prfmsg(WHOROW);
            outprf(usrnum);
        }
        snt_tv_chan = -1;
        rstmbk();
        return 1;
    }

    if (!sameas(margv[0], "/TIP")) return 0;

    if (modmb == NULL) {
        shocst("Total IP Control",
               "ERROR: /TIP unavailable -- SNTIPCTL.MSG missing; reinstall it and restart");
        return 1;
    }

    setmbk(modmb);
    if (!ed_allowed()) {
        prfmsg(NOACCESS);
        outprf(usrnum);
        rstmbk();
        return 1;
    }

    /*
     * Into the editor, drawn now so there is no visible delay.  MBBS then
     * calls sttrou once or twice with "/" or "" before real input, which
     * absorb_count has ed_entry() swallow.
     */
    ed_open();
    absorb_count[usrnum] = 2;
    rstmbk();
    return 1;
}

/* ======================================================================== */
/*   Per-module IP gateway                                                   */
/*                                                                           */
/*   When a BBS menu item points to SNTIPCTL, the module acts as a gateway  */
/*   to another module, limiting how many simultaneous sessions from the     */
/*   same IP address may be inside that target module at once.               */
/*                                                                           */
/*   Menu command string format:                                             */
/*     MODULE=<name>  MAXIP=<n>  [BYPASS=<key>[,<key>...]]                  */
/*                                                                           */
/*   The same menu entry point also opens other parts of the module with     */
/*   MENU=<name> (MENU=SYSOPMENU: the settings editor, as /TIP does).        */
/*   MENU takes precedence over MODULE; unknown MENU names are refused and   */
/*   noted in the Audit Trail, so the keyword can grow later.                */
/*                                                                           */
/*   Examples:                                                               */
/*     MODULE=LORD MAXIP=3                                                   */
/*     MODULE=TRADEWARS MAXIP=2 BYPASS=SYSOP,COSYSOP                        */
/* ======================================================================== */

#define GW_BYPASS_DEFAULT  "SYSOP"
#define GW_BYPASS_MAXSIZ   128

/*
 * parse_gateway_config
 *
 * Extracts MODULE, MAXIP, BYPASS and MENU from the BBS menu command string held
 * in margv[].  When the BBS enters a module via a menu item, margv[0] has
 * the menu select character prepended to the first token, so it is skipped
 * on the first iteration only.  Module names may contain spaces; a second
 * pass accumulates additional tokens until a known keyword is found.
 */
static VOID
parse_gateway_config(CHAR *modname, INT modnamsiz, INT *maxip,
                     CHAR *bypass, INT bypasssiz, CHAR *menu, INT menusiz)
{
    INT   i, modname_start = -1, curlen;
    CHAR  tmp[INPSIZ];
    CHAR *tok, *eq, *key, *val;

    modname[0] = '\0';
    menu[0] = '\0';
    *maxip = 1;
    stzcpy(bypass, GW_BYPASS_DEFAULT, bypasssiz);

    for (i = 0; i < margc; i++) {
        tok = (i == 0) ? margv[0] + 1 : margv[i];
        if (tok == NULL || *tok == '\0') continue;
        stzcpy(tmp, tok, sizeof(tmp));
        eq = strchr(tmp, '=');
        if (eq == NULL) continue;
        *eq = '\0';
        key = tmp;
        val = eq + 1;
        if (sameas(key, "MODULE")) {
            stzcpy(modname, val, modnamsiz);
            modname_start = i;
        } else if (sameas(key, "MAXIP")) {
            *maxip = atoi(val);
            if (*maxip < 1) *maxip = 1;
        } else if (sameas(key, "BYPASS")) {
            stzcpy(bypass, val, bypasssiz);
        } else if (sameas(key, "MENU")) {
            stzcpy(menu, val, menusiz);
        }
    }

    /* Pass 2: accumulate space-separated tokens that are part of the module name. */
    if (modname_start >= 0) {
        for (i = modname_start + 1; i < margc; i++) {
            tok = margv[i];
            if (tok == NULL || *tok == '\0') continue;
            stzcpy(tmp, tok, sizeof(tmp));
            eq = strchr(tmp, '=');
            if (eq != NULL) {
                *eq = '\0';
                if (sameas(tmp, "MAXIP") || sameas(tmp, "BYPASS") || sameas(tmp, "MENU"))
                    break;
            }
            curlen = (INT)strlen(modname);
            if (curlen + 1 < modnamsiz) {
                modname[curlen] = ' ';
                stzcpy(modname + curlen + 1, tok, modnamsiz - curlen - 1);
            }
        }
    }
}

/*
 * gw_has_bypass_key
 *
 * Returns TRUE if the current user holds any key from the comma-separated
 * bypass list.  Uses haskey() from the MBBS SDK to test each key name.
 */
static GBOOL
gw_has_bypass_key(const CHAR *bypass)
{
    CHAR  list[GW_BYPASS_MAXSIZ];
    CHAR *tok;

    stzcpy(list, bypass, sizeof(list));
    tok = strtok(list, ",");
    while (tok != NULL) {
        tok = (CHAR *)skptwht(tok);
        unpad(tok);
        if (*tok != '\0' && haskey(tok) == 1)
            return TRUE;
        tok = strtok(NULL, ",");
    }
    return FALSE;
}

/*
 * gw_other_has_bypass_key
 *
 * Returns TRUE if the user on channel `channel` holds any key from the
 * comma-separated bypass list.  Uses gen_haskey() (LOCKNKEY.H) which checks
 * keys for any channel, not just the current one.
 *
 * Called by count_ip_in_mod to exclude bypass-key holders from the session
 * count.  A user who bypassed the limit when they entered should not consume
 * a slot that counts against non-bypass users from the same IP.
 */
static GBOOL
gw_other_has_bypass_key(INT channel, const CHAR *bypass)
{
    CHAR  list[GW_BYPASS_MAXSIZ];
    CHAR *tok;

    stzcpy(list, bypass, sizeof(list));
    tok = strtok(list, ",");
    while (tok != NULL) {
        tok = (CHAR *)skptwht(tok);
        unpad(tok);
        if (*tok != '\0' && gen_haskey(tok, channel, usroff(channel)) == 1)
            return TRUE;
        tok = strtok(NULL, ",");
    }
    return FALSE;
}

/*
 * count_ip_in_mod
 *
 * Returns the number of active (ACTUSR) sessions from user_ip currently
 * inside the module identified by target_state, excluding the current
 * channel and any sessions whose user holds a bypass key.
 *
 * Bypass-key holders are excluded because they entered without consuming a
 * slot -- their presence must not count against non-bypass users from the
 * same IP (otherwise the sysop entering first would reduce the effective
 * limit for everyone else).
 */
static INT
count_ip_in_mod(const CHAR *user_ip, INT target_state, const CHAR *bypass)
{
    CHAR theirs[46];
    INT  i, count = 0;

    if (user_ip == NULL || user_ip[0] == '\0') return 0;

    for (i = 0; i < hichp1; i++) {
        if (i == usrnum)                        continue;
        if (usroff(i)->usrcls != ACTUSR)        continue;
        if (usroff(i)->state  != target_state)  continue;
        snt_source_ip(i, theirs, sizeof(theirs));
        if (strcmp(theirs, user_ip) != 0)       continue;
        if (gw_other_has_bypass_key(i, bypass)) continue;
        count++;
    }
    return count;
}

/*
 * build_ip_users
 *
 * Builds a comma-separated list of the userids logged on (ACTUSR) from
 * user_ip, other than the current channel, for the refusal messages and logs:
 * the Sysop and the refused caller can see who is already using the slots.
 * target_state limits it to sessions inside one module (the gateway); -1
 * takes every session (the BBS-wide connection limit).
 *
 * buf is filled with "(unknown)" if no qualifying sessions are found.
 */
static VOID
build_ip_users(const CHAR *user_ip, INT target_state, CHAR *buf, INT bufsiz)
{
    CHAR           theirs[46];
    INT            i;
    struct usracc *uap;

    buf[0] = '\0';
    if (user_ip == NULL) user_ip = "";
    for (i = 0; i < hichp1; i++) {
        if (i == usrnum)                 continue;
        if (usroff(i)->usrcls != ACTUSR) continue;
        if (target_state >= 0 && usroff(i)->state != target_state) continue;
        snt_source_ip(i, theirs, sizeof(theirs));
        if (theirs[0] == '\0' || strcmp(theirs, user_ip) != 0) continue;
        uap = uacoff(i);
        if (uap == NULL || uap->userid[0] == '\0')          continue;
        if (buf[0] != '\0')
            strncat(buf, ", ", bufsiz - (INT)strlen(buf) - 1);
        strncat(buf, uap->userid, bufsiz - (INT)strlen(buf) - 1);
    }
    if (buf[0] == '\0')
        strncpy(buf, "(unknown)", bufsiz - 1);
    buf[bufsiz - 1] = '\0';
}

/*
 * sntipctl_gateway
 *
 * Runs when the module is entered from a BBS menu item (substt == 0).
 * Parses the command string, checks bypass keys, counts active sessions
 * from the user's IP in the target module, then either forwards via
 * entmdl() or displays a denial message and returns to the menu.
 *
 * If pp_tcpipinf is NULL (proxy detection failed to initialise), the
 * IP check is skipped and access is granted to avoid blocking all users.
 */
static GBOOL
sntipctl_gateway(VOID)
{
    CHAR  modname[MNMSIZ];
    CHAR  bypass[GW_BYPASS_MAXSIZ];
    CHAR  menu[16];
    INT   maxip, modnum, ipcount;
    CHAR  user_ip[46];

    if (modmb == NULL) {
        shocst("Total IP Control", "ERROR: gateway unavailable -- SNTIPCTL.MSG missing; reinstall it and restart");
        return 0;
    }

    setmbk(modmb);

    parse_gateway_config(modname, sizeof(modname), &maxip, bypass, sizeof(bypass),
                         menu, sizeof(menu));

    /* MENU=SYSOPMENU: the settings editor, exactly as /TIP opens it. */
    if (menu[0] != '\0') {
        if (!sameas(menu, "SYSOPMENU")) {
            shocst("Total IP Control", "WARNING: menu entry has unknown MENU=%s", menu);
            rstmbk();
            return 0;
        }
        if (!ed_allowed()) {
            prfmsg(NOACCESS);
            outprf(usrnum);
            rstmbk();
            return 0;
        }
        ed_open();
        absorb_count[usrnum] = 0;
        rstmbk();
        return 1;
    }

    if (modname[0] == '\0') {
        shocst("Total IP Control", "WARNING: menu entry needs MODULE= or MENU=");
        rstmbk();
        return 0;
    }

    modnum = findmod(modname);
    if (modnum < 0) {
        /* "%s": modname comes from the menu's MODULE= parameter, and shocst()
         * treats its detail argument as a format string. */
        shocst("Total IP Control", "%s",
               spr("WARNING: gateway target module '%s' not found", modname));
        rstmbk();
        return 0;
    }

    /* Bypass keys skip the IP check entirely. */
    if (gw_has_bypass_key(bypass)) {
        rstmbk();
        entmdl(modnum, "");
        return 1;
    }

    /* Without IP resolution, fail open rather than blocking everyone. */
    if (pp_tcpipinf == NULL) {
        rstmbk();
        entmdl(modnum, "");
        return 1;
    }

    snt_source_ip(usrnum, user_ip, sizeof(user_ip));
    ipcount = count_ip_in_mod(user_ip, modnum, bypass);

    if (ipcount < maxip) {
        if (rawmsg(IPGGNT) != NULL && *rawmsg(IPGGNT) != '\0') {
            prfmsg(IPGGNT);
            outprf(usrnum);
        }
        rstmbk();
        entmdl(modnum, "");
        return 1;
    }

    /* Denied -- too many sessions from this IP in the target module. */
    {
        CHAR *usrbuf = tv_users;              /* also N!SNTUSERS in IPGDNY */
        build_ip_users(user_ip, modnum, tv_users, sizeof(tv_users));
        sprintf(tv_maxip, "%d", maxip);

        if (log_mode != LOGM_OFF) {
            CHAR        filebuf[560];
            CHAR        audbuf[SNT_AUDIT_DETMAX];
            const CHAR *uid = (usaptr != NULL && usaptr->userid[0] != '\0')
                              ? usaptr->userid : "(unknown)";
            /*
             * Both built with _snprintf into our own buffers -- never spr().
             * spr() formats into a 120-byte static and only checks the length
             * AFTERWARDS (GCOMMLIB\SPR.C), so an over-long line has already
             * overrun it by the time the engine calls catastro() and takes the
             * board down.  This line carries a userid, a module name and the
             * list of active userids, which together clear 120 characters with
             * only four users online.
             *
             * The two sinks get different text because they have very different
             * ceilings.  The file log has room for the whole user list (its
             * writer allows ~600 characters).  The Audit Trail's detail field
             * is 127 usable characters -- less than the surrounding text alone
             * needs once userids approach 29 characters -- so it gets the count
             * and a pointer to the log instead of a list it could only truncate
             * mid-name.  The short form is sized to fit even at maximum userid
             * and module-name lengths (116 characters worst case), so it is
             * never cut.
             */
            _snprintf(filebuf, sizeof(filebuf),
                      "chan %02x: %s denied gateway to %s -- limit exceeded "
                      "(%d active, max %d); active: %s",
                      usrnum + 1, uid, modname, ipcount, maxip, usrbuf);
            filebuf[sizeof(filebuf) - 1] = '\0'; /* _snprintf may not terminate */

            _snprintf(audbuf, sizeof(audbuf),
                      "chan %02x: %s denied gateway to %s -- limit %d/%d "
                      "exceeded; see log",
                      usrnum + 1, uid, modname, ipcount, maxip);
            audbuf[sizeof(audbuf) - 1] = '\0';

            snt_audit_sx("DENIED MODULE ACCESS", uid, user_ip, filebuf, audbuf);
        }

        prfmsg(IPGDNY);
        outprf(usrnum);
    }
    rstmbk();
    return 0;
}

/*
 * sntipctl_stt
 *
 * State-input routine (sttrou), called while usrptr->state == cfgstt.
 * substt == 0 means the module was entered from a BBS menu item: its command
 * line picks the per-module IP gateway (MODULE=) or the settings editor
 * (MENU=SYSOPMENU).  Any other sub-state is the settings editor.
 */
static GBOOL
sntipctl_stt(VOID)
{
    if (usrptr->substt == 0)
        return sntipctl_gateway();
    return ed_entry();
}
