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
#include <windows.h>

#include "gcomm.h"
#include "majorbbs.h"
#include "tcpip.h"
#include "SNTIPCTL.H"

#include <stdio.h>
#include <string.h>
#include "dfaapi.h"
#include "fsdbbs.h"

#define SNTIPCTL_VERSION "v1.0.0"

/* ======================================================================== */
/*   Proxy detection state                                                   */
/* ======================================================================== */

/*
 * Pending socket table, indexed by usrnum.
 * INVALID_SOCKET means no PROXY header processing is pending for that slot.
 * Set in sntipctl_hdlcon, cleared in prx_recv_hook or sntipctl_hup.
 */
static SOCKET pending_skt[MAXNTERM];

/*
 * After globalcmd returns 1, MBBS calls sttrou 1-2 times with spurious input
 * ("/" and/or "") before waiting for real user input.  absorb_count[] tracks
 * how many of those calls to silently swallow for each channel.
 */
static INT absorb_count[MAXNTERM];

/*
 * Config-editor pager suppression.  While a Sysop is inside the /TOTALIP
 * editor we set scnbrk=CTNUOS (continuous output, no "(N)onstop,Q,C?" prompt)
 * for the WHOLE session rather than toggling it around each screen -- toggling
 * is fragile because the FSE teardown (fsdcof) re-arms the pager between our
 * calls.  editor_scnbrk_saved[] holds the user's normal scnbrk so we can
 * restore it when they exit the editor; editor_pager_off[] flags that we have
 * suppressed it for that channel.
 */
static CHAR  editor_scnbrk_saved[MAXNTERM];
static GBOOL editor_pager_off[MAXNTERM];

/*
 * IAT patch state.
 * We patch recv() in either GALTNTD.DLL or GALTCPIP.DLL.
 * patched_iat_entry points into the module's IAT so we can restore it.
 * real_recv is the original function address saved from that slot.
 */
typedef int (WINAPI *recv_fn_t)(SOCKET, char *, int, int);
static recv_fn_t  real_recv         = NULL;
static recv_fn_t *patched_iat_entry = NULL;

/*
 * tcpipinf is resolved at runtime to avoid linking GALTCPIP_LIB.LIB,
 * which causes DLL load failure due to ordinal mismatch on some servers.
 */
static struct tcpipinf **pp_tcpipinf = NULL;

/* Saved hdlcon pointer -- we chain to this after our processing. */
static VOID (*hcsave)(VOID) = NULL;

/* ======================================================================== */
/*   Configuration state                                                     */
/* ======================================================================== */

static HMCVFILE modmb = NULL;

/*
 * IPv4 CIDR entry: network address + subnet mask, both in network byte order.
 * An all-zero entry (addr=0, mask=0) is treated as "not set".
 */
struct snt_cidr {
    ULONG addr;     /* network address (host bits zeroed)  */
    ULONG mask;     /* subnet mask                         */
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

/* Global IP connection limiting -- BBS-wide cap per source IP. */
static GBOOL conn_limit_enabled = FALSE;
static INT   conn_limit_max     = 1;

/* Audit logging -- daily log files under TOTALIPCONTROL\PROXCLIP LOGS\. */
static GBOOL            log_enabled = FALSE;
static CRITICAL_SECTION log_cs;

/* User profile IP recording -- write real IP to a user account field at logon. */
static GBOOL usrip_enabled = FALSE;
static INT   usrip_field   = 1;    /* 1=usrad1, 2=usrad2, 3=usrad3, 4=usrad4, 5=usrpho */

/*
 * Bypass key -- any user holding this BBS key is exempt from connection
 * limit enforcement.  SYSOP and MASTER key holders are always exempt
 * regardless of this setting.  Empty string = no additional bypass.
 */
static CHAR bypass_key[16];

/* Connection limit whitelist -- connections from these IPs/CIDRs are never
 * subject to the global per-IP connection limit. */
static struct snt_cidr whitelist_cidrs[SNTIPCTL_MAX_WHITELIST];

/* Online config editor -- module state number assigned at init. */
static INT cfgstt = -1;

/*
 * FSE field specification strings for the 3 config editor forms.
 * Must be static -- fsdroom() retains a pointer to fldspc across calls.
 */
static CHAR gen_fsp[] =
    "PRXTRU(ALT=NO ALT=YES MULTICHOICE) "
    "PRXBLK(ALT=NO ALT=YES MULTICHOICE) "
    "CONLIM(ALT=NO ALT=YES MULTICHOICE) "
    "MAXCON(MIN=1 MAX=1000) "
    "LOGON(ALT=NO ALT=YES MULTICHOICE) "
    "UIPON(ALT=NO ALT=YES MULTICHOICE) "
    "UIPFLD(MIN=1 MAX=5) "
    "BYPKEY "
    "DONE(ALT=SAVE ALT=QUIT MULTICHOICE)";

static CHAR prx_fsp[] =
    "PRX1 PRX2 "
    "DONE(ALT=SAVE ALT=QUIT MULTICHOICE)";

static CHAR wl1_fsp[] =
    "WL1 WL2 WL3 WL4 WL5 WL6 WL7 WL8 WL9 WL10 "
    "DONE(ALT=SAVE ALT=QUIT MULTICHOICE)";

/* Printf-style answer strings for loading current values into each FSE form. */
static CHAR gen_fmt[] =
    "PRXTRU=%s%c" "PRXBLK=%s%c" "CONLIM=%s%c" "MAXCON=%d%c"
    "LOGON=%s%c"  "UIPON=%s%c"  "UIPFLD=%d%c"
    "BYPKEY=%s%c";

static CHAR prx_fmt[] =
    "PRX1=%s%c" "PRX2=%s%c";

static CHAR wl1_fmt[] =
    "WL1=%s%c" "WL2=%s%c" "WL3=%s%c" "WL4=%s%c" "WL5=%s%c"
    "WL6=%s%c" "WL7=%s%c" "WL8=%s%c" "WL9=%s%c" "WL10=%s%c";

/*
 * Per-user VDA size required for FSE session data.
 * Computed at init as the maximum across all forms and declared via dclvda().
 * vdaptr is used directly as the sesbuf for all forms.
 */
static INT snt_vda_sz = 0;

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
 * version == 7 identifies this layout.  If a record with a different version
 * is found at startup, it is replaced with fresh defaults.  Field sizes:
 *   16 + 1 + 1 + 16 + 1 + 4 + 1 + 1 + 4 + 16 + 80 + 1 + 370 = 512 bytes
 */
#pragma pack(push, 1)
struct sntipctlcfg {
    CHAR            recid[16];                      /* key: "SNTIPCTL"         */
    CHAR            version;                        /* struct version (7)      */
    CHAR            proxy_trust;                    /* 'Y'/'N'                 */
    struct snt_cidr proxy_cidrs[2];                 /* trusted proxy CIDRs     */
    CHAR            conn_limit;                     /* 'Y'/'N'                 */
    INT             conn_max;                       /* 1-1000                  */
    CHAR            log_on;                         /* 'Y'/'N'                 */
    CHAR            usrip_on;                       /* 'Y'/'N'                 */
    INT             usrip_fld;                      /* 1-5                     */
    CHAR            bypass_key[16];                 /* BBS key name or empty   */
    struct snt_cidr whitelist[10];                  /* conn-limit whitelist    */
    CHAR            proxy_block;                    /* 'Y'/'N' require proxy   */
    CHAR            spare[370];                     /* pad to 512 bytes        */
};
#pragma pack(pop)

static DFAFILE             *sntbt = NULL;   /* SNTIPCTL.DAT file handle */
static struct sntipctlcfg   sntcfg;         /* in-memory config record  */

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
static GBOOL      is_trusted_proxy(ULONG ip);
static GBOOL      is_loopback(ULONG ip);
static INT        count_active_ip(ULONG ip);
static VOID       parse_gateway_config(CHAR *modname, INT modnamsiz, INT *maxip,
                                        CHAR *bypass, INT bypasssiz);
static GBOOL      gw_has_bypass_key(const CHAR *bypass);
static INT        count_ip_in_mod(ULONG user_ip, INT target_state);
static VOID       build_ip_in_mod_users(ULONG user_ip, INT target_state, CHAR *buf, INT bufsiz);
static VOID       build_active_ip_users(ULONG user_ip, CHAR *buf, INT bufsiz);
static GBOOL      sntipctl_gateway(VOID);
static VOID       build_log_path(const CHAR *subdir, CHAR *buf, INT bufsiz);
static VOID       sntipctl_log_event(const CHAR *subdir, const CHAR *userid, ULONG ip, const CHAR *event);

static GBOOL sntipctl_logon(VOID);
static VOID  sntipctl_hup(VOID);
static VOID  sntipctl_fin(VOID);
static GBOOL sntipctl_stt(VOID);

__declspec(dllexport) VOID      sntipctl_hdlcon(VOID);
__declspec(dllexport) INT       prx_consume_header(SOCKET skt, INT unum);
__declspec(dllexport) int WINAPI prx_recv_hook(SOCKET s, char *buf, int len, int flags);

static GBOOL cidr_match(ULONG ip, const struct snt_cidr *cidr);
static GBOOL parse_cidr(const CHAR *str, struct snt_cidr *out);
static VOID  cidr_to_str(const struct snt_cidr *cidr, CHAR *buf, INT bufsiz);
static GBOOL is_whitelisted(ULONG ip);
static GBOOL has_bypass_key(VOID);

static VOID write_ip_to_profile(ULONG ip);
static VOID cidr_for_fse(const struct snt_cidr *cidr, CHAR *buf, INT bufsiz);
static VOID cfg_launch_gen(VOID);
static VOID cfg_launch_prx(VOID);
static VOID cfg_launch_wl1(VOID);
static VOID cfg_gen_done(SHORT save);
static VOID cfg_prx_done(SHORT save);
static VOID cfg_wl1_done(SHORT save);
static INT  cfg_prx_vfy(INT fldno, CHAR *answer);
static INT  cfg_wl1_vfy(INT fldno, CHAR *answer);
static VOID cfg_live_to_struct(VOID);
static VOID cfg_struct_to_live(VOID);
static VOID cfg_save(VOID);
static VOID cfg_load(VOID);
static INT  sntipctl_gbl(VOID);
static VOID editor_pager_suppress(VOID);
static VOID editor_pager_restore(VOID);

/* ======================================================================== */
/*   Module interface block                                                  */
/* ======================================================================== */

struct module SNTIPCTL = {
    "",              /* descrp: filled from MDF at init              */
    sntipctl_logon,  /* lonrou: logon supplement                     */
    sntipctl_stt,    /* sttrou: online config editor                 */
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
        pending_skt[i]  = INVALID_SOCKET;
        absorb_count[i] = 0;
    }

    /* Open message file (LEVEL6 + LEVEL99 FSE templates -- no GCNF). */
    modmb = opnmsg("SNTIPCTL.MCV");
    if (modmb == NULL)
        shocst("Total IP Control", "WARNING: SNTIPCTL.MCV not found -- run GCNF then restart BBS");

    /*
     * Declare per-user VDA space for FSE config editor sessions.
     * fsdroom() sizes each form; we allocate max of the three so a single
     * vdaptr region covers whichever form the Sysop opens.
     */
    if (modmb != NULL) {
        INT r1, r2, r3;
        setmbk(modmb);
        r1 = fsdroom(SNTCFG_GEN, gen_fsp, 0);
        r2 = fsdroom(SNTCFG_PRX, prx_fsp, 0);
        r3 = fsdroom(SNTCFG_WL,  wl1_fsp, 0);
        rstmbk();
        snt_vda_sz = r1;
        if (r2 > snt_vda_sz) snt_vda_sz = r2;
        if (r3 > snt_vda_sz) snt_vda_sz = r3;
        if (snt_vda_sz > 0)
            dclvda(snt_vda_sz);
        else
            shocst("Total IP Control", "WARNING: FSE form sizing failed -- config editor unavailable");
    }

    /* Hard-coded first-run defaults -- all features off. Configure via /TOTALIP. */
    proxy_trust_enabled = FALSE;
    proxy_block_enabled = FALSE;
    setmem((CHAR *)trusted_proxy_cidrs, sizeof(trusted_proxy_cidrs), 0);
    trusted_proxy_count = 0;
    conn_limit_enabled  = FALSE;
    conn_limit_max      = 1;
    log_enabled         = FALSE;
    usrip_enabled       = FALSE;
    usrip_field         = 1;
    setmem((CHAR *)bypass_key,      sizeof(bypass_key),      0);
    setmem((CHAR *)whitelist_cidrs, sizeof(whitelist_cidrs), 0);

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

    if (log_enabled) {
        /* Create the log directory tree if it does not already exist. */
        CreateDirectoryA("TOTALIPCONTROL", NULL);
        CreateDirectoryA("TOTALIPCONTROL\\PROXCLIP LOGS", NULL);
        CreateDirectoryA("TOTALIPCONTROL\\DENIED CONNECTIONS", NULL);
        CreateDirectoryA("TOTALIPCONTROL\\DENIED MODULE ACCESS", NULL);
    }

    if (proxy_trust_enabled)
        shocst("Total IP Control", spr("trusted proxy enforcement enabled (%d CIDR(s) configured)", trusted_proxy_count));
    if (proxy_block_enabled) {
        if (trusted_proxy_count > 0)
            shocst("Total IP Control", spr("require-trusted-proxy ENABLED -- direct/untrusted connections will be refused (%d trusted CIDR(s))", trusted_proxy_count));
        else
            shocst("Total IP Control", "require-trusted-proxy is ON but no trusted CIDRs are configured -- blocking is INACTIVE (fail-safe)");
    }
    if (conn_limit_enabled)
        shocst("Total IP Control", spr("global connection limit enabled: max %d per IP", conn_limit_max));
    if (log_enabled)
        shocst("Total IP Control", "audit file logging enabled in TOTALIPCONTROL folder");
    if (usrip_enabled)
        shocst("Total IP Control", spr("user profile IP recording enabled (field %d)", usrip_field));

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
     * real_recv is saved for fin-time restoration only; SNTIPCTL.DLL's own
     * calls to recv() bypass the patched IAT via SNTIPCTL's unpatched entry.
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
            shocst("Total IP Control",
                   spr("recv hook installed in %s -- no-sleep mode",
                       patched_ntd ? "GALTNTD" : "GALTCPIP"));
        } else {
            shocst("Total IP Control", "WARNING: recv hook unavailable -- single-shot FIONREAD fallback");
        }
    }

    shocst("Total IP Control", "hdlcon hook installed -- proxy detection active");

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
 */
static recv_fn_t
patch_iat_recv(HMODULE hMod, recv_fn_t new_fn)
{
    recv_fn_t *slot = find_iat_recv(hMod);
    recv_fn_t  old_fn;
    DWORD      old_prot;

    if (slot == NULL) return NULL;
    old_fn = *slot;
    VirtualProtect(slot, sizeof(recv_fn_t), PAGE_READWRITE, &old_prot);
    *slot = new_fn;
    VirtualProtect(slot, sizeof(recv_fn_t), old_prot, &old_prot);
    if (patched_iat_entry == NULL)
        patched_iat_entry = slot;   /* remember first patch for fin-time restore */
    return old_fn;
}

/* ======================================================================== */
/*   Proxy detection                                                         */
/* ======================================================================== */

/*
 * prx_recv_hook
 *
 * Installed in place of recv() in GALTNTD.DLL (or GALTCPIP.DLL).
 *
 * When GALTNTD makes its first non-peek recv() call for a pending socket,
 * we intercept, strip the PROXY header, and patch the real IP.  Subsequent
 * recv() calls for the same socket pass through immediately.
 *
 * usrnum is valid here: hdlsock() calls curusr(usrnum) before invoking any
 * socket event handler, so it is set to the channel being processed.
 */
__declspec(dllexport) int WINAPI
prx_recv_hook(SOCKET s, char *buf, int len, int flags)
{
    if (!(flags & MSG_PEEK) &&
        pp_tcpipinf != NULL &&
        usrnum >= 0 && usrnum < MAXNTERM &&
        pending_skt[usrnum] == s) {

        /*
         * prx_consume_header returns:
         *    1  -- a complete PROXY header was consumed (IP applied or, if the
         *          source is untrusted, discarded); stream is now clean
         *   -1  -- this is not a PROXY stream; nothing to do
         *    0  -- a PROXY header is still arriving; we must NOT let GALTNTD
         *          read the partial bytes (that would split the header and
         *          corrupt the telnet/ANSI input stream -- the cause of both
         *          "real IP not restored" and broken arrow keys).
         */
        INT r = prx_consume_header(s, usrnum);
        if (r == 0) {
            /*
             * Report "would block" so GALTNTD's non-blocking event loop simply
             * retries the read on the next readable event, by which time more
             * of the (tiny, sent-at-once) header has arrived.  pending_skt is
             * left set so we try again.  This returns immediately -- still
             * no-sleep, no polling thread.
             */
            WSASetLastError(WSAEWOULDBLOCK);
            return SOCKET_ERROR;
        }
        pending_skt[usrnum] = INVALID_SOCKET;   /* done: consumed or not-proxy */
    }

    /* Call through SNTIPCTL.DLL's own unpatched IAT -- no recursion risk. */
    return recv(s, buf, len, flags);
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
 */
__declspec(dllexport) INT
prx_consume_header(SOCKET skt, INT unum)
{
    CHAR           hdr[128];    /* 107-byte max + \r\n + NUL fits easily */
    INT            n, hdr_start, avail, cmplen, hdr_end, i;
    CHAR           proto[16], src_ip[64], dst_ip[64];
    INT            src_port, dst_port, fields;
    struct in_addr real_ip;
    static const CHAR PFX[6] = { 'P','R','O','X','Y',' ' };

    if (pp_tcpipinf == NULL) return -1;     /* can't process -- treat as done */

    /*
     * Peek (non-destructively) at whatever bytes have arrived so far.  We must
     * NOT allow GALTNTD to read any data until we have either consumed a full
     * PROXY header or confirmed the stream is not a PROXY header -- otherwise
     * a header split across TCP reads would be half-consumed, corrupting the
     * input stream (no real IP, and garbled telnet/ANSI -> dead arrow keys).
     *   return  0 = need more data (caller holds GALTNTD off and retries)
     *   return  1 = a complete header was consumed (applied or discarded)
     *   return -1 = not a PROXY stream (caller lets GALTNTD read normally)
     */
    n = recv(skt, hdr, (INT)(sizeof(hdr) - 1), MSG_PEEK);
    if (n <= 0)
        return 0;                            /* nothing readable yet -- wait    */
    hdr[n] = '\0';

    /* Skip leading \r/\n (some proxies/clients emit a stray CR/LF first). */
    hdr_start = 0;
    while (hdr_start < n && (hdr[hdr_start] == '\r' || hdr[hdr_start] == '\n'))
        hdr_start++;
    avail = n - hdr_start;

    /*
     * Compare what we have so far against the start of "PROXY ".  If the bytes
     * already diverge, this is an ordinary (non-proxy) client -- return -1 and
     * let GALTNTD read untouched.  Only a stream whose leading bytes ARE a
     * prefix of "PROXY " is ever made to wait, so a direct telnet client is
     * never delayed by this check.
     */
    cmplen = (avail < 6) ? avail : 6;
    if (cmplen > 0 && memcmp(hdr + hdr_start, PFX, cmplen) != 0)
        return -1;                           /* definitely not a PROXY header   */
    if (avail < 6)
        return 0;                            /* "PROXY " still arriving -- wait */

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
            shocst("Total IP Control", spr("chan %02x: oversized/unterminated PROXY header, passing through", unum + 1));
            return -1;
        }
        return 0;
    }

    /* Destructively consume exactly the header bytes (including the \r\n). */
    recv(skt, hdr, hdr_end, 0);
    hdr[hdr_end] = '\0';

    /*
     * Trusted-proxy enforcement.  The header is consumed in all cases (so the
     * stream is clean for GALTNTD), but the real IP is only APPLIED when the
     * connecting proxy is trusted.  With enforcement off, every header is
     * applied -- i.e. PROXCLIP always runs.
     */
    if (proxy_trust_enabled && trusted_proxy_count > 0 &&
        !is_trusted_proxy((*pp_tcpipinf)[unum].inaddr.s_addr)) {
        if (log_enabled)
            sntipctl_log_event("PROXCLIP LOGS", "(connecting)",
                               (*pp_tcpipinf)[unum].inaddr.s_addr,
                               "PROXY header ignored -- source not in trusted proxy list");
        return 1;                            /* consumed but not applied        */
    }

    /* Parse: "PROXY TCP4 <src-ip> <dst-ip> <src-port> <dst-port>\r\n" */
    src_port = dst_port = 0;
    fields = sscanf(hdr + hdr_start, "PROXY %15s %63s %63s %d %d",
                    proto, src_ip, dst_ip, &src_port, &dst_port);
    if (fields < 5 || memcmp(proto, "TCP4", 4) != 0) {
        shocst("Total IP Control", spr("chan %02x: bad PROXY header (fields=%d), consumed", unum + 1, fields));
        return 1;
    }

    real_ip.s_addr = inet_addr(src_ip);
    if (real_ip.s_addr == INADDR_NONE) {
        shocst("Total IP Control", spr("chan %02x: bad src IP in header, consumed", unum + 1));
        return 1;
    }

    (*pp_tcpipinf)[unum].inaddr = real_ip;

    if (log_enabled) {
        CHAR evtbuf[128];
        _snprintf(evtbuf, sizeof(evtbuf),
                  "Proxy header processed on channel %02x, real IP %s", unum + 1, src_ip);
        sntipctl_log_event("PROXCLIP LOGS", "(connecting)", real_ip.s_addr, evtbuf);
    }

    shocst("Total IP Control", spr("chan %02x: real IP %s", unum + 1, src_ip));
    return 1;
}

/*
 * sntipctl_hdlcon
 *
 * Called by GALTNTD for every new telnet connection.
 *
 * Records the socket as pending for PROXY header processing, then hands
 * off to GALTNTD immediately via hcsave() -- no sleeping or polling.
 * When GALTNTD later calls recv() for this socket, prx_recv_hook fires
 * and consumes the PROXY header before GALTNTD sees any data.
 *
 * If the recv hook is unavailable (IAT patch failed), falls back to a
 * single non-blocking FIONREAD check as a best-effort measure.
 */
__declspec(dllexport) VOID
sntipctl_hdlcon(VOID)
{
    SOCKET skt;

    if (pp_tcpipinf == NULL || usrnum < 0 || usrnum >= nterms) {
        hcsave();
        return;
    }

    skt = (*pp_tcpipinf)[usrnum].socket;

    if (skt != INVALID_SOCKET) {
        if (real_recv != NULL) {
            /* Normal path: mark pending, hook will process on first recv. */
            pending_skt[usrnum] = skt;
        } else {
            /* Fallback: single non-blocking check right now. */
            u_long avail = 0;
            ioctlsocket(skt, FIONREAD, &avail);
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
                        /*
                         * In the fallback path, also enforce trusted proxy check
                         * before processing the PROXY header.
                         */
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
                                if (fields >= 5 && memcmp(proto, "TCP4", 4) == 0) {
                                    real_ip.s_addr = inet_addr(src_ip);
                                    if (real_ip.s_addr != INADDR_NONE) {
                                        (*pp_tcpipinf)[usrnum].inaddr = real_ip;
                                        shocst("Total IP Control", spr("chan %02x: real IP %s (fallback)", usrnum + 1, src_ip));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    hcsave();

    /*
     * Require-trusted-proxy enforcement.  When enabled (and at least one
     * trusted proxy CIDR is configured), refuse any connection whose raw
     * source IP is not one of the trusted proxies, before the login prompt.
     *
     * The IP examined here is the RAW TCP peer IP (the proxy's address for a
     * relayed connection, or the client's own address for a direct one) -- it
     * has not yet been rewritten by the PROXY-header recv hook.  So:
     *   - relayed via a trusted proxy  -> raw IP is the trusted proxy -> allow
     *   - direct telnet to the backend -> raw IP is the client        -> block
     *   - relayed via an unknown proxy -> raw IP is that proxy         -> block
     *
     * Loopback (local console) and connection-limit whitelist IPs are always
     * allowed so a misconfigured CIDR cannot lock the host or trusted admins
     * out.  An empty trusted list disables blocking entirely.  No MBBS session
     * exists yet, so the refusal message is written straight to the socket and
     * the socket is closed directly (the same approach as the pre-login
     * connection-limit rejection below).
     */
    if (proxy_block_enabled && trusted_proxy_count > 0 &&
        pp_tcpipinf != NULL && usrnum >= 0 && usrnum < nterms) {

        ULONG  raw_ip  = (*pp_tcpipinf)[usrnum].inaddr.s_addr;
        SOCKET skt_blk = (*pp_tcpipinf)[usrnum].socket;

        if (skt_blk != INVALID_SOCKET && raw_ip != 0 &&
            !is_loopback(raw_ip) &&
            !is_whitelisted(raw_ip) &&
            !is_trusted_proxy(raw_ip)) {

            if (log_enabled)
                sntipctl_log_event("DENIED CONNECTIONS", "(connecting)", raw_ip,
                    "Direct/untrusted connection refused -- require trusted proxy");

            if (modmb != NULL) {
                const char *tmpl;
                setmbk(modmb);
                tmpl = rawmsg(PRXBLK);
                if (tmpl != NULL)
                    send(skt_blk, tmpl, (int)strlen(tmpl), 0);
                rstmbk();
                Sleep(500); /* allow TCP stack to flush before close */
            }
            closesocket(skt_blk);
            (*pp_tcpipinf)[usrnum].socket = INVALID_SOCKET;
            if (usrnum >= 0 && usrnum < MAXNTERM)
                pending_skt[usrnum] = INVALID_SOCKET;
            return;  /* connection refused -- skip all further processing */
        }
    }

    /*
     * Post-connect enforcement for non-proxy connections (real IP is already
     * known at this point).  Proxy connections are checked in sntipctl_logon
     * after prx_recv_hook has consumed the PROXY header and patched the IP.
     *
     * Order of checks:
     *   1. Blocked list -- silent drop, no login prompt shown.
     *   2. Global connection limit -- drop with message.
     */
    if (pp_tcpipinf != NULL &&
        usrnum >= 0 && usrnum < nterms &&
        pending_skt[usrnum] == INVALID_SOCKET) {

        ULONG  user_ip  = (*pp_tcpipinf)[usrnum].inaddr.s_addr;
        SOCKET skt_chk  = (*pp_tcpipinf)[usrnum].socket;

        if (user_ip == 0 || skt_chk == INVALID_SOCKET) goto hdlcon_done;

        /* --- Global connection limit --- */
        if (conn_limit_enabled &&
            !is_whitelisted(user_ip) &&
            count_active_ip(user_ip) >= conn_limit_max) {

            if (log_enabled) {
                CHAR evtbuf[128];
                _snprintf(evtbuf, sizeof(evtbuf),
                          "Connection rejected at connect time: per-IP limit (%d max)",
                          conn_limit_max);
                sntipctl_log_event("DENIED CONNECTIONS", "(connecting)", user_ip, evtbuf);
            }

            if (modmb != NULL) {
                const char *tmpl;
                const char *pct_s;
                CHAR usrbuf[256];
                build_active_ip_users(user_ip, usrbuf, sizeof(usrbuf));
                setmbk(modmb);
                tmpl = rawmsg(CLIMIT);
                if (tmpl != NULL) {
                    /*
                     * Split at %s and send in three parts to avoid _snprintf
                     * misinterpreting MBBS-internal % bytes in the template.
                     */
                    pct_s = strstr(tmpl, "%s");
                    if (pct_s != NULL) {
                        send(skt_chk, tmpl,   (int)(pct_s - tmpl),   0);
                        send(skt_chk, usrbuf,  (int)strlen(usrbuf),   0);
                        send(skt_chk, pct_s+2, (int)strlen(pct_s+2),  0);
                    } else {
                        send(skt_chk, tmpl, (int)strlen(tmpl), 0);
                    }
                    Sleep(500); /* allow TCP stack to flush before close */
                }
                rstmbk();
            }
            closesocket(skt_chk);
            (*pp_tcpipinf)[usrnum].socket = INVALID_SOCKET;
        }
    }

    hdlcon_done: ;
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
 * is_whitelisted
 *
 * Returns TRUE if ip matches any entry in the connection-limit whitelist.
 * Whitelisted IPs are never subject to connection limit enforcement.
 */
static GBOOL
is_whitelisted(ULONG ip)
{
    INT i;
    for (i = 0; i < SNTIPCTL_MAX_WHITELIST; i++) {
        if (cidr_match(ip, &whitelist_cidrs[i]))
            return TRUE;
    }
    return FALSE;
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
    if (haskey("SYSOP")  || haskey("MASTER")) return TRUE;
    if (bypass_key[0] != '\0' && haskey(bypass_key)) return TRUE;
    return FALSE;
}

/*
 * is_trusted_proxy
 *
 * Returns TRUE if ip matches any CIDR entry in the trusted proxy list.
 */
static GBOOL
is_trusted_proxy(ULONG ip)
{
    INT i;
    for (i = 0; i < SNTIPCTL_MAX_TRUSTED; i++) {
        if (cidr_match(ip, &trusted_proxy_cidrs[i]))
            return TRUE;
    }
    return FALSE;
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
count_active_ip(ULONG user_ip)
{
    INT i, count = 0;

    for (i = 0; i < hichp1; i++) {
        if (i == usrnum)                                  continue; /* skip self          */
        if (usroff(i)->usrcls != ACTUSR)                  continue; /* must be logged on  */
        if ((*pp_tcpipinf)[i].inaddr.s_addr != user_ip)   continue; /* must match IP      */
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
    ULONG user_ip;
    INT   count;

    if (pp_tcpipinf == NULL)
        return 0;

    user_ip = (*pp_tcpipinf)[usrnum].inaddr.s_addr;

    if (conn_limit_enabled) {
        /*
         * Whitelist check: IPs/CIDRs in the whitelist are never subject to
         * the connection limit.  SYSOP/MASTER and the configured bypass key
         * also exempt the user.  These checks occur before the count so
         * privileged users always get through.
         */
        if (!is_whitelisted(user_ip) && !has_bypass_key()) {
            count = count_active_ip(user_ip);
            if (count >= conn_limit_max) {
                if (log_enabled) {
                    CHAR evtbuf[128];
                    _snprintf(evtbuf, sizeof(evtbuf),
                              "Connection limit exceeded (%d active, max %d) -- session rejected",
                              count, conn_limit_max);
                    sntipctl_log_event("DENIED CONNECTIONS",
                        (usaptr != NULL && usaptr->userid[0] != '\0') ? usaptr->userid : "(unknown)",
                        user_ip, evtbuf);
                }
                /*
                 * Disconnect the user with a message naming the other
                 * sessions already connected from this IP.
                 *
                 * We use byenow() -- the sanctioned MBBS "log off a user with
                 * a message" utility -- rather than writing to the socket
                 * ourselves.  This is important for two reasons:
                 *
                 *   1) Correct text.  byenow() formats the message through
                 *      prfmsg(), so the "%s" in CLIMIT is replaced with the
                 *      userid list cleanly.  Writing the raw template to the
                 *      socket by hand interleaved our bytes with the normal
                 *      logon output MBBS had already queued (the welcome
                 *      banner, the pager prompt, etc.), which scrambled the
                 *      message on the wire.
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
                 */
                if (modmb != NULL) {
                    CHAR usrbuf[256];
                    build_active_ip_users(user_ip, usrbuf, sizeof(usrbuf));
                    /*
                     * Suppress the output pager so the user does not get a
                     * "(N)onstop, (Q)uit, or (C)ontinue?" prompt wedged into
                     * the middle of being disconnected.  Setting scnbrk to the
                     * continuous-output sentinel and re-arming via rstrxf()
                     * tells MBBS not to break the page.  No need to restore --
                     * the session is about to end.
                     */
                    if (usaptr != NULL) {
                        usaptr->scnbrk = CTNUOS;
                        rstrxf();
                    }
                    setmbk(modmb);
                    byenow(CLIMIT, usrbuf);
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
     * Record the real IP (post-proxy) to the user's profile field.
     * Only reached for sessions that passed the connection limit check.
     */
    if (usrip_enabled)
        write_ip_to_profile(user_ip);

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
        pending_skt[usrnum]   = INVALID_SOCKET;
        absorb_count[usrnum]  = 0;
        /* Session is gone -- clear the editor pager flag (MBBS resets the
         * channel's scnbrk on the next login, so no restore is needed here). */
        editor_pager_off[usrnum] = FALSE;
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
    if (patched_iat_entry != NULL && real_recv != NULL) {
        DWORD old_prot;
        VirtualProtect(patched_iat_entry, sizeof(recv_fn_t), PAGE_READWRITE, &old_prot);
        *patched_iat_entry = real_recv;
        VirtualProtect(patched_iat_entry, sizeof(recv_fn_t), old_prot, &old_prot);
        patched_iat_entry = NULL;
        real_recv = NULL;
    }

    if (hcsave != NULL) {
        hdlcon = hcsave;
        hcsave = NULL;
    }

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
    SYSTEMTIME     st;
    CHAR           logpath[MAX_PATH];
    CHAR           line[512];
    CHAR           ipbuf[20];
    FILE          *fp;
    unsigned char *b;

    if (!log_enabled) return;

    GetLocalTime(&st);
    build_log_path(subdir != NULL ? subdir : "PROXCLIP LOGS", logpath, sizeof(logpath));

    b = (unsigned char *)&ip;
    _snprintf(ipbuf, sizeof(ipbuf), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);

    _snprintf(line, sizeof(line),
              "%04d-%02d-%02d %02d:%02d:%02d  %-20s  %-15s  %s\n",
              st.wYear, st.wMonth, st.wDay,
              st.wHour, st.wMinute, st.wSecond,
              userid != NULL ? userid : "(unknown)",
              ipbuf,
              event  != NULL ? event  : "");

    EnterCriticalSection(&log_cs);
    fp = fopen(logpath, "a");
    if (fp != NULL) {
        fputs(line, fp);
        fclose(fp);
    }
    LeaveCriticalSection(&log_cs);
}

/* ======================================================================== */
/*   Online configuration editor                                             */
/*                                                                           */
/*   Triggered by the global command /TOTALIP (Master access required).     */
/*   Uses the sttrou state machine so the Sysop can review and change any   */
/*   setting interactively from a live BBS session.                          */
/*                                                                           */
/*   Changes take effect immediately in memory.  [S] persists them to       */
/*   SNTIPCTL.DAT (a Btrieve file in the BBS data directory).               */
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
write_ip_to_profile(ULONG ip)
{
    CHAR           ipbuf[20];
    CHAR          *field;
    INT            maxlen;
    unsigned char *b = (unsigned char *)&ip;

    if (usaptr == NULL || ip == 0) return;

    _snprintf(ipbuf, sizeof(ipbuf), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);

    switch (usrip_field) {
    case 1: field = usaptr->usrad1; maxlen = NADSIZ; break;
    case 2: field = usaptr->usrad2; maxlen = NADSIZ; break;
    case 3: field = usaptr->usrad3; maxlen = NADSIZ; break;
    case 4: field = usaptr->usrad4; maxlen = NADSIZ; break;
    case 5: field = usaptr->usrpho; maxlen = PHOSIZ; break;
    default: return;
    }

    stzcpy(field, ipbuf, maxlen);
    updacc();

    if (log_enabled)
        sntipctl_log_event("PROXCLIP LOGS", usaptr->userid, ip,
                           spr("IP recorded to profile field %d", usrip_field));
}

/*
 * cidr_for_fse
 *
 * Like cidr_to_str() but returns an empty string for unset entries rather
 * than "(not set)".  FSE fields should be blank when no value is configured
 * so the Sysop can tab past them without having to clear the placeholder.
 */
static VOID
cidr_for_fse(const struct snt_cidr *cidr, CHAR *buf, INT bufsiz)
{
    if (cidr->addr == 0 && cidr->mask == 0)
        buf[0] = '\0';
    else
        cidr_to_str(cidr, buf, bufsiz);
}

/*
 * editor_pager_suppress / editor_pager_restore
 *
 * Turn the MBBS output pager off for the entire /TOTALIP editor session and
 * back on when the Sysop leaves.  Doing this once (rather than around every
 * screen) is reliable because scnbrk stays CTNUOS the whole time, so even the
 * FSE teardown's own rstrxf() keeps paging disabled.  Idempotent per channel.
 */
static VOID
editor_pager_suppress(VOID)
{
    if (usaptr == NULL || usrnum < 0 || usrnum >= MAXNTERM) return;
    if (editor_pager_off[usrnum]) return;          /* already suppressed */
    editor_scnbrk_saved[usrnum] = usaptr->scnbrk;
    editor_pager_off[usrnum]    = TRUE;
    usaptr->scnbrk = CTNUOS;
    rstrxf();
}

static VOID
editor_pager_restore(VOID)
{
    if (usrnum < 0 || usrnum >= MAXNTERM) return;
    if (!editor_pager_off[usrnum]) return;
    if (usaptr != NULL) {
        usaptr->scnbrk = editor_scnbrk_saved[usrnum];
        rstrxf();
    }
    editor_pager_off[usrnum] = FALSE;
}

/*
 * cfg_show_topmenu
 *
 * Displays the config editor header and top-level menu.  Caller must have
 * setmbk(modmb) in effect.  Flushes output to the current user.
 *
 * Pager suppression for the editor is handled at session level via
 * editor_pager_suppress() (entered in sntipctl_gbl), so this routine no longer
 * needs to toggle scnbrk itself.
 */
static VOID
cfg_show_topmenu(VOID)
{
    CHAR saved_scnbrk = 0;
    GBOOL pager_saved = FALSE;

    if (usaptr != NULL) {
        saved_scnbrk = usaptr->scnbrk;
        usaptr->scnbrk = CTNUOS;
        rstrxf();   /* re-arm btuxnf with continuous (0 lines = no paging) */
        pager_saved = TRUE;
    }

    prfmsg(CFGHED);
    prfmsg(CFGMNU);
    outprf(usrnum);

    if (pager_saved) {
        usaptr->scnbrk = saved_scnbrk;
        rstrxf();   /* re-arm btuxnf with user's normal screen length */
    }
}

/* ======================================================================== */
/*   FSE form launch functions                                               */
/* ======================================================================== */

/*
 * cfg_launch_gen
 *
 * Starts a full-screen FSE session for the General Settings form.
 * Loads current settings as defaults, paints the ANSI background, and
 * hands control to FSD.  cfg_gen_done() is called when the user saves or
 * quits.
 *
 * Caller must NOT have setmbk active (launch function manages it).
 */
static VOID
cfg_launch_gen(VOID)
{
    if (snt_vda_sz <= 0 || modmb == NULL) return;

    setmbk(modmb);
    fsdroom(SNTCFG_GEN, gen_fsp, 1);

    sprintf(vdatmp, gen_fmt,
            proxy_trust_enabled ? "YES" : "NO", '\0',
            proxy_block_enabled ? "YES" : "NO", '\0',
            conn_limit_enabled  ? "YES" : "NO", '\0',
            conn_limit_max,                      '\0',
            log_enabled         ? "YES" : "NO", '\0',
            usrip_enabled       ? "YES" : "NO", '\0',
            usrip_field,                         '\0',
            bypass_key[0] ? bypass_key : "",    '\0');

    fsdapr(vdaptr, snt_vda_sz, vdatmp);
    fsdbkg(fsdrft());
    fsdego(vfyadn, cfg_gen_done);
    rstmbk();
}

/*
 * cfg_gen_done
 *
 * FSE whndun callback for the General Settings form.  Applies all field
 * values to live variables and persists to SNTIPCTL.DAT.  Restores the
 * top-level config menu regardless of save/quit.
 */
static VOID
cfg_gen_done(SHORT save)
{
    CHAR buf[20];
    INT  ord;
    CHAR saved_scnbrk = 0;
    GBOOL pager_saved = FALSE;

    /*
     * Suppress pager for the save message and menu redisplay.
     * rstrxf() must be called after setting scnbrk to override the state
     * left by fsdcof()->rstrxf() which fired before this callback.
     */
    if (usaptr != NULL) {
        saved_scnbrk = usaptr->scnbrk;
        usaptr->scnbrk = CTNUOS;
        rstrxf();
        pager_saved = TRUE;
    }

    if (save && fsdscb->chgcnt > 0) {
        ord = fsdord(GEN_PRXTRU);
        proxy_trust_enabled = (ord == 1) ? TRUE : FALSE;

        ord = fsdord(GEN_PRXBLK);
        proxy_block_enabled = (ord == 1) ? TRUE : FALSE;

        ord = fsdord(GEN_CONLIM);
        conn_limit_enabled = (ord == 1) ? TRUE : FALSE;

        fsdfxt(GEN_MAXCON, buf, sizeof(buf));
        { INT v = atoi(buf); if (v >= 1 && v <= 1000) conn_limit_max = v; }

        ord = fsdord(GEN_LOGON);
        if (!log_enabled && ord == 1) {
            CreateDirectoryA("TOTALIPCONTROL", NULL);
            CreateDirectoryA("TOTALIPCONTROL\\PROXCLIP LOGS", NULL);
            CreateDirectoryA("TOTALIPCONTROL\\DENIED CONNECTIONS", NULL);
            CreateDirectoryA("TOTALIPCONTROL\\DENIED MODULE ACCESS", NULL);
        }
        log_enabled = (ord == 1) ? TRUE : FALSE;

        ord = fsdord(GEN_UIPON);
        usrip_enabled = (ord == 1) ? TRUE : FALSE;

        fsdfxt(GEN_UIPFLD, buf, sizeof(buf));
        { INT v = atoi(buf); if (v >= 1 && v <= 5) usrip_field = v; }

        fsdfxt(GEN_BYPKEY, bypass_key, sizeof(bypass_key));
        strupr(bypass_key);

        cfg_save();
        if (modmb != NULL) {
            setmbk(modmb);
            prfmsg(CFGSAV);
            rstmbk();
        }
    }

    if (modmb != NULL) {
        setmbk(modmb);
        cfg_show_topmenu();
        rstmbk();
    }

    usrptr->state  = cfgstt;
    usrptr->substt = CFGSTT_MENU;

    /*
     * Swallow the spurious empty/"/" sttrou call(s) MBBS delivers right after
     * an FSE session ends, so the save confirmation + menu are not re-rendered
     * (which looked like a duplicate "Settings saved" screen).
     */
    if (usrnum >= 0 && usrnum < MAXNTERM)
        absorb_count[usrnum] = 2;

    if (pager_saved) {
        usaptr->scnbrk = saved_scnbrk;
        rstrxf();   /* restore pager to user's normal screen length */
    }
}

/*
 * cfg_prx_vfy
 *
 * FSE field verify callback for the Trusted Proxy CIDR form.
 * Validates CIDR syntax on each PRX field; delegates DONE to vfyadn.
 * Blank input is accepted (clears the slot).
 */
static INT
cfg_prx_vfy(INT fldno, CHAR *answer)
{
    struct snt_cidr tmp;
    if (fldno == PRX_DONE) return vfyadn(fldno, answer);
    if (*answer == '\0') return VFYOK;
    if (!parse_cidr(answer, &tmp)) {
        fsdouc('\7');
        return VFYREJ;
    }
    return VFYOK;
}

/*
 * cfg_launch_prx
 *
 * Starts a full-screen FSE session for the Trusted Proxy CIDR form.
 */
static VOID
cfg_launch_prx(VOID)
{
    CHAR p1[20], p2[20];

    if (snt_vda_sz <= 0 || modmb == NULL) return;

    cidr_for_fse(&trusted_proxy_cidrs[0], p1, sizeof(p1));
    cidr_for_fse(&trusted_proxy_cidrs[1], p2, sizeof(p2));

    setmbk(modmb);
    fsdroom(SNTCFG_PRX, prx_fsp, 1);
    sprintf(vdatmp, prx_fmt,
            p1, '\0', p2, '\0');
    fsdapr(vdaptr, snt_vda_sz, vdatmp);
    fsdbkg(fsdrft());
    fsdego(cfg_prx_vfy, cfg_prx_done);
    rstmbk();
}

/*
 * cfg_prx_done
 *
 * FSE whndun callback for the Trusted Proxy CIDR form.
 */
static VOID
cfg_prx_done(SHORT save)
{
    CHAR buf[24];
    INT  i;
    CHAR saved_scnbrk = 0;
    GBOOL pager_saved = FALSE;

    if (usaptr != NULL) {
        saved_scnbrk = usaptr->scnbrk;
        usaptr->scnbrk = CTNUOS;
        rstrxf();
        pager_saved = TRUE;
    }

    if (save && fsdscb->chgcnt > 0) {
        for (i = 0; i < SNTIPCTL_MAX_TRUSTED; i++) {
            fsdfxt(i, buf, sizeof(buf));
            if (*buf == '\0') {
                trusted_proxy_cidrs[i].addr = 0;
                trusted_proxy_cidrs[i].mask = 0;
            } else {
                parse_cidr(buf, &trusted_proxy_cidrs[i]);
            }
        }
        trusted_proxy_count = 0;
        for (i = 0; i < SNTIPCTL_MAX_TRUSTED; i++)
            if (trusted_proxy_cidrs[i].addr != 0 || trusted_proxy_cidrs[i].mask != 0)
                trusted_proxy_count++;
        cfg_save();
        if (modmb != NULL) {
            setmbk(modmb);
            prfmsg(CFGSAV);
            rstmbk();
        }
    }

    if (modmb != NULL) {
        setmbk(modmb);
        cfg_show_topmenu();
        rstmbk();
    }

    usrptr->state  = cfgstt;
    usrptr->substt = CFGSTT_MENU;

    /* Absorb the spurious post-FSE sttrou call(s) -- see cfg_gen_done. */
    if (usrnum >= 0 && usrnum < MAXNTERM)
        absorb_count[usrnum] = 2;

    if (pager_saved) {
        usaptr->scnbrk = saved_scnbrk;
        rstrxf();
    }
}

/*
 * cfg_wl1_vfy
 *
 * FSE field verify callback for the whitelist form.
 * Validates CIDR syntax on each WL field; delegates DONE to vfyadn.
 * Blank input is accepted (clears the slot).
 */
static INT
cfg_wl1_vfy(INT fldno, CHAR *answer)
{
    struct snt_cidr tmp;
    if (fldno == WL_DONE) return vfyadn(fldno, answer);
    if (*answer == '\0') return VFYOK;
    if (!parse_cidr(answer, &tmp)) { fsdouc('\7'); return VFYREJ; }
    return VFYOK;
}

/* Return to top-level config menu and restore sttrou state. */
static VOID
cfg_return_to_menu(VOID)
{
    if (modmb != NULL) { setmbk(modmb); cfg_show_topmenu(); rstmbk(); }
    usrptr->state  = cfgstt;
    usrptr->substt = CFGSTT_MENU;
    /* Absorb the spurious post-FSE sttrou call(s) -- see cfg_gen_done. */
    if (usrnum >= 0 && usrnum < MAXNTERM)
        absorb_count[usrnum] = 2;
}

/*
 * cfg_launch_wl1
 *
 * Launches the whitelist FSE form (10 slots, single page), pre-filled from
 * the current whitelist_cidrs[].
 */
static VOID
cfg_launch_wl1(VOID)
{
    CHAR s[10][20];
    INT  i;

    if (snt_vda_sz <= 0 || modmb == NULL) return;
    for (i = 0; i < SNTIPCTL_MAX_WHITELIST; i++)
        cidr_for_fse(&whitelist_cidrs[i], s[i], sizeof(s[i]));

    setmbk(modmb);
    fsdroom(SNTCFG_WL, wl1_fsp, 1);
    sprintf(vdatmp, wl1_fmt,
            s[0],'\0', s[1],'\0', s[2],'\0', s[3],'\0', s[4],'\0',
            s[5],'\0', s[6],'\0', s[7],'\0', s[8],'\0', s[9],'\0');
    fsdapr(vdaptr, snt_vda_sz, vdatmp);
    fsdbkg(fsdrft());
    fsdego(cfg_wl1_vfy, cfg_wl1_done);
    rstmbk();
}

/*
 * cfg_wl1_done
 *
 * FSE whndun callback for the whitelist form.  Applies all 10 field values
 * to whitelist_cidrs[] and persists to SNTIPCTL.DAT.
 */
static VOID
cfg_wl1_done(SHORT save)
{
    CHAR buf[24];
    INT  i;
    CHAR saved_scnbrk = 0;
    GBOOL pager_saved = FALSE;

    if (usaptr != NULL) {
        saved_scnbrk = usaptr->scnbrk;
        usaptr->scnbrk = CTNUOS;
        rstrxf();
        pager_saved = TRUE;
    }

    if (save && fsdscb->chgcnt > 0) {
        for (i = 0; i < SNTIPCTL_MAX_WHITELIST; i++) {
            fsdfxt(i, buf, sizeof(buf));
            if (*buf == '\0') {
                whitelist_cidrs[i].addr = 0;
                whitelist_cidrs[i].mask = 0;
            } else {
                parse_cidr(buf, &whitelist_cidrs[i]);
            }
        }
        cfg_save();
        if (modmb != NULL) { setmbk(modmb); prfmsg(CFGSAV); rstmbk(); }
    }

    cfg_return_to_menu();

    if (pager_saved) {
        usaptr->scnbrk = saved_scnbrk;
        rstrxf();
    }
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
    sntcfg.version     = 7;
    sntcfg.proxy_trust = proxy_trust_enabled ? 'Y' : 'N';
    sntcfg.proxy_block = proxy_block_enabled ? 'Y' : 'N';
    for (i = 0; i < SNTIPCTL_MAX_TRUSTED; i++)
        sntcfg.proxy_cidrs[i] = trusted_proxy_cidrs[i];
    sntcfg.conn_limit  = conn_limit_enabled ? 'Y' : 'N';
    sntcfg.conn_max    = conn_limit_max;
    sntcfg.log_on      = log_enabled    ? 'Y' : 'N';
    sntcfg.usrip_on    = usrip_enabled  ? 'Y' : 'N';
    sntcfg.usrip_fld   = usrip_field;
    stzcpy(sntcfg.bypass_key, bypass_key, sizeof(sntcfg.bypass_key));
    for (i = 0; i < SNTIPCTL_MAX_WHITELIST; i++)
        sntcfg.whitelist[i] = whitelist_cidrs[i];
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
    for (i = 0; i < SNTIPCTL_MAX_TRUSTED; i++)
        trusted_proxy_cidrs[i] = sntcfg.proxy_cidrs[i];
    conn_limit_enabled = (sntcfg.conn_limit == 'Y') ? TRUE : FALSE;
    if (sntcfg.conn_max >= 1 && sntcfg.conn_max <= 1000)
        conn_limit_max = sntcfg.conn_max;
    log_enabled   = (sntcfg.log_on   == 'Y') ? TRUE : FALSE;
    usrip_enabled = (sntcfg.usrip_on == 'Y') ? TRUE : FALSE;
    if (sntcfg.usrip_fld >= 1 && sntcfg.usrip_fld <= 5)
        usrip_field = sntcfg.usrip_fld;
    stzcpy(bypass_key, sntcfg.bypass_key, sizeof(bypass_key));
    for (i = 0; i < SNTIPCTL_MAX_WHITELIST; i++)
        whitelist_cidrs[i] = sntcfg.whitelist[i];

    trusted_proxy_count = 0;
    for (i = 0; i < SNTIPCTL_MAX_TRUSTED; i++)
        if (trusted_proxy_cidrs[i].addr != 0 || trusted_proxy_cidrs[i].mask != 0)
            trusted_proxy_count++;
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
    if (dfaAcqEQ(&key, &key, 0))
        dfaUpdateV(&sntcfg, (USHORT)sizeof(sntcfg));
    else
        dfaInsertV(&sntcfg, (USHORT)sizeof(sntcfg));
    dfaRstBlk();

    shocst("Total IP Control", "settings saved to SNTIPCTL.DAT");
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
        if (sntcfg.version == 7) {
            cfg_struct_to_live();
            shocst("Total IP Control", "settings loaded from SNTIPCTL.DAT");
        } else {
            /*
             * Record exists but was written by an older build with a different
             * struct layout.  Delete it and insert fresh defaults.
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
 * sntipctl_gbl
 *
 * Global command handler.  Registered via globalcmd() and called for every
 * user input on every channel.  Returns 1 if the command was consumed, 0 to
 * pass the input through to normal BBS processing.
 *
 * Trigger:  /TOTALIP  (Master access required)
 */
static INT
sntipctl_gbl(VOID)
{
    if (!margc) return 0;
    if (!sameas(margv[0], "/TOTALIP")) return 0;

    if (modmb == NULL) {
        shocst("Total IP Control", "ERROR: /TOTALIP unavailable -- run GCNF to generate SNTIPCTL.MCV then restart");
        return 1;
    }

    setmbk(modmb);

    /*
     * Verify the MCV was compiled from the current MSG file.
     * If CFGHED (slot 2) is missing, the MCV is stale -- redeploy
     * SNTIPCTL.MSG to the BBS directory and rerun GCNF.
     */
    if (rawmsg(CFGHED) == NULL) {
        rstmbk();
        shocst("Total IP Control",
               "ERROR: /TOTALIP unavailable -- SNTIPCTL.MCV is stale. "
               "Redeploy SNTIPCTL.MSG and rerun GCNF, then restart the BBS.");
        return 1;
    }

    if (!(usrptr->flags & MASTER)) {
        prfmsg(CFGDNY);
        outprf(usrnum);
        rstmbk();
        return 1;
    }

    usrptr->state  = cfgstt;
    usrptr->substt = CFGSTT_MENU;

    /* Turn the output pager off for the whole editor session (restored on X/Q). */
    editor_pager_suppress();

    /*
     * Display the menu immediately so there is no visible delay.
     * MBBS then calls sttrou 1-2 more times with "/" or "" before waiting
     * for real user input.  absorb_count causes sttrou to swallow those
     * spurious "/" and "" calls so the menu is not re-rendered.
     */
    cfg_show_topmenu();
    if (usrnum >= 0 && usrnum < MAXNTERM)
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
/*   Examples:                                                               */
/*     MODULE=LORD MAXIP=3                                                   */
/*     MODULE=TRADEWARS MAXIP=2 BYPASS=SYSOP,COSYSOP                        */
/* ======================================================================== */

#define GW_BYPASS_DEFAULT  "SYSOP"
#define GW_BYPASS_MAXSIZ   128

/*
 * parse_gateway_config
 *
 * Extracts MODULE, MAXIP, and BYPASS from the BBS menu command string held
 * in margv[].  When the BBS enters a module via a menu item, margv[0] has
 * the menu select character prepended to the first token, so it is skipped
 * on the first iteration only.  Module names may contain spaces; a second
 * pass accumulates additional tokens until a known keyword is found.
 */
static VOID
parse_gateway_config(CHAR *modname, INT modnamsiz, INT *maxip,
                     CHAR *bypass, INT bypasssiz)
{
    INT   i, modname_start = -1, curlen;
    CHAR  tmp[INPSIZ];
    CHAR *tok, *eq, *key, *val;

    modname[0] = '\0';
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
                if (sameas(tmp, "MAXIP") || sameas(tmp, "BYPASS"))
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
        if (*tok != '\0' && haskey(tok))
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
 * channel.
 */
static INT
count_ip_in_mod(ULONG user_ip, INT target_state)
{
    INT i, count = 0;
    for (i = 0; i < hichp1; i++) {
        if (i == usrnum)                                    continue;
        if (usroff(i)->usrcls != ACTUSR)                    continue;
        if (usroff(i)->state  != target_state)              continue;
        if ((*pp_tcpipinf)[i].inaddr.s_addr != user_ip)    continue;
        count++;
    }
    return count;
}

/*
 * build_ip_in_mod_users
 *
 * Builds a comma-separated list of userids for all active sessions from
 * user_ip that are currently inside the module identified by target_state,
 * excluding the current channel.  Used in gateway denial messages and logs
 * so the Sysop and blocked user can see who is already occupying the slots.
 *
 * buf is filled with "(unknown)" if no qualifying sessions are found.
 */
static VOID
build_ip_in_mod_users(ULONG user_ip, INT target_state, CHAR *buf, INT bufsiz)
{
    INT            i;
    struct usracc *uap;

    buf[0] = '\0';
    for (i = 0; i < hichp1; i++) {
        if (i == usrnum)                                    continue;
        if (usroff(i)->usrcls != ACTUSR)                    continue;
        if (usroff(i)->state  != target_state)              continue;
        if ((*pp_tcpipinf)[i].inaddr.s_addr != user_ip)    continue;
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
 * build_active_ip_users
 *
 * Like build_ip_in_mod_users() but scans ALL active sessions regardless of
 * module/state.  Used by sntipctl_logon() to tell a rejected user who else
 * is logged in from their IP address.
 */
static VOID
build_active_ip_users(ULONG user_ip, CHAR *buf, INT bufsiz)
{
    INT            i;
    struct usracc *uap;

    buf[0] = '\0';
    for (i = 0; i < hichp1; i++) {
        if (i == usrnum)                                    continue;
        if (usroff(i)->usrcls != ACTUSR)                    continue;
        if ((*pp_tcpipinf)[i].inaddr.s_addr != user_ip)    continue;
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
    INT   maxip, modnum, ipcount;
    ULONG user_ip;

    if (modmb == NULL) {
        shocst("Total IP Control", "ERROR: gateway unavailable -- run GCNF to generate SNTIPCTL.MCV then restart");
        return 0;
    }

    setmbk(modmb);

    parse_gateway_config(modname, sizeof(modname), &maxip, bypass, sizeof(bypass));

    if (modname[0] == '\0') {
        shocst("Total IP Control", "WARNING: gateway menu entry missing MODULE= parameter");
        rstmbk();
        return 0;
    }

    modnum = findmod(modname);
    if (modnum < 0) {
        shocst("Total IP Control", spr("WARNING: gateway target module '%s' not found", modname));
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

    user_ip = (*pp_tcpipinf)[usrnum].inaddr.s_addr;
    ipcount = count_ip_in_mod(user_ip, modnum);

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
        CHAR usrbuf[256];
        build_ip_in_mod_users(user_ip, modnum, usrbuf, sizeof(usrbuf));

        if (log_enabled) {
            sntipctl_log_event("DENIED MODULE ACCESS",
                (usaptr != NULL && usaptr->userid[0] != '\0') ? usaptr->userid : "(unknown)",
                user_ip,
                spr("Gateway limit exceeded for module %s (%d active, max %d) -- denied; active users: %s",
                    modname, ipcount, maxip, usrbuf));
        }

        prfmsg(IPGDNY, maxip, usrbuf);
        outprf(usrnum);
    }
    rstmbk();
    return 0;
}

/*
 * sntipctl_stt
 *
 * State-input routine (sttrou).  Called by the BBS when usrptr->state ==
 * cfgstt.  substt == 0 means entered from a BBS menu item (gateway); all
 * other sub-states are the online config editor.
 *
 * The config editor shows a simple top-level menu.  Selecting 1/2/3 launches
 * an FSE full-screen form; X exits.  FSE sessions are self-contained
 * -- their done callbacks restore state and re-display this menu.
 */
static GBOOL
sntipctl_stt(VOID)
{
    CHAR *inp;

    /* substt == 0: entered from a BBS menu item -- run gateway logic. */
    if (usrptr->substt == 0)
        return sntipctl_gateway();

    switch (usrptr->substt) {

    case CFGSTT_MENU:
        /*
         * Absorb spurious "/" and empty inputs MBBS delivers immediately after
         * globalcmd returns 1.  Only "/" and empty are swallowed; real user
         * keystrokes ("1", "X", etc.) bypass the counter so they are not lost.
         */
        if (usrnum >= 0 && usrnum < MAXNTERM && absorb_count[usrnum] > 0) {
            GBOOL spurious = (!margc || margv[0] == NULL ||
                              *margv[0] == '\0' || *margv[0] == '/');
            if (spurious) {
                absorb_count[usrnum]--;
                return 1;
            }
            absorb_count[usrnum] = 0;  /* real input: stop absorbing, fall through */
        }

        if (!margc || margv[0] == NULL || *margv[0] == '\0') {
            /* Empty input: user pressed Enter to re-display the menu. */
            if (modmb != NULL) {
                setmbk(modmb);
                cfg_show_topmenu();
                rstmbk();
            }
            return 1;
        }
        inp = margv[0];

        if (sameas(inp, "X") || sameas(inp, "Q")) {
            editor_pager_restore();   /* re-enable the normal output pager */
            condex();
            return 0;
        }

        if (sameas(inp, "1")) { cfg_launch_gen(); outprf(usrnum); return 1; }
        if (sameas(inp, "2")) { cfg_launch_prx(); outprf(usrnum); return 1; }
        if (sameas(inp, "3")) { cfg_launch_wl1(); outprf(usrnum); return 1; }

        if (modmb != NULL) {
            setmbk(modmb);
            prfmsg(CFGBAD);
            cfg_show_topmenu();
            rstmbk();
        }
        return 1;
    }

    return 1;
}
