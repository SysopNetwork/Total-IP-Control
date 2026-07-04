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
#include <winhttp.h>        /* outbound HTTPS/HTTP for GeoIP lookups          */
#include <process.h>        /* _beginthreadex for the GeoIP worker thread    */

#include "gcomm.h"
#include "majorbbs.h"
#include "tcpip.h"
#include "SNTIPCTL.H"

#include <stdio.h>
#include <string.h>
#include "dfaapi.h"
#include "fsdbbs.h"

/* Link the WinHTTP client library (also listed in the .vcxproj for clarity). */
#pragma comment(lib, "winhttp.lib")

#define SNTIPCTL_VERSION "v1.1.0"

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
 * GeoIP Location form field specification.  PROVIDER is a MULTICHOICE listing
 * the available providers; only ipwho.is is implemented in v1.1.0, so it is
 * the sole choice for now.  Adding a provider = add an ALT here (and a case in
 * geo_build_url()/geo_parse_body()).  LOGLVL maps 0..3 to OFF/ERRORS/NORMAL/
 * VERBOSE.  Field ordering must match the GEO_* #defines in SNTIPCTL.H.
 */
static CHAR geo_fsp[] =
    "ENABLE(ALT=NO ALT=YES MULTICHOICE) "
    "WRITEMODE(ALT=COMBINED ALT=SPLIT MULTICHOICE) "
    "FIELD(MIN=1 MAX=5) "
    "CTYFLD(MIN=1 MAX=5) "
    "CTYFMT(ALT=FULL ALT=CODE MULTICHOICE) "
    "PROVIDER(ALT=IPWHO.IS ALT=IP-API.COM ALT=IPAPI.CO MULTICHOICE) "
    "HOST "
    "KEY "
    "HTTPS(ALT=YES ALT=NO MULTICHOICE) "
    "TIMEOUT(MIN=1 MAX=60) "
    "CACHE(ALT=OFF ALT=TIME ALT=IP MULTICHOICE) "
    "CACHEDUR(MIN=1 MAX=44640) "
    "RETRY(MIN=0 MAX=5) "
    "LOGLVL(ALT=OFF ALT=ERRORS ALT=NORMAL ALT=VERBOSE MULTICHOICE) "
    "FORMAT "
    "DONE(ALT=SAVE ALT=QUIT MULTICHOICE)";

static CHAR geo_fmt[] =
    "ENABLE=%s%c" "WRITEMODE=%s%c" "FIELD=%d%c" "CTYFLD=%d%c" "CTYFMT=%s%c"
    "PROVIDER=%s%c" "HOST=%s%c" "KEY=%s%c" "HTTPS=%s%c" "TIMEOUT=%d%c"
    "CACHE=%s%c" "CACHEDUR=%d%c" "RETRY=%d%c" "LOGLVL=%s%c" "FORMAT=%s%c";

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
 * version == 9 identifies this layout (v8 added the GeoIP block; v9 added the
 * split write-mode / country field / country format / cache-mode flag).
 * Field sizes:
 *   original v7 core .......... 142 bytes
 *   GeoIP block (v8) .......... 213 bytes
 *   GeoIP split block (v9) ....   7 bytes
 *   spare ..................... 150 bytes
 *   total ..................... 512 bytes
 */
#pragma pack(push, 1)
struct sntipctlcfg {
    CHAR            recid[16];                      /* key: "SNTIPCTL"         */
    CHAR            version;                        /* struct version (9)      */
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

    CHAR            spare[150];                     /* pad to 512 bytes        */
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
static GBOOL      gw_other_has_bypass_key(INT channel, const CHAR *bypass);
static INT        count_ip_in_mod(ULONG user_ip, INT target_state, const CHAR *bypass);
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

/* ---- GeoIP Location subsystem ---- */
struct geo_loc;                                      /* defined below              */
static VOID  geoip_start(VOID);
static VOID  geoip_stop(VOID);
static VOID  geoip_enqueue(INT channel, ULONG ip, const CHAR *userid);
static VOID  geoip_drain(VOID);                      /* rtkick target, main thread */
static unsigned __stdcall geoip_worker(VOID *arg);   /* background thread          */
static GBOOL geoip_http_get(const CHAR *host, const CHAR *path, GBOOL https,
                            INT timeout_s, CHAR *body, INT bodysz, INT *status);
static VOID  geoip_build_url(INT provider, ULONG ip, CHAR *host, INT hostsz,
                             CHAR *path, INT pathsz);
static GBOOL geoip_parse_body(INT provider, const CHAR *body, struct geo_loc *out);
static VOID  geo_format(const CHAR *fmt, const struct geo_loc *L, GBOOL inc_country,
                        CHAR *out, INT outsz);
static GBOOL geo_set_field(struct usracc *ua, INT fieldnum, const CHAR *val);
static VOID  geoip_apply(INT channel, const CHAR *userid, const struct geo_loc *L);
static VOID  geoip_log(INT level, const CHAR *userid, ULONG ip, const CHAR *event);
static GBOOL geo_cache_lookup(ULONG ip, struct geo_loc *out);
static VOID  geo_cache_store(ULONG ip, const struct geo_loc *L);
static GBOOL is_private_ip(ULONG ip);
static GBOOL json_get_str(const CHAR *body, const CHAR *key, CHAR *out, INT outsz);
static GBOOL json_get_bool_true(const CHAR *body, const CHAR *key);
static VOID  cfg_launch_geo(VOID);
static VOID  cfg_geo_done(SHORT save);
static INT   cfg_geo_vfy(INT fldno, CHAR *answer);

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
        shocst("Total IP Control", "WARNING: SNTIPCTL.MCV not found -- ensure SNTIPCTL.MSG is installed in the BBS directory");

    /*
     * Declare per-user VDA space for FSE config editor sessions.
     * fsdroom() sizes each form; we allocate max of the three so a single
     * vdaptr region covers whichever form the Sysop opens.
     */
    if (modmb != NULL) {
        INT r1, r2, r3, r4;
        setmbk(modmb);
        r1 = fsdroom(SNTCFG_GEN, gen_fsp, 0);
        r2 = fsdroom(SNTCFG_PRX, prx_fsp, 0);
        r3 = fsdroom(SNTCFG_WL,  wl1_fsp, 0);
        r4 = fsdroom(SNTCFG_GEO, geo_fsp, 0);
        rstmbk();
        snt_vda_sz = r1;
        if (r2 > snt_vda_sz) snt_vda_sz = r2;
        if (r3 > snt_vda_sz) snt_vda_sz = r3;
        if (r4 > snt_vda_sz) snt_vda_sz = r4;
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

    /* GeoIP Location defaults -- disabled, ipwho.is, 24h cache.
     * Default write mode is SPLIT: city/state -> Address 3, country -> Address 4. */
    geoip_enabled   = FALSE;
    geoip_field     = 3;
    geoip_split     = TRUE;
    geoip_cty_field = 4;
    geoip_cty_fmt   = GEOCF_FULL;
    geoip_provider  = GEOPRV_IPWHOIS;
    geoip_use_https = TRUE;
    geoip_timeout   = 5;
    geoip_cache_on     = TRUE;
    geoip_cache_bytime = TRUE;
    geoip_cache_min = 1440;
    geoip_retries   = 1;
    geoip_loglevel  = GEOLOG_NORMAL;
    stzcpy(geoip_host,   "ipwho.is",                    sizeof(geoip_host));
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

    if (log_enabled) {
        /* Create the log directory tree if it does not already exist. */
        CreateDirectoryA("TOTALIPCONTROL", NULL);
        CreateDirectoryA("TOTALIPCONTROL\\PROXCLIP LOGS", NULL);
        CreateDirectoryA("TOTALIPCONTROL\\DENIED CONNECTIONS", NULL);
        CreateDirectoryA("TOTALIPCONTROL\\DENIED MODULE ACCESS", NULL);
    }

    /* GeoIP logging has its own verbosity switch and its own log folder. */
    if (geoip_loglevel != GEOLOG_OFF) {
        CreateDirectoryA("TOTALIPCONTROL", NULL);
        CreateDirectoryA("TOTALIPCONTROL\\GEOIP LOGS", NULL);
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
    if (geoip_enabled)
        shocst("Total IP Control", spr("GeoIP location lookups enabled (host %s, profile field %d)",
                                       geoip_host[0] ? geoip_host : "ipwho.is", geoip_field));

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

    /*
     * Start the GeoIP background worker + result-drain rtkick.  The
     * infrastructure is always created (it is idle and cheap when the feature
     * is off); actual lookups only occur when geoip_enabled is set.
     */
    geoip_start();

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
    /*
     * Stop the GeoIP worker FIRST and join it, so the thread cannot still be
     * running (and touching module state) while the DLL is unloaded.
     */
    geoip_stop();

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
    CHAR region[64];          /* US 2-letter state code, or full subdivision */
    CHAR country[64];         /* full country name                          */
    CHAR ccode[8];            /* two-letter ISO country code                */
};

/* Snapshot of everything the worker needs -- no BBS globals are referenced. */
struct geo_req {
    INT   channel;              /* originating channel (for result apply)   */
    ULONG ip;                   /* source IP (network byte order)           */
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
    ULONG          ip;
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
    ULONG          ip;         /* 0 = empty slot                            */
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
is_private_ip(ULONG ip)
{
    unsigned char *b = (unsigned char *)&ip;
    if (ip == 0) return TRUE;
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
geoip_log(INT level, const CHAR *userid, ULONG ip, const CHAR *event)
{
    SYSTEMTIME     st;
    CHAR           logpath[MAX_PATH];
    CHAR           line[512];
    CHAR           ipbuf[20];
    FILE          *fp;
    unsigned char *b;

    if (geoip_loglevel == GEOLOG_OFF || level > geoip_loglevel) return;

    GetLocalTime(&st);
    build_log_path("GEOIP LOGS", logpath, sizeof(logpath));

    b = (unsigned char *)&ip;
    _snprintf(ipbuf, sizeof(ipbuf), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);

    _snprintf(line, sizeof(line),
              "%04d-%02d-%02d %02d:%02d:%02d  %-20s  %-15s  %s\n",
              st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
              (userid != NULL && userid[0] != '\0') ? userid : "(geoip)",
              ipbuf, event != NULL ? event : "");

    EnterCriticalSection(&log_cs);
    fp = fopen(logpath, "a");
    if (fp != NULL) { fputs(line, fp); fclose(fp); }
    LeaveCriticalSection(&log_cs);
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
static VOID
geoip_build_url(INT provider, ULONG ip, CHAR *host, INT hostsz, CHAR *path, INT pathsz)
{
    CHAR           ipbuf[20];
    unsigned char *b = (unsigned char *)&ip;

    _snprintf(ipbuf, sizeof(ipbuf), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);

    /* Host: sysop override wins; otherwise the provider's default host. */
    if (geoip_host[0] != '\0') {
        stzcpy(host, geoip_host, hostsz);
    } else {
        switch (provider) {
        case GEOPRV_IPAPI:   stzcpy(host, "ip-api.com", hostsz); break;
        case GEOPRV_IPAPICO: stzcpy(host, "ipapi.co",   hostsz); break;
        default:             stzcpy(host, "ipwho.is",   hostsz); break;
        }
    }

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
    default: /* GEOPRV_IPWHOIS */
        if (geoip_key[0] != '\0')
            _snprintf(path, pathsz, "/%s?key=%s", ipbuf, geoip_key);
        else
            _snprintf(path, pathsz, "/%s", ipbuf);
        break;
    }
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
    default: /* GEOPRV_IPWHOIS */
        if (!json_get_bool_true(body, "success")) return FALSE;
        json_get_str(body, "city",         out->city,    sizeof(out->city));
        json_get_str(body, "region_code",  regcode,      sizeof(regcode));
        json_get_str(body, "region",       regfull,      sizeof(regfull));
        json_get_str(body, "country_code", out->ccode,   sizeof(out->ccode));
        json_get_str(body, "country",      out->country, sizeof(out->country));
        break;
    }

    /* US -> two-letter state code; elsewhere -> full subdivision name. */
    if (_stricmp(out->ccode, "US") == 0 && regcode[0] != '\0')
        stzcpy(out->region, regcode, sizeof(out->region));
    else if (regfull[0] != '\0')
        stzcpy(out->region, regfull, sizeof(out->region));
    else
        stzcpy(out->region, regcode, sizeof(out->region));

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
            r.ip      = q.ip;
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
geo_cache_lookup(ULONG ip, struct geo_loc *out)
{
    INT       i;
    ULONGLONG now = GetTickCount64();
    if (ip == 0) return FALSE;
    for (i = 0; i < GEO_CACHE_MAX; i++) {
        if (geo_cache[i].ip == ip && geo_cache[i].expiry > now) {
            *out = geo_cache[i].loc;
            return TRUE;
        }
    }
    return FALSE;
}

static VOID
geo_cache_store(ULONG ip, const struct geo_loc *L)
{
    INT       i, slot = -1;
    ULONGLONG now = GetTickCount64();
    ULONGLONG ttl = (ULONGLONG)(geoip_cache_min > 0 ? geoip_cache_min : 1440) * 60000ULL;

    if (ip == 0) return;
    for (i = 0; i < GEO_CACHE_MAX; i++)          /* reuse existing entry      */
        if (geo_cache[i].ip == ip) { slot = i; break; }
    if (slot < 0)                                 /* else an empty/expired one */
        for (i = 0; i < GEO_CACHE_MAX; i++)
            if (geo_cache[i].ip == 0 || geo_cache[i].expiry <= now) { slot = i; break; }
    if (slot < 0) {                               /* else round-robin evict    */
        slot = geo_cache_next;
        geo_cache_next = (geo_cache_next + 1) % GEO_CACHE_MAX;
    }
    geo_cache[slot].ip     = ip;
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

    if (geoip_split) {
        const CHAR *country = (geoip_cty_fmt == GEOCF_CODE) ? L->ccode : L->country;
        geo_format(geoip_format, L, FALSE, primary, sizeof(primary));   /* City, State */
        changed |= geo_set_field(ua, geoip_field, primary);
        /* Only write the country separately when it targets a different field
         * (guards against a misconfiguration that would clobber city/state). */
        if (geoip_cty_field != geoip_field)
            changed |= geo_set_field(ua, geoip_cty_field, country);
    } else {
        geo_format(geoip_format, L, TRUE, primary, sizeof(primary));    /* City, State, Country */
        changed |= geo_set_field(ua, geoip_field, primary);
    }

    if (!changed) return;                         /* nothing new -- no write   */
    updaccu(ua);                                  /* persist without curusr()  */

    {
        CHAR  evt[160];
        ULONG ip = (pp_tcpipinf != NULL) ? (*pp_tcpipinf)[channel].inaddr.s_addr : 0;
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
geoip_enqueue(INT channel, ULONG ip, const CHAR *userid)
{
    struct geo_req q;
    struct geo_loc loc;

    if (!geoip_enabled || !geo_started) return;

    if (ip == 0 || ip == (ULONG)INADDR_NONE || is_private_ip(ip)) {
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
    q.ip       = ip;
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
 * Displays the config editor header, an optional one-line banner (0 for none,
 * e.g. CFGSAV after a save or CFGBAD after bad input), and the top-level menu.
 * Caller must have setmbk(modmb) in effect.  Flushes output to the user.
 *
 * The banner is printed AFTER the header (which clears the screen) so it is not
 * wiped, and appears cleanly above the menu instead of flashing separately.
 *
 * scnbrk is (re-)asserted to CTNUOS here but deliberately NOT restored -- the
 * editor keeps continuous output for its whole session (restored only on exit
 * via editor_pager_restore), so this menu's asynchronously transmitted output
 * can never re-arm the "(N)onstop,Q,C?" pager.
 */
static VOID
cfg_show_topmenu(INT banner)
{
    CHAR  saved_scnbrk = 0;
    GBOOL pager_saved = FALSE;

    /*
     * Suppress paging around this output.  Because the editor session already
     * holds scnbrk at CTNUOS (editor_pager_suppress), the value saved here is
     * itself CTNUOS, so the restore is effectively a no-op that keeps the pager
     * off -- the menu's output never raises a "(N)onstop,Q,C?" prompt.
     */
    if (usaptr != NULL) {
        saved_scnbrk = usaptr->scnbrk;
        usaptr->scnbrk = CTNUOS;
        rstrxf();
        pager_saved = TRUE;
    }

    prfmsg(CFGHED);
    if (banner != 0)
        prfmsg(banner);          /* one-line status ABOVE the menu (post-clear)*/
    prfmsg(CFGMNU);
    outprf(usrnum);

    if (pager_saved) {
        /*
         * Menu output is transmitted asynchronously by the poll loop, so scnbrk
         * must stay continuous until it drains.  While the editor session owns
         * the pager (editor_pager_off), pin it to CTNUOS rather than restoring a
         * value the FSD teardown may have left paged -- otherwise the async menu
         * output could still raise the "(N)onstop,Q,C?" prompt.  editor_pager_restore()
         * puts the user's real screen length back when they leave the editor.
         */
        GBOOL in_editor = (usrnum >= 0 && usrnum < MAXNTERM && editor_pager_off[usrnum]);
        usaptr->scnbrk = in_editor ? CTNUOS : saved_scnbrk;
        rstrxf();
    }
}

/*
 * cfg_finish_form
 *
 * Common tail for every FSE whndun callback: redraw the top menu (with an
 * optional "settings saved" banner) and return the editor to the menu state.
 * MBBS does not reliably re-enter sttrou on its own after a form closes, so the
 * menu must be drawn here rather than deferred.  absorb_count swallows the
 * spurious empty/"/" call(s) MBBS may deliver next.
 */
static VOID
cfg_finish_form(GBOOL saved)
{
    if (modmb != NULL) {
        setmbk(modmb);
        cfg_show_topmenu(saved ? CFGSAV : 0);
        rstmbk();
    }
    usrptr->state  = cfgstt;
    usrptr->substt = CFGSTT_MENU;
    if (usrnum >= 0 && usrnum < MAXNTERM)
        absorb_count[usrnum] = 2;
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
    CHAR  buf[20];
    INT   ord;
    GBOOL changed = (save && fsdscb->chgcnt > 0);

    if (changed) {
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
    }

    cfg_finish_form(changed);
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
    CHAR  buf[24];
    INT   i;
    GBOOL changed = (save && fsdscb->chgcnt > 0);

    if (changed) {
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
    }

    cfg_finish_form(changed);
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
    CHAR  buf[24];
    INT   i;
    GBOOL changed = (save && fsdscb->chgcnt > 0);

    if (changed) {
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
    }

    cfg_finish_form(changed);
}

/*
 * cfg_geo_vfy
 *
 * FSE field verify callback for the GeoIP Location form.  Numeric ranges are
 * enforced by the field's MIN/MAX spec; text fields accept any input.  DONE
 * is delegated to vfyadn so SAVE/QUIT end the session.
 */
static INT
cfg_geo_vfy(INT fldno, CHAR *answer)
{
    if (fldno == GEO_DONE) return vfyadn(fldno, answer);
    return VFYOK;
}

/*
 * cfg_launch_geo
 *
 * Starts a full-screen FSE session for the GeoIP Location form, pre-filled
 * from the current settings.  cfg_geo_done() runs on save/quit.
 */
static VOID
cfg_launch_geo(VOID)
{
    const CHAR *lvl, *prov;

    if (snt_vda_sz <= 0 || modmb == NULL) return;

    switch (geoip_loglevel) {
    case GEOLOG_OFF:     lvl = "OFF";     break;
    case GEOLOG_ERRORS:  lvl = "ERRORS";  break;
    case GEOLOG_VERBOSE: lvl = "VERBOSE"; break;
    default:             lvl = "NORMAL";  break;
    }
    switch (geoip_provider) {
    case GEOPRV_IPAPI:   prov = "IP-API.COM"; break;
    case GEOPRV_IPAPICO: prov = "IPAPI.CO";   break;
    default:             prov = "IPWHO.IS";   break;
    }

    setmbk(modmb);
    fsdroom(SNTCFG_GEO, geo_fsp, 1);
    sprintf(vdatmp, geo_fmt,
            geoip_enabled ? "YES" : "NO",                        '\0',
            geoip_split   ? "SPLIT" : "COMBINED",                '\0',
            geoip_field,                                         '\0',
            geoip_cty_field,                                     '\0',
            (geoip_cty_fmt == GEOCF_CODE) ? "CODE" : "FULL",     '\0',
            prov,                                                '\0',
            geoip_host[0]   ? geoip_host   : "ipwho.is",         '\0',
            geoip_key[0]    ? geoip_key    : "",                 '\0',
            geoip_use_https ? "YES" : "NO",                      '\0',
            geoip_timeout,                                       '\0',
            (!geoip_cache_on) ? "OFF" : (geoip_cache_bytime ? "TIME" : "IP"), '\0',
            geoip_cache_min,                                     '\0',
            geoip_retries,                                       '\0',
            lvl,                                                 '\0',
            geoip_format[0] ? geoip_format : "{city}, {region}, {country}", '\0');
    fsdapr(vdaptr, snt_vda_sz, vdatmp);
    fsdbkg(fsdrft());
    fsdego(cfg_geo_vfy, cfg_geo_done);
    rstmbk();
}

/*
 * cfg_geo_done
 *
 * FSE whndun callback for the GeoIP Location form.  Applies all field values
 * to the live GeoIP variables and persists them to SNTIPCTL.DAT.  Restores
 * the top-level config menu regardless of save/quit.
 */
static VOID
cfg_geo_done(SHORT save)
{
    CHAR  buf[24];
    INT   ord;
    GBOOL changed = (save && fsdscb->chgcnt > 0);

    if (changed) {
        ord = fsdord(GEO_ENABLE);
        geoip_enabled = (ord == 1) ? TRUE : FALSE;

        ord = fsdord(GEO_WRITEMODE);          /* COMBINED(0)/SPLIT(1) */
        geoip_split = (ord == GEOWM_SPLIT) ? TRUE : FALSE;

        fsdfxt(GEO_FIELD, buf, sizeof(buf));
        { INT v = atoi(buf); if (v >= 1 && v <= 5) geoip_field = v; }

        fsdfxt(GEO_CTYFLD, buf, sizeof(buf));
        { INT v = atoi(buf); if (v >= 1 && v <= 5) geoip_cty_field = v; }

        ord = fsdord(GEO_CTYFMT);             /* FULL(0)/CODE(1) */
        geoip_cty_fmt = (ord == GEOCF_CODE) ? GEOCF_CODE : GEOCF_FULL;

        ord = fsdord(GEO_PROVIDER);           /* IPWHO.IS(0)/IP-API.COM(1)/IPAPI.CO(2) */
        if (ord >= 0 && ord <= GEOPRV_IPAPICO) geoip_provider = ord;

        fsdfxt(GEO_HOST, geoip_host, sizeof(geoip_host));
        fsdfxt(GEO_KEY,  geoip_key,  sizeof(geoip_key));

        ord = fsdord(GEO_HTTPS);              /* ALT=YES(0)/NO(1) */
        geoip_use_https = (ord == 0) ? TRUE : FALSE;

        /*
         * HTTPS availability depends on the provider: ip-api.com's free tier is
         * HTTP-only, so force HTTPS off there unless a paid API key is set (which
         * unlocks the encrypted endpoint).  ipwho.is and ipapi.co support HTTPS
         * on their free tiers, so their choice is left as the sysop set it.
         */
        if (geoip_provider == GEOPRV_IPAPI && geoip_key[0] == '\0')
            geoip_use_https = FALSE;

        fsdfxt(GEO_TIMEOUT, buf, sizeof(buf));
        { INT v = atoi(buf); if (v >= 1 && v <= 60) geoip_timeout = v; }

        ord = fsdord(GEO_CACHE);              /* OFF(0)/TIME(1)/IP(2) */
        geoip_cache_on     = (ord != GEOCM_OFF);
        geoip_cache_bytime = (ord == GEOCM_IP) ? FALSE : TRUE;

        fsdfxt(GEO_CACHEDUR, buf, sizeof(buf));
        { INT v = atoi(buf); if (v >= 1 && v <= 44640) geoip_cache_min = v; }

        fsdfxt(GEO_RETRY, buf, sizeof(buf));
        { INT v = atoi(buf); if (v >= 0 && v <= 5) geoip_retries = v; }

        ord = fsdord(GEO_LOGLVL);             /* OFF/ERRORS/NORMAL/VERBOSE = 0..3 */
        if (ord >= GEOLOG_OFF && ord <= GEOLOG_VERBOSE) geoip_loglevel = ord;

        fsdfxt(GEO_FORMAT, geoip_format, sizeof(geoip_format));

        if (geoip_host[0]   == '\0') stzcpy(geoip_host,   "ipwho.is",                    sizeof(geoip_host));
        if (geoip_format[0] == '\0') stzcpy(geoip_format, "{city}, {region}, {country}", sizeof(geoip_format));

        /* Make sure the GeoIP log folder exists if logging was just enabled. */
        if (geoip_loglevel != GEOLOG_OFF) {
            CreateDirectoryA("TOTALIPCONTROL", NULL);
            CreateDirectoryA("TOTALIPCONTROL\\GEOIP LOGS", NULL);
        }

        cfg_save();
    }

    cfg_finish_form(changed);
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
    sntcfg.version     = 9;
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
    sntcfg.geoip_cache_bytime = geoip_cache_bytime ? 'Y' : 'N';
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

    /* GeoIP Location block (struct version 8), with range/default guards. */
    geoip_enabled   = (sntcfg.geoip_on == 'Y') ? TRUE : FALSE;
    if (sntcfg.geoip_fld >= 1 && sntcfg.geoip_fld <= 5)
        geoip_field = sntcfg.geoip_fld;
    if (sntcfg.geoip_provider >= 0 && sntcfg.geoip_provider <= GEOPRV_IPAPICO)
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
    if (geoip_host[0]   == '\0') stzcpy(geoip_host,   "ipwho.is",                    sizeof(geoip_host));
    if (geoip_format[0] == '\0') stzcpy(geoip_format, "{city}, {region}, {country}", sizeof(geoip_format));

    geoip_split = (sntcfg.geoip_split == 'Y') ? TRUE : FALSE;
    if (sntcfg.geoip_cty_fld >= 1 && sntcfg.geoip_cty_fld <= 5)
        geoip_cty_field = sntcfg.geoip_cty_fld;
    if (sntcfg.geoip_cty_fmt == GEOCF_FULL || sntcfg.geoip_cty_fmt == GEOCF_CODE)
        geoip_cty_fmt = sntcfg.geoip_cty_fmt;
    /* Cache mode: only 'N' means per-IP; anything else (incl. a zeroed byte
     * from a pre-v9 record) means the historical time-based expiry. */
    geoip_cache_bytime = (sntcfg.geoip_cache_bytime == 'N') ? FALSE : TRUE;
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
        if (sntcfg.version == 9) {
            cfg_struct_to_live();
            shocst("Total IP Control", "settings loaded from SNTIPCTL.DAT");
        } else if (sntcfg.version == 7 || sntcfg.version == 8) {
            /*
             * Forward-migrate a version 7 or 8 record.  Each newer block was
             * appended after the previous layout (carved from the old spare
             * area), so an older record is a byte-compatible prefix of version 9
             * -- every existing field sits at the same offset.  We therefore
             * PRESERVE all existing settings via cfg_struct_to_live() (bytes that
             * did not exist in the old version read as zero and are ignored by
             * the range guards), then apply defaults for the blocks that record
             * did not have, and rewrite it as version 9.
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
                stzcpy(geoip_host,   "ipwho.is",                    sizeof(geoip_host));
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
            geoip_cache_bytime = TRUE;      /* new in v9 -- historical time mode */

            dfaDelete();
            cfg_live_to_struct();
            dfaInsertV(&sntcfg, (USHORT)sizeof(sntcfg));
            shocst("Total IP Control", "settings migrated to v1.1.0 -- existing settings preserved");
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
               "Redeploy SNTIPCTL.MSG and restart the BBS.");
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
    cfg_show_topmenu(0);
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
        if (*tok != '\0' && gen_haskey(tok, channel, usroff(channel)))
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
count_ip_in_mod(ULONG user_ip, INT target_state, const CHAR *bypass)
{
    INT i, count = 0;
    for (i = 0; i < hichp1; i++) {
        if (i == usrnum)                                    continue;
        if (usroff(i)->usrcls != ACTUSR)                    continue;
        if (usroff(i)->state  != target_state)              continue;
        if ((*pp_tcpipinf)[i].inaddr.s_addr != user_ip)    continue;
        if (gw_other_has_bypass_key(i, bypass))             continue;
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
         * Re-assert continuous output every editor cycle.  The menu is
         * transmitted asynchronously by the poll loop, so if the FSD teardown
         * (or anything else) left scnbrk at the user's paged screen length, the
         * next redraw could raise a "(N)onstop,Q,C?" prompt.  Pinning CTNUOS
         * here -- in addition to editor_pager_suppress() on entry -- guarantees
         * paging stays off for the whole session (restored on X/Q exit).
         */
        if (usaptr != NULL && usrnum >= 0 && usrnum < MAXNTERM &&
            editor_pager_off[usrnum]) {
            usaptr->scnbrk = CTNUOS;
            rstrxf();
        }

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
            /*
             * Empty input -- a stray Enter, or a spurious empty call delivered
             * past the absorb counter.  Do nothing rather than repaint the whole
             * menu (which clears the screen), so the display is not needlessly
             * redrawn.  The menu is already on screen from the last real draw.
             */
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
        if (sameas(inp, "4")) { cfg_launch_geo(); outprf(usrnum); return 1; }

        if (modmb != NULL) {
            setmbk(modmb);
            cfg_show_topmenu(CFGBAD);   /* menu with an "invalid input" banner */
            rstmbk();
        }
        return 1;
    }

    return 1;
}
