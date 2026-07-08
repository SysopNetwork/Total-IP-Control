/***************************************************************************
 *                                                                         *
 *   SNTIPCTL.H  --  Total IP Control                                      *
 *                                                                         *
 *   Centralized IP management, proxy detection, connection control,       *
 *   and audit logging for The Major BBS v10.                              *
 *                                                                         *
 *   Total IP Control is developed and maintained by Mark Laudenbach       *
 *   at Sysop Network.                                                     *
 *                                                                         *
 *   Copyright (c) 2026 Sysop Network.  All Rights Reserved.              *
 *                                                                         *
 ***************************************************************************/

#ifndef SNTIPCTL_H
#define SNTIPCTL_H

/* Maximum number of trusted proxy CIDR entries that can be configured. */
#define SNTIPCTL_MAX_TRUSTED   2

/* Maximum number of connection-limit whitelist CIDR entries. */
#define SNTIPCTL_MAX_WHITELIST 10

/*
 * Message slot numbers derived from SNTIPCTL.MSG.
 * LEVEL6 display messages (slots 1-8); LEVEL99 marker occupies slot 9;
 * FSE form templates are slots 10-13.  All slots are sequential across
 * the entire MSG file including LEVEL section markers.
 */

/* ---- LEVEL6 display messages ---- */
#define CLIMIT      1    /* Connection limit exceeded message (T)          */
#define CFGHED      2    /* Config editor header                           */
#define CFGMNU      3    /* Config top-level menu [1][2][3][4][X]          */
#define CFGSAV      4    /* "Settings saved"                               */
#define CFGDNY      5    /* "Access denied"                                */
#define CFGBAD      6    /* "Invalid input"                                */
#define IPGDNY      7    /* Gateway denial message (%d = max allowed)      */
#define IPGGNT      8    /* Gateway granted message (optional, blank=off)  */

/* ---- LEVEL99 FSE form templates ---- */
/* NOTE: The LEVEL99 marker itself occupies slot 9; forms start at 10.     */
#define SNTCFG_GEN  10   /* General settings FSE form                      */
#define SNTCFG_PRX  11   /* Trusted proxy CIDR FSE form                    */
#define SNTCFG_WL   12   /* Connection limit whitelist FSE form (10 slots) */

/* ---- Additional LEVEL99-section display message ---- */
/* Placed after the FSE forms so adding it does not renumber slots 1-12.   */
#define PRXBLK      13   /* "Direct connection refused" (require-proxy)     */

/* ---- GeoIP Location FSE form (v1.1.0) ---- */
/* Appended after PRXBLK so existing slots 1-13 are never renumbered.      */
#define SNTCFG_GEO  14   /* GeoIP Location settings FSE form               */

/*
 * FSE field numbers -- General Settings form (SNTCFG_GEN).
 * Fields are numbered 0-based in declaration order from gen_fsp[].
 */
#define GEN_PRXTRU  0    /* Trusted proxy enforcement (ALT=NO/YES)         */
#define GEN_PRXBLK  1    /* Require trusted proxy / block others (ALT=NO/YES)*/
#define GEN_CONLIM  2    /* Global connection limit (ALT=NO/YES)           */
#define GEN_MAXCON  3    /* Max connections per IP (MIN=1 MAX=1000)        */
#define GEN_LOGON   4    /* Audit logging (ALT=NO/AUDIT/LOG/BOTH)          */
#define GEN_UIPON   5    /* User profile IP recording (ALT=NO/YES)         */
#define GEN_UIPFLD  6    /* Profile field number (MIN=1 MAX=5)             */
#define GEN_BYPKEY  7    /* Bypass key name (text)                         */
#define GEN_DONE    8    /* Action selector (ALT=SAVE/QUIT)                */

/*
 * Audit-logging mode (stored in config; spacebar-cycled in the editor as the
 * GEN_LOGON multichoice).  Values are the 0-based ALT ordinals so fsdord()
 * maps directly.  Two independent sinks: the BBS Audit Trail (live sysop log,
 * written via shocst) and daily log files under TOTALIPCONTROL\.
 */
#define LOGM_OFF    0    /* no Audit Trail, no log files                   */
#define LOGM_AUDIT  1    /* BBS Audit Trail only (shocst), no files        */
#define LOGM_LOG    2    /* daily log files only, no Audit Trail lines     */
#define LOGM_BOTH   3    /* Audit Trail + log files                        */

/*
 * FSE field numbers -- Trusted Proxy CIDR form (SNTCFG_PRX).
 */
#define PRX_PRX1    0    /* Trusted proxy CIDR #1                          */
#define PRX_PRX2    1    /* Trusted proxy CIDR #2                          */
#define PRX_DONE    2    /* Action selector (ALT=SAVE/QUIT)                */

/*
 * FSE field numbers -- Whitelist form (SNTCFG_WL).
 */
#define WL_WL1      0    /* Whitelist CIDR #1                              */
#define WL_WL2      1    /* Whitelist CIDR #2                              */
#define WL_WL3      2    /* Whitelist CIDR #3                              */
#define WL_WL4      3    /* Whitelist CIDR #4                              */
#define WL_WL5      4    /* Whitelist CIDR #5                              */
#define WL_WL6      5    /* Whitelist CIDR #6                              */
#define WL_WL7      6    /* Whitelist CIDR #7                              */
#define WL_WL8      7    /* Whitelist CIDR #8                              */
#define WL_WL9      8    /* Whitelist CIDR #9                              */
#define WL_WL10     9    /* Whitelist CIDR #10                             */
#define WL_DONE     10   /* Action selector (ALT=SAVE/QUIT)                */

/*
 * FSE field numbers -- GeoIP Location form (SNTCFG_GEO).
 * Order must match geo_fsp[] / geo_fmt[] in SNTIPCTL.C and the field marker
 * runs in the SNTCFG_GEO template.
 */
#define GEO_ENABLE    0  /* GeoIP lookups on/off (ALT=NO/YES)             */
#define GEO_WRITEMODE 1  /* COMBINED (one field) vs SPLIT (city/state + country) */
#define GEO_FIELD     2  /* City/State field (MIN=1 MAX=5)                */
#define GEO_CTYFLD    3  /* Country field, SPLIT mode (MIN=1 MAX=5)       */
#define GEO_CTYFMT    4  /* Country format (ALT=FULL/CODE)               */
#define GEO_REGFMT    5  /* State/region format (ALT=CODE/FULL)          */
#define GEO_PROVIDER  6  /* GeoIP provider (ALT=IPWHO.IS/IP-API.COM/IPAPI.CO/IPINFO.IO) */
#define GEO_HOST      7  /* API host name (text)                          */
#define GEO_KEY       8  /* API key/token, blank for keyless free tier    */
#define GEO_HTTPS     9  /* Use HTTPS (ALT=YES/NO)                        */
#define GEO_TIMEOUT  10  /* Per-request timeout seconds (MIN=1 MAX=60)    */
#define GEO_CACHE    11  /* Cache mode (ALT=OFF/TIME/IP)                  */
#define GEO_CACHEDUR 12  /* Cache duration in minutes (MIN=1 MAX=44640)   */
#define GEO_RETRY    13  /* Retries on failed lookup (MIN=0 MAX=5)        */
#define GEO_LOGLVL   14  /* Log level (ALT=OFF/ERRORS/NORMAL/VERBOSE)     */
#define GEO_FORMAT   15  /* Location format template (text)               */
#define GEO_DONE     16  /* Action selector (ALT=SAVE/QUIT)               */

/* GeoIP provider identifiers (stored in config). */
#define GEOPRV_IPWHOIS  0  /* ipwho.is / ipwhois.io (default)             */
#define GEOPRV_IPAPI    1  /* ip-api.com                                  */
#define GEOPRV_IPAPICO  2  /* ipapi.co                                    */
#define GEOPRV_IPINFO   3  /* ipinfo.io (free tier, own probe data)       */

/* GeoIP location write mode (stored in config). */
#define GEOWM_COMBINED  0  /* whole location string in one field          */
#define GEOWM_SPLIT     1  /* city/state in one field, country in another */

/* GeoIP country rendering (stored in config). */
#define GEOCF_FULL      0  /* full country name, e.g. "United States"     */
#define GEOCF_CODE      1  /* two-letter ISO code, e.g. "US"              */

/* GeoIP state/region rendering (stored in config). */
#define GEORF_CODE      0  /* two-letter code where available, e.g. "MN" (default) */
#define GEORF_FULL      1  /* full subdivision name, e.g. "Minnesota"     */

/*
 * GeoIP cache mode (chosen on the form; stored as two flags -- see
 * geoip_cache_on / geoip_cache_bytime).  OFF = no caching; TIME = cache and
 * re-look-up after the cache duration expires; IP = cache per IP for the BBS
 * uptime so a repeat IP is never looked up again (the duration is ignored).
 */
#define GEOCM_OFF       0  /* caching disabled                            */
#define GEOCM_TIME      1  /* time-based expiry (cache duration)          */
#define GEOCM_IP        2  /* per-IP, no time expiry                      */

/* GeoIP log verbosity levels (stored in config). */
#define GEOLOG_OFF      0  /* no GeoIP logging                            */
#define GEOLOG_ERRORS   1  /* API errors / rate limiting / failures only  */
#define GEOLOG_NORMAL   2  /* + successful lookups and profile updates    */
#define GEOLOG_VERBOSE  3  /* + cache hits/misses and enqueue activity    */

/*
 * Sub-states for the online config editor sttrou (stored in usrptr->substt).
 * substt == 0 is reserved for BBS menu gateway use (sntipctl_gateway).
 * The menu is displayed in sntipctl_gbl before returning 1; sttrou absorbs
 * MBBS's spurious re-invocation via the '/' guard in CFGSTT_MENU.
 */
#define CFGSTT_MENU    1  /* Top-level menu -- awaiting 1/2/3/X input        */

#endif /* SNTIPCTL_H */
