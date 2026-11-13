/***************************************************************************
 *                                                                         *
 *   SNTIPCTL.H  --  Total IP Control                                      *
 *                                                                         *
 *   Centralized IP management, proxy detection, connection control,       *
 *   and audit logging for The Major BBS v10.                              *
 *                                                                         *
 *   Copyright (c) 2026 Sysop Network.  All Rights Reserved.               *
 *                                                                         *
 *   Message numbers for SNTIPCTL.MSG.                                     *
 *                                                                         *
 *   Code finds a message by its position in the .MSG file.  The file     *
 *   starts with its only LEVEL6 marker, which takes no number, so the     *
 *   first message is 1.  New messages must be APPENDED at the end of the  *
 *   .MSG: inserting one renumbers every message after it.                 *
 *                                                                         *
 ***************************************************************************/

#ifndef SNTIPCTL_H
#define SNTIPCTL_H

/* Number of trusted proxy entries per protocol (telnet, SSH). */
#define SNTIPCTL_MAX_TRUSTED    10

/* Number of IPv4 connection-limit whitelist entries. */
#define SNTIPCTL_MAX_WHITELIST  50

/* Number of IPv6 connection-limit whitelist entries. */
#define SNTIPCTL_MAX_WHITELIST6 50

/* ---- Messages shown to callers ---- */
#define CLIMIT       1             /* refused: too many connections per IP */
#define PRXBLK       2             /* refused: direct connection, proxy    */
                                   /*   required                           */
#define IPGDNY       3             /* gateway: too many from this IP       */
#define IPGGNT       4             /* gateway: access granted (optional)   */
#define MYIP         5             /* /MYIP                                */
#define WHOHDR       6             /* /WHOSON header                       */
#define WHOROW       7             /* /WHOSON one user                     */
#define NOACCESS     8             /* no access: /WHOSON, /TIP, settings   */

/* ---- /TIP and MENU=SYSOPMENU settings editor ---- */
#define TOPHDR       9             /* section list header                  */
#define TOPROW      10             /* one section                          */
#define TOPFTR      11             /* section list commands                */
#define TOPPRMT     12             /* section list prompt                  */
#define MAINHDR     13             /* section header                       */
#define SETROW      14             /* one settings row                     */
#define MAINFTR     15             /* section commands                     */
#define MAINFTRP    16             /* section commands, paged section      */
#define PROMPT      17             /* section prompt                       */
#define ASKVAL      18             /* prompt for a new value               */
#define SAVED       19             /* setting saved                        */
#define BADVAL      20             /* value rejected                       */
#define BADSEL      21             /* unknown menu choice                  */
#define LEAVE       22             /* leaving the editor                   */
#define CHOICES     23             /* a list setting: its current value    */
#define CHOICEP     24             /* a list setting: the prompt           */
#define CHROW       25             /* one choice in a setting's list       */
#define HELPMENU    26             /* quick-start help (H)                 */

/* ---- Help for each setting (? at its prompt, or H n in a section) ---- */
#define HCONLIM     27             /* Connection limit                     */
#define HMAXCON     28             /* Max connections per IP               */
#define HBYPASS     29             /* Limit bypass key                     */
#define HSTAFF      30             /* Staff key for /WHOSON                */
#define HLOGMODE    31             /* Audit logging                        */
#define HDEBUG      32             /* Debug trace log                      */
#define HUIPON      33             /* Record IP in profile                 */
#define HUIPFLD     34             /* Profile field for IP                 */
#define HPRXTRU     35             /* Telnet: trusted proxy only           */
#define HPRXBLK     36             /* Telnet: block direct connections     */
#define HPRXIP      37             /* Telnet trusted proxy 1-2             */
#define HSSHMAN     38             /* SSH: manage connections              */
#define HSSHHDR     39             /* SSH: read PROXY header               */
#define HSSHTRU     40             /* SSH: trusted proxy only              */
#define HSSHBLK     41             /* SSH: block direct connections        */
#define HSSHIP      42             /* SSH trusted proxy 1-2                */
#define HWL4        43             /* IPv4 whitelist 1-10                  */
#define HWL6        44             /* IPv6 whitelist 1-10                  */
#define HGEOON      45             /* GeoIP lookups                        */
#define HGEOPRV     46             /* GeoIP provider                       */
#define HGEOHOST    47             /* API host                             */
#define HGEOKEY     48             /* API key                              */
#define HGEOTLS     49             /* Use HTTPS                            */
#define HGEOTMO     50             /* Lookup timeout                       */
#define HGEORTY     51             /* Retries on failure                   */
#define HGEOCACH    52             /* Cache                                */
#define HGEODUR     53             /* Cache duration                       */
#define HGEOLOG     54             /* GeoIP log level                      */
#define HGEOMODE    55             /* Write mode                           */
#define HGEOFLD     56             /* City/state field                     */
#define HGEOCFLD    57             /* Country field                        */
#define HGEOCFMT    58             /* Country format                       */
#define HGEORFMT    59             /* State format                         */
#define HGEOFMT     60             /* Location format                      */

/*
 * Audit-logging mode.  Two independent sinks: the BBS Audit Trail (live sysop
 * log, written via shocst) and daily log files under TOTALIPCONTROL\.
 */
#define LOGM_OFF    0    /* no Audit Trail, no log files                   */
#define LOGM_AUDIT  1    /* BBS Audit Trail only (shocst), no files        */
#define LOGM_LOG    2    /* daily log files only, no Audit Trail lines     */
#define LOGM_BOTH   3    /* Audit Trail + log files                        */

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
 * GeoIP cache mode, as chosen in the editor; stored as two flags (see
 * geoip_cache_on / geoip_cache_bytime).  OFF = no caching; TIME = cache and
 * look up again after the cache duration; IP = cache each IP for as long as
 * the BBS runs (the duration is ignored).
 */
#define GEOCM_OFF       0  /* caching disabled                            */
#define GEOCM_TIME      1  /* time-based expiry (cache duration)          */
#define GEOCM_IP        2  /* per-IP, no time expiry                      */

/* GeoIP log verbosity levels (stored in config). */
#define GEOLOG_OFF      0  /* no GeoIP logging                            */
#define GEOLOG_ERRORS   1  /* API errors / rate limiting / failures only  */
#define GEOLOG_NORMAL   2  /* + successful lookups and profile updates    */
#define GEOLOG_VERBOSE  3  /* + cache hits/misses and enqueue activity    */

#endif /* SNTIPCTL_H */
