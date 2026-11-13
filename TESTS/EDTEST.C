/***************************************************************************
 *                                                                         *
 *   EDTEST.C  --  host-side test of the /TOTALIP settings editor          *
 *                                                                         *
 *   Builds the editor's settings table and value logic straight out of   *
 *   SRC\SNTIPCTL.C (TESTS\RUNTESTS.CMD extracts the code between the     *
 *   markers into EDCODE.INC) and checks that every kind of setting reads *
 *   and writes the live variable it is bound to.  No BBS needed: the few *
 *   SDK calls involved are stubbed below.  Exit code 0 = all passed.     *
 *                                                                         *
 ***************************************************************************/

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

/* ---- SDK types and stubs ---- */
typedef char           CHAR;
typedef unsigned char  UCHAR;
typedef int            INT;
typedef unsigned long  ULONG;
typedef short          GBOOL;       /* GCTYPDEF.H: GBOOL is a short       */
#define VOID void
#define MAXNTERM 8
#define INPSIZ   256

static INT usrnum = 0;

static INT sameas(const CHAR *a, const CHAR *b) { return _stricmp(a, b) == 0; }
static VOID stzcpy(CHAR *d, const CHAR *s, INT n) { strncpy(d, s, n - 1); d[n - 1] = '\0'; }
static VOID setmem(CHAR *p, INT n, INT v) { memset(p, v, n); }
static VOID prfmsg(INT n, ...) { (void)n; }
static VOID shocst(const CHAR *a, const CHAR *b, ...) { (void)a; (void)b; }

#include "..\SRC\SNTIPCTL.H"

struct snt_cidr  { ULONG addr; ULONG mask; };
struct snt_cidr6 { UCHAR addr[16]; UCHAR prefix; };

/* ---- the live settings the table binds to ---- */

/*
 * Two GBOOL settings sit in a struct with guard bytes right after them, so a
 * write of the wrong width (an INT into a 2-byte GBOOL) shows up as damage to
 * the guard -- it would otherwise go unnoticed, because the low half of the
 * INT reads back correctly on this CPU while the next variable is clobbered.
 */
static struct { GBOOL v; GBOOL guard; } g_conn = { 0, 0x5A5A }, g_split = { 0, 0x5A5A };
#define conn_limit_enabled g_conn.v
#define geoip_split        g_split.v

static GBOOL proxy_trust_enabled, proxy_block_enabled, ssh_manage_enabled,
             ssh_hdr_enabled, ssh_trust_enabled, ssh_block_enabled,
             debug_enabled, usrip_enabled, geoip_enabled,
             geoip_use_https, geoip_cache_on = TRUE,
             geoip_cache_bytime = TRUE, ssh_recv_hooked = TRUE, tnt_recv_hooked = TRUE;
static INT   trusted_proxy_count, ssh_proxy_count, conn_limit_max = 1, log_mode,
             usrip_field = 1, geoip_field = 3, geoip_cty_field = 4, geoip_cty_fmt,
             geoip_reg_fmt, geoip_provider, geoip_timeout = 5, geoip_cache_min = 1440,
             geoip_retries = 1, geoip_loglevel = GEOLOG_NORMAL;
static CHAR  bypass_key[16], staff_key[16], geoip_host[64], geoip_key[80], geoip_format[48];
static struct snt_cidr  trusted_proxy_cidrs[SNTIPCTL_MAX_TRUSTED], ssh_proxy_cidrs[SNTIPCTL_MAX_TRUSTED],
                        whitelist_cidrs[SNTIPCTL_MAX_WHITELIST];
static struct snt_cidr6 whitelist6_cidrs[SNTIPCTL_MAX_WHITELIST6];

static const CHAR *geoip_default_host(INT p) { (void)p; return "ipwho.is"; }

/* CIDR helpers and the editor, extracted from SNTIPCTL.C */
#include "EDCODE.INC"

/* ---- tests ---- */
static INT failures = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); failures++; } } while (0)

/*
 * A setting by name within section sec (1-6).  sec 0 searches every section
 * and requires the name to be unique, since some names (Trusted proxy 1,
 * Block direct connections) occur in both the telnet and SSH sections.
 */
static const FIELD *
byname(INT sec, const CHAR *name)
{
    INT s, k, hits = 0;
    const FIELD *found = NULL;

    for (s = 0; s < NSECTIONS; s++) {
        if (sec != 0 && s != sec - 1)
            continue;
        for (k = 0; k < sections[s].count; k++)
            if (strcmp(fields[sections[s].first + k].name, name) == 0) {
                found = &fields[sections[s].first + k];
                hits++;
            }
    }
    if (hits != 1) {
        printf("setting %s in section %d: %d matches\n", name, sec, hits);
        exit(2);
    }
    return found;
}

static const CHAR *
shown(const FIELD *f)
{
    static CHAR buf[112];
    ed_fieldvalue(f, buf, sizeof(buf));
    return buf;
}

int
main(void)
{
    const FIELD *f;

    ed_build();                     /* the table is built at startup */

    /* yes/no settings are GBOOL (short): both directions, and the Y/N shortcuts */
    f = byname(0, "Connection limit");
    CHECK(f->size == sizeof(GBOOL));
    CHECK(ed_setfield(f, "yes") && conn_limit_enabled == TRUE && strcmp(shown(f), "YES") == 0);
    CHECK(ed_setfield(f, "N") && conn_limit_enabled == FALSE && strcmp(shown(f), "NO") == 0);
    CHECK(!ed_setfield(f, "maybe") && conn_limit_enabled == FALSE);
    conn_limit_enabled = 1; CHECK(strcmp(shown(f), "YES") == 0);

    /* numbers: range and digits only */
    f = byname(0, "Max connections per IP");
    CHECK(ed_setfield(f, "3") && conn_limit_max == 3);
    CHECK(!ed_setfield(f, "0") && !ed_setfield(f, "1001") && !ed_setfield(f, "2x")
          && !ed_setfield(f, "") && conn_limit_max == 3);
    f = byname(0, "Retries on failure");
    CHECK(ed_setfield(f, "0") && geoip_retries == 0);

    /* list settings bound to INT, with stored values that are not the index */
    f = byname(0, "Profile field for IP");
    CHECK(f->size == sizeof(INT));
    CHECK(ed_setfield(f, "phone") && usrip_field == 5 && strcmp(shown(f), "PHONE") == 0);
    CHECK(ed_setfield(f, "ADDRESS2") && usrip_field == 2);
    CHECK(!ed_setfield(f, "ADDRESS9") && usrip_field == 2);
    f = byname(0, "Audit logging");
    CHECK(ed_setfield(f, "both") && log_mode == LOGM_BOTH && strcmp(shown(f), "BOTH") == 0);
    f = byname(0, "GeoIP provider");
    CHECK(ed_setfield(f, "ipinfo.io") && geoip_provider == GEOPRV_IPINFO);

    /* a list setting bound to a GBOOL */
    f = byname(0, "Write mode");
    CHECK(f->size == sizeof(GBOOL));
    CHECK(ed_setfield(f, "SPLIT") && geoip_split == TRUE && strcmp(shown(f), "SPLIT") == 0);
    CHECK(ed_setfield(f, "combined") && geoip_split == FALSE && strcmp(shown(f), "COMBINED") == 0);

    /* a yes/no or list setting writes exactly its own GBOOL, nothing beyond */
    CHECK(g_conn.guard == 0x5A5A && g_split.guard == 0x5A5A);

    /* the cache mode is two flags */
    f = byname(0, "Cache");
    CHECK(ed_setfield(f, "OFF") && !geoip_cache_on && strcmp(shown(f), "OFF") == 0);
    CHECK(ed_setfield(f, "IP") && geoip_cache_on && !geoip_cache_bytime && strcmp(shown(f), "IP") == 0);
    CHECK(ed_setfield(f, "time") && geoip_cache_on && geoip_cache_bytime && strcmp(shown(f), "TIME") == 0);

    /* key names: upper case, no spaces, - clears */
    f = byname(0, "Staff key for /WHOSON");
    CHECK(ed_setfield(f, "cosysop") && strcmp(staff_key, "COSYSOP") == 0);
    CHECK(!ed_setfield(f, "two words") && strcmp(staff_key, "COSYSOP") == 0);
    CHECK(!ed_setfield(f, "ABCDEFGHIJKLMNOP") && strcmp(staff_key, "COSYSOP") == 0);  /* 16 > 15 */
    CHECK(ed_setfield(f, "-") && staff_key[0] == '\0' && strcmp(shown(f), "(none)") == 0);

    /* text: spaces allowed, too long refused, secrets never shown */
    f = byname(0, "Location format");
    CHECK(ed_setfield(f, "{city}, {cc}") && strcmp(geoip_format, "{city}, {cc}") == 0);
    CHECK(!ed_setfield(f, "123456789012345678901234567890123456789012345678"));  /* 48 */
    f = byname(0, "API key");
    CHECK(ed_setfield(f, "abc123") && strcmp(shown(f), "(set)") == 0);
    CHECK(ed_setfield(f, "-") && geoip_key[0] == '\0' && strcmp(shown(f), "(not set)") == 0);
    f = byname(0, "API host");
    CHECK(strcmp(shown(f), "ipwho.is (provider's own)") == 0);

    /* IPv4 addresses and ranges, each row bound to its own slot */
    f = byname(2, "Trusted proxy 2");
    CHECK(f->var == &trusted_proxy_cidrs[1]);
    CHECK(ed_setfield(f, "10.1.2.3/24") && strcmp(shown(f), "10.1.2.0/24") == 0);
    CHECK(ed_setfield(f, "192.168.5.9") && strcmp(shown(f), "192.168.5.9") == 0);
    CHECK(!ed_setfield(f, "0.0.0.0/0") && !ed_setfield(f, "10.0.0.300") && !ed_setfield(f, "1.2.3.4/33"));
    CHECK(strcmp(shown(f), "192.168.5.9") == 0);
    CHECK(ed_setfield(f, "-") && trusted_proxy_cidrs[1].addr == 0 && trusted_proxy_cidrs[1].mask == 0);
    CHECK(byname(3, "Entry 10")->var == &whitelist_cidrs[9]);
    CHECK(byname(3, "Entry 1")->var == &whitelist_cidrs[0]);
    CHECK(byname(6, "Trusted proxy 1")->var == &ssh_proxy_cidrs[0]);

    /* IPv6 */
    f = byname(4, "Entry 10");
    CHECK(f->var == &whitelist6_cidrs[9]);
    CHECK(ed_setfield(f, "2001:db8::/32") && whitelist6_cidrs[9].prefix == 32);
    CHECK(!ed_setfield(f, "10.0.0.1") && !ed_setfield(f, "::/0"));
    CHECK(ed_setfield(f, "-") && whitelist6_cidrs[9].prefix == 0 && strcmp(shown(f), "(not set)") == 0);

    /* remarks on settings that cannot take effect */
    proxy_block_enabled = TRUE; trusted_proxy_count = 0;
    CHECK(ed_rownote(byname(2, "Block direct connections")) != NULL);
    trusted_proxy_count = 1;
    CHECK(ed_rownote(byname(2, "Block direct connections")) == NULL);
    ssh_manage_enabled = FALSE;
    CHECK(ed_rownote(byname(6, "Block direct connections")) != NULL);

    /* the sections cover every setting exactly once, in order, and their
     * titles fit the 34-character column of TOPROW */
    {
        INT p, k, next = 0;
        for (p = 0; p < NSECTIONS; p++) {
            CHECK(strlen(sections[p].title) <= 24);   /* MAINHDR's column */
            for (k = 0; k < sections[p].count; k++)
                CHECK(sections[p].first + k == next++);
        }
        CHECK(next == NFIELDS);
        CHECK(NSECTIONS == 6);
        CHECK(NFIELDS == NFIELDS_MAX);  /* the table is exactly full */
    }

    /* list sizes, and every generated row bound to its own entry */
    CHECK(sections[1].count == 2 + SNTIPCTL_MAX_TRUSTED && SNTIPCTL_MAX_TRUSTED == 10);
    CHECK(sections[5].count == 4 + SNTIPCTL_MAX_TRUSTED);
    CHECK(sections[2].count == 50 && sections[3].count == 50);
    CHECK(strcmp(sections[2].title, "IPv4 Whitelist") == 0);
    CHECK(byname(2, "Trusted proxy 10")->var == &trusted_proxy_cidrs[9]);
    CHECK(byname(6, "Trusted proxy 10")->var == &ssh_proxy_cidrs[9]);
    CHECK(byname(3, "Entry 50")->var == &whitelist_cidrs[49]);
    CHECK(byname(4, "Entry 50")->var == &whitelist6_cidrs[49]);
    CHECK(byname(4, "Entry 37")->var == &whitelist6_cidrs[36]);
    CHECK(byname(4, "Entry 37")->size == sizeof(struct snt_cidr6));

    /* whitelists page 10 at a time; the other sections are one screen */
    CHECK(ed_npages(2) == 5 && ed_npages(3) == 5);
    CHECK(ed_npages(0) == 1 && ed_npages(4) == 1 && ed_npages(5) == 1);

    /* entry 37 of the IPv6 list: storing it reaches the live list */
    f = byname(4, "Entry 37");
    CHECK(ed_setfield(f, "2001:db8:37::/48") && whitelist6_cidrs[36].prefix == 48);
    ed_load_row((INT)(f - fields));
    CHECK(strcmp(tv_rownum, "37") == 0);

    /* the section list's summary counts the entries in use */
    ed_secinfo(3);
    CHECK(strcmp(tv_secinfo, "1 of 50 in use") == 0);
    ed_secinfo(0);
    CHECK(strcmp(tv_secinfo, "8 settings") == 0);

    /* section numbering: rows are numbered from 1 within their section */
    ed_load_row(byname(6, "Trusted proxy 1") - fields);
    CHECK(strcmp(tv_rownum, "5") == 0);
    ed_load_row(byname(0, "GeoIP lookups") - fields);
    CHECK(strcmp(tv_rownum, "1") == 0);

    /* every label fits the 26-character column of SETROW */
    {
        INT i;
        for (i = 0; i < NFIELDS; i++)
            CHECK(strlen(fields[i].name) <= 26);
    }

    printf("%d settings, %d sections: %s\n", NFIELDS, NSECTIONS, failures ? "FAILED" : "all passed");
    return failures ? 1 : 0;
}
