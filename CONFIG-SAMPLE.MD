# Total IP Control — Sample Configuration

Total IP Control stores its settings in a Btrieve record (`SNTIPCTL.DAT`), edited
live from the **`/TIP`** settings menu (Master key required; also a menu item with `MENU=SYSOPMENU`). There is no
text configuration file to hand-edit; this document lists recommended values to
enter in the menu, with worked examples for the GeoIP Location feature.

The menu groups the settings into six sections; pick one to see its settings,
numbered from 1 (the whitelists ten to a page; `N`/`P` turn the page):

```
 1. General Settings          8 settings
 2. Telnet Trusted Proxies    2 settings, 1 proxy
 3. IPv4 Whitelist            0 of 50 in use
 4. IPv6 Whitelist            0 of 50 in use
 5. GeoIP Location            16 settings
 6. SSH Settings              4 settings, 0 proxies
```

Type a setting's number to change it; `?` at its prompt explains it, and `X`
goes back one step. Each change takes effect immediately and persists across
restarts.

---

## SSH behind a proxy — recommended baseline

Section 6, **SSH Settings**, mirrors section 2 (telnet) but keeps its own trusted
proxy list, so telnet and SSH can sit behind different front ends. All of it is off
by default.

**Force SSH through your proxy, and recover the real client IP** (the proxy must
be configured to send a PROXY Protocol v1 header on the SSH port):

```
1. Manage SSH connections     YES
2. Read PROXY header          YES
3. Trusted proxy only         YES
4. Block direct connections   YES
5. Trusted proxy 1            203.0.113.10
```

**Force SSH through your proxy, without header support** (the proxy relays SSH
but does not speak PROXY protocol). The block still works; every SSH session will
simply report the proxy's address as the caller IP:

```
1. Manage SSH connections     YES
2. Read PROXY header          NO
3. Trusted proxy only         NO
4. Block direct connections   YES
5. Trusted proxy 1            203.0.113.10
```

Notes:

- Enter at least one SSH trusted proxy. With an empty list, blocking stays inactive —
  a deliberate fail-safe, so a half-finished configuration cannot lock you out.
- Loopback (`127.0.0.0/8`) and any address on the connection-limit whitelist are
  never blocked.
- If **Read PROXY header** cannot take effect until a restart (SNSSH loaded
  after SNTIPCTL), the menu shows it as inactive and the Audit Trail says so.
  Every other setting here applies to the next SSH connection.
- Do **not** turn header processing on unless the proxy really sends the header.
  A direct SSH client is passed through untouched either way, but the setting is
  pointless without a proxy that emits it.

---

## GeoIP Location — recommended baseline

Section 5 of `/TIP`, **GeoIP Location**. This baseline works out of the box with no signup or
API key; apart from turning it on, every value shown is the default.

| # | Setting | Recommended value | Notes |
|---|---|---|---|
| 1 | GeoIP lookups | `YES` | Turns the feature on |
| 2 | Write mode | `SPLIT` | City/state and country in separate fields |
| 3 | City/state field | `ADDRESS3` | Address line 3 |
| 4 | Country field | `ADDRESS4` | Address line 4 (used in SPLIT mode) |
| 5 | Country format | `FULL` | `United States` (or `CODE` for `US`) |
| 6 | State format | `CODE` | `MN` (or `FULL` for `Minnesota`) |
| 7 | GeoIP provider | `IPWHO.IS` | Keyless free service with HTTPS |
| 8 | API host | *(provider's own)* | Follows the provider |
| 9 | API key | *(not set)* | Leave clear for the free tier |
| 10 | Use HTTPS | `YES` | Encrypt the lookup |
| 11 | Lookup timeout (seconds) | `5` | Per-request network timeout |
| 12 | Cache | `TIME` | Cache per IP; look up again after the duration (see below) |
| 13 | Cache duration (minutes) | `1440` | 24 hours (used with TIME) |
| 14 | Retries on failure | `1` | One extra attempt on a failed lookup |
| 15 | GeoIP log level | `NORMAL` | Log successes + failures (see below) |
| 16 | Location format | `{city}, {region}, {country}` | See *Format template* |

With these (SPLIT) settings a US caller from Minneapolis is stored as:

```
Address 3:  Minneapolis, MN
Address 4:  United States
```

and a caller from London as:

```
Address 3:  London, England
Address 4:  United Kingdom
```

### Everything in one field (COMBINED)

Set **Write mode** (GeoIP setting 2) to `COMBINED` to store the whole location in the
City/state field instead. The country then comes from the location template, so you control
its form there:

| Write mode | Location format | US result (one field) |
|---|---|---|
| COMBINED | `{city}, {region}, {country}` | `Minneapolis, MN, United States` |
| COMBINED | `{city}, {region}, {cc}` | `Minneapolis, MN, US` |
| COMBINED | `{city}, {region}` | `Minneapolis, MN` |

---

## Format template

The **Location format** is assembled from these tokens:

| Token | Replaced with |
|---|---|
| `{city}` | City name |
| `{region}` | Two-letter state code for US addresses; full subdivision name elsewhere |
| `{country}` | Full country name |
| `{cc}` | Two-letter country code |

Empty pieces are dropped automatically, so a result with no known region collapses
cleanly. If the assembled value is longer than the target profile field (address
lines hold 29 characters, the phone field 15) it is truncated to fit.

Examples:

| Format template | US result | Non-US result |
|---|---|---|
| `{city}, {region}, {country}` | `Minneapolis, MN, United States` | `London, England, United Kingdom` |
| `{city}, {region}` | `Minneapolis, MN` | `London, England` |
| `{city}, {cc}` | `Minneapolis, US` | `London, GB` |
| `{region}, {country}` | `MN, United States` | `England, United Kingdom` |

Use a shorter template (for example `{city}, {region}`) when storing into the
Phone field or any narrow field.

---

## Example: paid API key

If you subscribe to a provider plan, set the **API key** (and, if the plan uses a
different endpoint, the **API host**). Everything else can stay the same.

| Setting | Value |
|---|---|
| 8. API host | *(the provider's paid host, if different)* |
| 9. API key | `your-api-key-here` |

The key is sent with the request; caching still applies, so you only pay for
distinct IP addresses within the cache window.

---

## Example: high-traffic board

To minimize API usage on a busy system, use per-IP caching and keep logging quiet:

| Setting | Value | Effect |
|---|---|---|
| 12. Cache | `IP` | Each IP is looked up once, then never again while the BBS is up |
| 14. Retries on failure | `0` | Do not retry (fail fast) |
| 15. GeoIP log level | `ERRORS` | Log only failures / rate limiting |

In `IP` mode the **Cache duration** is ignored — a known IP is never re-queried,
so the only lookups are for IPs not seen since the last restart. Use `TIME` mode
with a long duration (e.g. `10080` = 7 days) instead if you prefer locations to
refresh periodically.

---

## Log levels

The GeoIP log folder is `TOTALIPCONTROL\GEOIP LOGS\` (daily `YYYY-MM-DD.LOG`
files), controlled by **GeoIP log level** (GeoIP setting 15) independently of the main
**Audit logging** setting (General Settings):

| Log level | Records |
|---|---|
| `OFF` | Nothing |
| `ERRORS` | Failed lookups, API errors, rate limiting (HTTP 429), dropped requests |
| `NORMAL` | The above, plus successful lookups and profile updates |
| `VERBOSE` | The above, plus cache hits/misses and skipped private IPs |

---

## Notes

- **Private, loopback, and reserved IP addresses are never looked up** (RFC1918,
  `127.0.0.0/8`, `169.254.0.0/16`, CGNAT, etc.).
- Lookups run on a background thread and results are applied a moment later, so a
  slow or unreachable provider **never delays or blocks a login**.
- Store the GeoIP location in a **different** profile field from the one used by
  **Record IP in profile** (General Settings) so the two do not overwrite each other.
