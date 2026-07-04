# Total IP Control

**Total IP Control** (`SNTIPCTL`) is a unified IP-management module for **The Major BBS v10**. It restores real caller IPs from a reverse proxy, enforces per-IP connection limits, records caller IPs to user profiles, looks up each caller's approximate geographic location, and writes a full audit trail — all configurable live from the BBS, with settings stored on disk so they survive a restart.

It consolidates and extends two earlier modules, **PROXCLIP** (proxy protocol / real IP restoration) and **IPControl** (per-IP connection limiting), into a single module.

---

## Features

- **Proxy Protocol v1 support** — Restores the real caller IP from `PROXY TCP4` headers sent by a reverse proxy. Implemented by hooking `recv()` in `GALTNTD.DLL`, so the header is consumed the moment it arrives — no polling or sleeping. Falls back to a single non-blocking check if the hook cannot be installed.

- **Trusted proxy enforcement** — Optionally applies PROXY headers only when the connection originates from a configured trusted proxy IP/CIDR, preventing header spoofing from untrusted sources.

- **Require trusted proxy (block direct)** — Optionally refuses any connection that does **not** arrive from a trusted proxy, before the login prompt — stopping users from bypassing the reverse proxy by connecting straight to the backend port. Loopback and whitelisted addresses are always allowed, and an empty trusted-proxy list disables blocking, so a misconfiguration cannot lock the system out.

- **Global per-IP connection limits** — Enforces a configurable maximum number of simultaneous sessions from any single IP address, BBS-wide. Connections over the limit are refused at connect time or disconnected at login with a message that names the other sessions already connected from that IP.

- **Connection-limit whitelist** — Up to ten IP/CIDR entries that are never subject to the connection limit.

- **Bypass key** — Any user holding the configured BBS access key is exempt from the connection limit. `SYSOP` and `MASTER` key holders are always exempt.

- **Per-module IP gateway** — A BBS menu item can route users through Total IP Control to cap how many simultaneous sessions from one IP may be inside a specific module at once.

- **User profile IP recording** — Writes the real caller IP to a selected user-profile field on each successful login.

- **GeoIP location** — Looks up each caller's approximate City / State / Country from their IP address at login and stores it in a configurable profile field. Lookups run on a background worker thread so login is never delayed, results are cached per IP to minimize API calls, and a failed lookup can never prevent a user from logging in. US states are stored as the standard two-letter abbreviation; locations elsewhere use the most appropriate subdivision plus country. Built around a provider abstraction so additional providers can be added over time.

- **Audit logging** — Daily, timestamped, thread-safe log files split across four categories (proxy events, denied connections, denied module access, and GeoIP activity).

- **Live configuration** — All settings are edited from a full-screen Sysop editor while the BBS is running. Changes take effect immediately and are saved to disk.

---

## Requirements

- The Major BBS v10

---

## Installation

1. Copy the contents of `DIST\1.1.0\` (`SNTIPCTL.DLL`, `SNTIPCTL.MDF`, `SNTIPCTL.MSG`) into the BBS installation directory.
2. Restart the BBS. Total IP Control prints its version and active feature set to the startup log.

On first run, a settings file (`SNTIPCTL.DAT`) is created automatically with all features disabled. Configure the module with `/TOTALIP` (see below).

### Replaces

Remove these modules before loading Total IP Control (If used previously):

- `PROXCLIP` — proxy protocol and real IP restoration
- `IPCTRL` / IPControl — per-IP connection limiting

---

## Configuration

Total IP Control is configured entirely from a live, full-screen editor. A user holding the **Master** key can open it from anywhere on the BBS:

```
/TOTALIP
```

The editor presents four forms:

1. **General Settings**
2. **Trusted Proxy IP/CIDRs** (up to 2 entries)
3. **Connection Limit Whitelist** (up to 10 entries)
4. **GeoIP Location**

Each form is saved or abandoned individually. Saved changes take effect immediately and are written to `SNTIPCTL.DAT`, so they persist across restarts.

### General Settings

| Setting | Values | Description |
|---|---|---|
| Trusted proxy enforcement | YES / NO | Apply PROXY headers only from trusted proxies |
| Require trusted proxy (block direct) | YES / NO | Refuse connections not relayed by a trusted proxy |
| Global connection limit | YES / NO | Enforce the per-IP connection cap |
| Max connections per IP | 1–1000 | Maximum simultaneous sessions per IP |
| Audit logging | YES / NO | Write daily audit log files |
| User profile IP recording | YES / NO | Record the caller IP to the user profile at login |
| Profile field for recorded IP | 1–5 | Which profile field to write (see below) |
| Bypass key | BBS key name | Additional key exempt from the connection limit |

### Address and CIDR notation

Trusted-proxy and whitelist entries accept either a single address (`203.0.113.10`) or CIDR notation (`203.0.113.0/24`). A bare address is treated as `/32`.

### User profile field mapping

When IP recording is enabled, the caller's IPv4 address (dotted-decimal, at most 15 characters) is written to one of these `usracc` fields:

| Field | Profile field | Capacity |
|---|---|---|
| 1 | Address line 1 | 30 characters |
| 2 | Address line 2 | 30 characters |
| 3 | Address line 3 | 30 characters |
| 4 | Address line 4 | 30 characters |
| 5 | Phone number | 16 characters |

---

## GeoIP Location

When enabled, Total IP Control looks up each caller's approximate geographic location from their IP address at login and stores it in one or two user-profile fields (the same 1–5 field mapping shown above).

The lookup runs on a **background worker thread**, so login is never delayed. Results are **cached per IP address**, so repeat logins from the same address make no further API calls. If the provider is unreachable, times out, or returns an error, the lookup is simply skipped and logged — **it can never block or delay a user from logging in.** Private, loopback, and reserved IP addresses are never looked up.

Locations are resolved consistently:

- **United States** — city plus the standard two-letter state abbreviation (e.g. `Minneapolis, MN`).
- **Elsewhere** — city plus the most appropriate subdivision (province / region), using whatever the provider supplies (no assumption that every country has US-style states).

### Write modes

Two write modes control where the pieces go:

- **Split (default)** — the city and state go to one field and the **country** goes to a **separate** field. By default city/state is written to **Address 3** and the country to **Address 4**. This keeps the country in its own dedicated field (useful when other modules read a specific field for country).
- **Combined** — the whole location, including the country, is written to a single field, formatted by the location template (so you can abbreviate the country, e.g. `Minneapolis, MN, US`).

The **country format** setting stores the country either as its **full name** (`United States`) or its **two-letter code** (`US`).

### GeoIP settings

| Setting | Values | Description |
|---|---|---|
| Enable GeoIP lookups | YES / NO | Turn the feature on or off |
| Write mode | COMBINED / SPLIT | One field, or city/state + country in separate fields (default SPLIT) |
| City/State field | 1–5 | Field for the city/state (default 3 = Address 3) |
| Country field | 1–5 | Field for the country in SPLIT mode (default 4 = Address 4) |
| Country format | FULL / CODE | Full name (`United States`) or two-letter code (`US`) |
| GeoIP provider | IPWHO.IS / IP-API.COM / IPAPI.CO | Location provider (cycle with the space bar) |
| API host | host name | Provider host, e.g. `ipwho.is` (change for a paid endpoint) |
| API key / token | text | Leave blank for the keyless free tier; set for a paid plan |
| Use HTTPS | YES / NO | Encrypt the lookup request (recommended: YES) |
| Lookup timeout (seconds) | 1–60 | Per-request network timeout (default 5) |
| Cache mode | OFF / TIME / IP | How results are cached (default TIME — see below) |
| Cache duration (minutes) | 1–44640 | How long a cached location is reused in TIME mode (default 1440 = 24 hours) |
| Retries on failure | 0–5 | Extra attempts after a failed lookup (default 1) |
| Log level | OFF / ERRORS / NORMAL / VERBOSE | GeoIP log detail (see Audit Logs) |
| Location format | template | How the city/state (and country, in COMBINED mode) is formatted (see below) |

> **Providers and HTTPS:** `ipwho.is` and `ipapi.co` support HTTPS on their free tiers; `ip-api.com`'s free tier is HTTP-only (HTTPS needs a paid key), so when `IP-API.COM` is selected without a key, HTTPS is turned off automatically. The two-letter country code (`US`) is the provider's ISO code; a three-letter form (`USA`) is not returned by these providers.

### Cache modes

The **Cache mode** controls when a caller's IP is looked up again:

- **TIME (default)** — a looked-up IP is cached for the **Cache duration**, then looked up again on the next login after it expires. Good if you want locations to refresh periodically.
- **IP** — a looked-up IP is remembered and **never looked up again while the BBS stays up**; only an IP that has not been seen before triggers a lookup. The cache duration is ignored. This minimizes API calls the most: if the same caller returns from the same IP, no request is made regardless of how much time has passed. (The cache is in memory, so it resets on a BBS restart.)
- **OFF** — no caching; every login performs a fresh lookup (subject to the API's own rate limits).

For example, with two different callers a day, **IP** mode looks each up once and then never again (until their IP changes or the BBS restarts), whereas **TIME** mode with a 1440-minute duration looks each up again once a day.

### Location format template

The **Location format** controls exactly how the stored string is assembled, using these tokens:

| Token | Replaced with |
|---|---|
| `{city}` | City name |
| `{region}` | Two-letter state code for US addresses, otherwise the full subdivision name |
| `{country}` | Full country name |
| `{cc}` | Two-letter country code |

The default template is `{city}, {region}, {country}`. Empty pieces are dropped automatically, so a result with no known region collapses cleanly (e.g. `London, United Kingdom`). If the assembled location is longer than the target profile field, it is truncated to fit — choose a shorter template (for example `{city}, {region}` or `{city}, {cc}`) if you prefer compact values.

In **SPLIT** mode the `{country}` and `{cc}` tokens are ignored for the city/state field (the country is written separately to the country field), so `{city}, {region}, {country}` naturally yields `Minneapolis, MN` in the city/state field and the country in its own field.

### Default provider

The shipped default provider is **ipwho.is**, which works out of the box with no signup or API key and supports HTTPS. Its free tier allows a generous number of lookups per day from the server; because results are cached per IP, a typical board stays well within it. A paid API key (set the **API key** and, if required, the **API host**) raises the limit for very busy systems.

> **Tip:** Store the GeoIP location in a *different* profile field from the one used by "User profile IP recording" so the two features do not overwrite each other.

---

## Per-Module IP Gateway

To limit how many simultaneous sessions from one IP may enter a specific module, point a BBS menu item at Total IP Control and supply parameters in the menu command string:

```
MODULE=<name> MAXIP=<n> [BYPASS=<key>[,<key>...]]
```

| Parameter | Required | Description |
|---|---|---|
| `MODULE` | Yes | Target module name (as it appears on the main menu) |
| `MAXIP` | No | Maximum simultaneous sessions per IP in that module (default 1) |
| `BYPASS` | No | Comma-separated BBS access keys that skip the limit (default `SYSOP`) |

Examples:

```
MODULE=TRADEWARS MAXIP=2 BYPASS=SYSOP,COSYSOP
MODULE=GLOBALWAR MAXIP=1
```

Users who hold a bypass key are forwarded immediately and their sessions do not count against the limit for other users from the same IP. Users over the limit see a message naming the others from their IP already in that module.

---

## Audit Logs

When audit logging is enabled, daily log files are written under `TOTALIPCONTROL\`, split into three folders:

| Folder | Contents |
|---|---|
| `PROXCLIP LOGS\` | Proxy header processing, untrusted-source rejections, profile IP writes |
| `DENIED CONNECTIONS\` | Global per-IP connection-limit refusals |
| `DENIED MODULE ACCESS\` | Per-module gateway denials |
| `GEOIP LOGS\` | GeoIP lookups, cache hits/misses, API errors, rate limiting, and profile updates |

The first three folders are written when **Audit logging** is enabled. The `GEOIP LOGS\` folder has its own **Log level** control on the GeoIP form (independent of the main audit toggle):

| Log level | Records |
|---|---|
| OFF | Nothing |
| ERRORS | Failed lookups, API errors, rate limiting (HTTP 429), dropped requests |
| NORMAL | The above, plus successful lookups and profile updates |
| VERBOSE | The above, plus cache hits/misses and skipped private IPs |

Files are named `YYYY-MM-DD.LOG`. Each line records one event:

```
YYYY-MM-DD HH:MM:SS  <userid>             <ip>             <event>
2026-06-18 14:32:07  JohnDoe              203.0.113.4      Proxy header processed on channel 03, real IP 203.0.113.4
2026-06-18 14:33:12  JaneSmith            203.0.113.22     Connection limit exceeded (3 active, max 2) -- session rejected
```

Logging is thread-safe; multiple channels can write concurrently.

---

## Credits

- **Developer:** Mark Laudenbach
- **R&D / Testing:** Gregory McGill

Total IP Control is maintained by Sysop Network.

## License

Released under the MIT License. See [LICENSE](LICENSE) for details.
