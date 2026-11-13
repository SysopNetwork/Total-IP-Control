<div align="center">

```
         ████████╗ ██████╗ ████████╗ █████╗ ██╗        ██╗██████╗
         ╚══██╔══╝██╔═══██╗╚══██╔══╝██╔══██╗██║        ██║██╔══██╗
            ██║   ██║   ██║   ██║   ███████║██║        ██║██████╔╝
            ██║   ██║   ██║   ██║   ██╔══██║██║        ██║██╔═══╝
            ██║   ╚██████╔╝   ██║   ██║  ██║███████╗   ██║██║
            ╚═╝    ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚══════╝   ╚═╝╚═╝

        ██████╗ ██████╗ ███╗   ██╗████████╗██████╗  ██████╗ ██╗
       ██╔════╝██╔═══██╗████╗  ██║╚══██╔══╝██╔══██╗██╔═══██╗██║
       ██║     ██║   ██║██╔██╗ ██║   ██║   ██████╔╝██║   ██║██║
       ██║     ██║   ██║██║╚██╗██║   ██║   ██╔══██╗██║   ██║██║
       ╚██████╗╚██████╔╝██║ ╚████║   ██║   ██║  ██║╚██████╔╝███████╗
        ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
```

**Real caller IPs, per-IP connection limits, GeoIP and a full audit trail for The Major BBS v10 — in one module.**

By **[Sysop Network](https://github.com/SysopNetwork)** — https://github.com/SysopNetwork/Total-IP-Control

[![The Major BBS](https://img.shields.io/badge/The%20Major%20BBS-v10-blue)](https://github.com/SysopNetwork/Total-IP-Control)
[![Release](https://img.shields.io/badge/release-v2.0.0-brightgreen)](https://github.com/SysopNetwork/Total-IP-Control/releases)
[![Language](https://img.shields.io/badge/language-C-555555?logo=c&logoColor=white)]()
[![Platform](https://img.shields.io/badge/platform-Windows-lightgrey?logo=windows&logoColor=white)]()
[![License](https://img.shields.io/badge/license-MIT-blue?logo=opensourceinitiative&logoColor=white)](LICENSE)

📋 **[See what's new in v2.0.0 →](CHANGELOG.MD)**

</div>

---

**Total IP Control** (`SNTIPCTL`) is a unified IP-management module for **The Major BBS v10**. It restores real caller IPs from a reverse proxy, enforces per-IP connection limits, records caller IPs to user profiles, looks up each caller's approximate geographic location, and writes a full audit trail — all configurable live from the BBS, with settings stored on disk so they survive a restart.

It consolidates and extends two earlier modules, **PROXCLIP** (proxy protocol / real IP restoration) and **IPControl** (per-IP connection limiting), into a single module.

---

## ✨ Features

| | Feature | Description |
|---|---|---|
| 🔀 | **PROXY Protocol v1** | Restores the real caller IP from `PROXY TCP4` and `PROXY TCP6` headers sent by a reverse proxy, for telnet and SSH. The header is consumed the moment it arrives — no polling, no waiting |
| 🌐 | **IPv6 callers** | A caller's real IPv6 address is used everywhere: `/MYIP`, `/WHOSON`, logs, GeoIP, connection limits and the user profile |
| 🛡️ | **Trusted proxies** | Up to 10 trusted proxies each for telnet and SSH; PROXY headers are applied only when they come from one, so headers cannot be spoofed |
| 🚫 | **Block direct connections** | Optionally refuses connections that bypass your proxy, before the login prompt. Loopback and whitelisted addresses are always allowed, and an empty proxy list disables blocking, so a misconfiguration cannot lock you out |
| 🔒 | **SSH policy** | The same trusted-proxy options for SSH, configured separately from telnet (off by default) |
| 🔢 | **Per-IP connection limits** | A BBS-wide cap on simultaneous sessions from one IP; refused callers are told which sessions are already connected from their IP |
| ✅ | **Whitelists** | Up to 50 IPv4 and 50 IPv6 addresses or ranges that are never subject to the connection limit, plus a bypass key |
| 🚪 | **Per-module gateway** | A menu item can cap how many sessions from one IP may be inside a specific module at once |
| 👤 | **Profile IP recording** | Writes the real caller IP to a chosen user-profile field at each login |
| 🌍 | **GeoIP location** | Looks up each caller's City / State / Country at login on a background thread, with caching and four providers. A failed lookup never delays or blocks a login |
| 📋 | **Audit logging** | The BBS Audit Trail and/or daily log files: logins, proxy events, denied connections, denied module access |
| ⚙️ | **Live configuration** | A sectioned Sysop settings menu (`/TIP`); every change applies at once, is saved, and is noted in the Audit Trail |
| 💬 | **`/MYIP` and `/WHOSON`** | Callers see their own real IP; staff see who is online with connection type, real IP, module and time on line |

---

## 📦 Requirements

- The Major BBS v10

---

## 🚀 Installation

1. Copy the contents of the release folder under `DIST\` (`SNTIPCTL.DLL`, `SNTIPCTL.MDF`, `SNTIPCTL.MSG`, `SNTIPCTL.RLN`) into the BBS installation directory (typically `C:\BBSV10`).
2. Restart the BBS. Total IP Control prints its version and active feature set to the startup log.

**Upgrading from 1.x:** install all four files together. Your settings carry over unchanged. Every message in `SNTIPCTL.MSG` is new, so if you reworded any Total IP Control message in the message editor, note your text first and redo it afterwards. The settings command is now `/TIP` (it was `/TOTALIP`).

On first run, a settings file (`SNTIPCTL.DAT`) is created automatically with all features disabled. Configure the module with `/TIP` (see below).

### Replaces

Remove these modules before loading Total IP Control (If used previously):

- `PROXCLIP` — proxy protocol and real IP restoration
- `IPCTRL` / IPControl — per-IP connection limiting

---

## ⚙️ Configuration

Total IP Control is configured entirely online, while the BBS runs. A user holding the **Master** key opens the settings from anywhere on the BBS:

```
/TIP
```

or from a menu item: in the Menu Tree editor, add an item that runs the **Total IP Control** module with this command line (give the item a Sysop key so only you see it):

```
MENU=SYSOPMENU
```

The settings are grouped into six sections, like the Globals `=gset` menu:

```
╔══════════════════════════════════════════════════════════════════╗
║ Total IP Control v2.0.0                    changes apply at once ║
╚══════════════════════════════════════════════════════════════════╝
 Status: telnet 1 proxy; SSH off; limit 2 per IP; GeoIP on

 1. General Settings          8 settings
 2. Telnet Trusted Proxies    2 settings, 1 proxy
 3. IPv4 Whitelist            0 of 50 in use
 4. IPv6 Whitelist            0 of 50 in use
 5. GeoIP Location            16 settings
 6. SSH Settings              4 settings, 0 proxies

   H. Help     X. Exit
```

Pick a section to list its settings with their current values, numbered from 1. The whitelists show 10 entries a page (`N` next page, `P` previous); any entry's number works from any page. Type a setting's number: the editor shows its value and what is allowed, and you type the new one (blank keeps it). A setting with fixed choices lists them by number. `?` at any prompt explains the setting, `H 2` in a section explains its setting 2, `H` shows a quick-start guide, `-` clears a key, text, or address setting, and `X` goes back one step.

Every change takes effect immediately, is saved to `SNTIPCTL.DAT`, and writes an Audit Trail line naming the Sysop, the section and the setting. A setting that cannot have its effect right now says so, e.g. `YES (inactive: no proxy listed)`.

### 1. General Settings

| # | Setting | Values | Description |
|---|---|---|---|
| 1 | Connection limit | YES / NO | Enforce the per-IP connection cap |
| 2 | Max connections per IP | 1–1000 | Maximum simultaneous sessions per IP |
| 3 | Audit logging | OFF / AUDIT / LOG / BOTH | Where to record events: nothing, the BBS Audit Trail only, daily log files only, or both |
| 4 | Record IP in profile | YES / NO | Record the caller IP to the user profile at login |
| 5 | Profile field for IP | ADDRESS1–4 / PHONE | Which profile field to write (see below) |
| 6 | Limit bypass key | BBS key name | Additional key exempt from the connection limit (SYSOP and MASTER always are) |
| 7 | Staff key for /WHOSON | BBS key name | Key that may use `/WHOSON` (default `SYSOP`) |
| 8 | Debug trace log | YES / NO | Detailed per-connection trace under `TOTALIPCONTROL\DEBUG`, for troubleshooting |

### 2. Telnet Trusted Proxies and 6. SSH Settings

The telnet and SSH policies are stored, and enforced, entirely separately — including their trusted proxy lists — so the two protocols can sit behind different proxies, or one can be locked down while the other is left open.

| # | Telnet Trusted Proxies | Values | Description |
|---|---|---|---|
| 1 | Trusted proxy only | YES / NO | Apply PROXY headers only from the telnet trusted proxies |
| 2 | Block direct connections | YES / NO | Refuse telnet connections not relayed by a trusted proxy |
| 3–12 | Trusted proxy 1–10 | address or range | The proxies trusted for telnet |

| # | SSH Settings | Values | Description |
|---|---|---|---|
| 1 | Manage SSH connections | YES / NO | Master switch. When `NO` (the default) no SSH-specific policy applies |
| 2 | Read PROXY header | YES / NO | Consume a PROXY header on SSH connections and restore the real caller IP |
| 3 | Trusted proxy only | YES / NO | Apply SSH PROXY headers only from the SSH trusted proxies |
| 4 | Block direct connections | YES / NO | Refuse SSH connections not relayed by a trusted SSH proxy |
| 5–14 | Trusted proxy 1–10 | address or range | The proxies trusted for SSH |

Notes:

- Blocking never starts until at least one trusted proxy is listed for that protocol, so an empty list can never lock the BBS out. Loopback (`127.x`) and IPv4 whitelist addresses are never blocked.
- **Turn on SSH header processing only if your front end actually sends the PROXY header on the SSH port.** Most proxies do not unless configured to. With it off, the block still works — SSH sessions simply report the proxy's address as the caller IP.
- A refused SSH connection is **closed without a message**. Nothing has been negotiated at that point, so any text would be read as part of the SSH version exchange. The refusal is written to the `DENIED CONNECTIONS` log.
- SSH header processing requires the SSH Server module (`SNSSH`) to load **before** `SNTIPCTL` in `wgserv.cfg`; the usual alphabetical order already does. If it did not, the menu says the setting is inactive until a restart. Every other SSH setting takes effect on the next SSH connection.

### 3. IPv4 Whitelist and 4. IPv6 Whitelist

Up to 50 IPv4 and 50 IPv6 addresses or ranges (entries 1–50, ten to a page) that are never subject to the connection limit. IPv4 whitelist addresses are also always let in when direct connections are blocked.

### 5. GeoIP Location

See [GeoIP Location](#-geoip-location) below.

### Address and CIDR notation

Trusted-proxy, SSH trusted-proxy, and whitelist entries accept either a single address (`203.0.113.10`) or CIDR notation (`203.0.113.0/24`). A bare address is treated as `/32`.

### User profile field mapping

When IP recording is enabled, the caller's IP address is written to one of these user account fields:

| Choice | Profile field | Holds |
|---|---|---|
| ADDRESS1 | Address line 1 | 29 characters |
| ADDRESS2 | Address line 2 | 29 characters |
| ADDRESS3 | Address line 3 | 29 characters |
| ADDRESS4 | Address line 4 | 29 characters |
| PHONE | Phone number | 15 characters |

An IPv6 address too long for the field is stored as its `/64` network (e.g. `2601:648:8600:1234::/64`); the phone field is too short for any IPv6 form and gets the marker `IPv6`.

---

## 🌍 GeoIP Location

When enabled, Total IP Control looks up each caller's approximate geographic location from their IP address at login and stores it in one or two user-profile fields (the same field choices shown above).

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

Section 5 of `/TIP`:

| # | Setting | Values | Description |
|---|---|---|---|
| 1 | GeoIP lookups | YES / NO | Turn the feature on or off |
| 2 | Write mode | COMBINED / SPLIT | One field, or city/state + country in separate fields (default SPLIT) |
| 3 | City/state field | ADDRESS1–4 / PHONE | Field for the city/state (default ADDRESS3) |
| 4 | Country field | ADDRESS1–4 / PHONE | Field for the country in SPLIT mode (default ADDRESS4) |
| 5 | Country format | FULL / CODE | Full name (`United States`) or two-letter code (`US`) |
| 6 | State format | CODE / FULL | Two-letter code (`MN`) or full name (`Minnesota`) |
| 7 | GeoIP provider | IPWHO.IS / IP-API.COM / IPAPI.CO / IPINFO.IO | Location provider |
| 8 | API host | host name | Follows the provider; change only for a paid or regional endpoint |
| 9 | API key | text | Leave clear for the keyless free tier; set for a paid plan (never shown on screen) |
| 10 | Use HTTPS | YES / NO | Encrypt the lookup request (recommended: YES) |
| 11 | Lookup timeout (seconds) | 1–60 | Per-request network timeout (default 5) |
| 12 | Cache | OFF / TIME / IP | How results are cached (default TIME — see below) |
| 13 | Cache duration (minutes) | 1–44640 | How long a cached location is reused in TIME mode (default 1440 = 24 hours) |
| 14 | Retries on failure | 0–5 | Extra attempts after a failed lookup (default 1) |
| 15 | GeoIP log level | OFF / ERRORS / NORMAL / VERBOSE | GeoIP log detail (see [Audit Logs](#-audit-logs)) |
| 16 | Location format | template | How the city/state (and country, in COMBINED mode) is formatted (see below) |

> **Providers and HTTPS:** `ipwho.is` and `ipapi.co` support HTTPS on their free tiers; `ip-api.com`'s free tier is HTTP-only (HTTPS needs a paid key), so when `IP-API.COM` is selected without a key, HTTPS is turned off automatically. The two-letter country code (`US`) is the provider's ISO code; a three-letter form (`USA`) is not returned by these providers.

### Cache modes

The **Cache** setting controls when a caller's IP is looked up again:

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

## 🚪 Per-Module IP Gateway

To limit how many simultaneous sessions from one IP may enter a specific module, point a BBS menu item at Total IP Control and supply parameters in the menu command string:

```
MODULE=<name> MAXIP=<n> [BYPASS=<key>[,<key>...]]
```

| Parameter | Required | Description |
|---|---|---|
| `MODULE` | Yes | Target module name (as it appears on the main menu) |
| `MAXIP` | No | Maximum simultaneous sessions per IP in that module (default 1) |
| `BYPASS` | No | Comma-separated BBS access keys that skip the limit (default `SYSOP`) |

The same menu entry point opens Total IP Control's own screens with `MENU=` instead of `MODULE=`: `MENU=SYSOPMENU` is the settings menu (see Configuration). Other `MENU=` names are reserved for later; an unknown one is refused and noted in the Audit Trail.

Examples:

```
MODULE=TRADEWARS MAXIP=2 BYPASS=SYSOP,COSYSOP
MODULE=GLOBALWAR MAXIP=1
```

Users who hold a bypass key are forwarded immediately and their sessions do not count against the limit for other users from the same IP. Users over the limit see a message naming the others from their IP already in that module.

---

## 📋 Audit Logs

**Audit logging** records to two independent sinks depending on the selected mode: the BBS **Audit Trail** (the live sysop log) and/or daily **log files** under `TOTALIPCONTROL\`. `AUDIT` writes only the Audit Trail, `LOG` writes only the files, `BOTH` writes both, and `OFF` writes neither. Recorded events include every login's real IP (telnet at connect time; SSH and other daemons at login, tagged with protocol and user ID), untrusted/direct refusals, and connection- and gateway-limit denials.

The daily log files (written in `LOG` or `BOTH` mode) are split into folders:

| Folder | Contents |
|---|---|
| `LOGINS\` | **Who connected and from where** — one line per successful login (all protocols): timestamp, user ID, real IP, and protocol |
| `PROXCLIP LOGS\` | Telnet PROXY-header processing, untrusted-source rejections, profile IP writes |
| `DENIED CONNECTIONS\` | Global per-IP connection-limit refusals and require-trusted-proxy blocks |
| `DENIED MODULE ACCESS\` | Per-module gateway denials |
| `GEOIP LOGS\` | GeoIP lookups, cache hits/misses, API errors, rate limiting, and profile updates |

The first four folders are written when **Audit logging** is set to `LOG` or `BOTH`. The `GEOIP LOGS\` folder has its own **GeoIP log level** setting (section 5, independent of the main audit setting):

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

## 💬 Commands

| Command | Who | What it does |
|---|---|---|
| `/TIP` | Master key | Opens the settings menu (also a menu item with `MENU=SYSOPMENU`) |
| `/MYIP` | Anyone | Shows the caller their own real IP address |
| `/WHOSON` | SYSOP, MASTER, or the staff key (General Settings) | Lists who is online with user ID, connection type, real IP, module, and time on line |

All of their text is in `SNTIPCTL.MSG` and can be reworded in the BBS's message editor; dynamic values appear as `N!SNT...` text variables.

---

## 📁 Architecture

Total IP Control is a single DLL loaded by the BBS like any other module. It hooks the telnet server's socket read so a PROXY header is taken off the stream the instant it arrives — before the telnet server or the login prompt ever see it — and applies the real IP to the channel as soon as the BBS assigns one. SSH connections get the same treatment through the SSH Server module. Connection limits, blocking and the gateway then work from the real IP, and GeoIP lookups run on a worker thread so nothing waits on the network. Settings live in `SNTIPCTL.DAT` and are read where they are used, so a change in `/TIP` takes effect on the next connection without a restart.

```
Total-IP-Control/
├── SRC/
│   ├── SNTIPCTL.C           # The module
│   ├── SNTIPCTL.H           # Message numbers and setting constants
│   ├── SNTVER.H             # The version number (code and DLL resource)
│   ├── SNTIPCTL.MSG         # Message file (all user and Sysop text)
│   ├── SNTIPCTL.MDF         # Module descriptor
│   ├── SNTIPCTL.RC          # Windows version resource
│   ├── SNTIPCTL.vcxproj     # Visual Studio project
│   └── SNTIPCTL_EXP.DEF     # DLL exports
├── DIST/<version>/          # Deployable files: DLL, MDF, MSG, RLN
├── TESTS/                   # Host-side test of the settings menu
├── SNTIPCTL.sln
├── TECHNICAL.MD             # Internals: hooks, data structures, file formats
├── BUILDING.MD              # Toolchain, SDK setup, build and packaging
├── CONFIG-SAMPLE.MD         # Example configurations
├── DEVELOPMENT.md           # Coding conventions
├── CHANGELOG.MD             # Release notes
└── LICENSE
```

---

## 🏆 Credits

Total IP Control is developed and maintained by [Mark Laudenbach](https://github.com/laudenbachm) at [Sysop Network](https://github.com/SysopNetwork). R&D and testing by Gregory McGill.

It grew out of two earlier modules, **PROXCLIP** and **IPControl**.

---

## 💖 Tips / Donations

- **Cash App:** [$laudenbachm](https://cash.app/$laudenbachm)
- **Ko-fi:** [ko-fi.com/laudenbachm](https://ko-fi.com/laudenbachm)

---

## 📄 License

MIT — Copyright (c) 2026 Sysop Network. See [LICENSE](LICENSE).
