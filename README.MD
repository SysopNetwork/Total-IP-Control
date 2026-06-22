# Total IP Control

**Total IP Control** (`SNTIPCTL`) is a unified IP-management module for **The Major BBS v10**. It restores real caller IPs from a reverse proxy, enforces per-IP connection limits, records caller IPs to user profiles, and writes a full audit trail — all configurable live from the BBS, with settings stored on disk so they survive a restart.

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

- **Audit logging** — Daily, timestamped, thread-safe log files split across three categories (proxy events, denied connections, denied module access).

- **Live configuration** — All settings are edited from a full-screen Sysop editor while the BBS is running. Changes take effect immediately and are saved to disk.

---

## Requirements

- The Major BBS v10
- `GALTNTD.DLL`, loaded **before** `SNTIPCTL` in `wgserv.cfg`

---

## Installation

1. Copy the contents of `DIST\1.0.0\` (`SNTIPCTL.DLL`, `SNTIPCTL.MDF`, `SNTIPCTL.MSG`) into the BBS installation directory.
2. Run **GCNF** to compile `SNTIPCTL.MSG` into `SNTIPCTL.MCV`.
3. Add `SNTIPCTL` to `wgserv.cfg`, listed **after** `GALTNTD`. This order is required: if `SNTIPCTL` loads first, the connection hook is unavailable and proxy detection will not function.
4. Restart the BBS. Total IP Control prints its version and active feature set to the startup log.

On first run, a settings file (`SNTIPCTL.DAT`) is created automatically with all features disabled. Configure the module with `/TOTALIP` (see below).

### Replaces

Remove these modules before loading Total IP Control:

- `PROXCLIP` — proxy protocol and real IP restoration
- `IPCTRL` / IPControl — per-IP connection limiting

---

## Configuration

Total IP Control is configured entirely from a live, full-screen editor. A user holding the **Master** key can open it from anywhere on the BBS:

```
/TOTALIP
```

The editor presents three forms:

1. **General Settings**
2. **Trusted Proxy IP/CIDRs** (up to 2 entries)
3. **Connection Limit Whitelist** (up to 10 entries)

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

Users who hold a bypass key are forwarded immediately; users over the limit see a message naming the others from their IP already in that module.

---

## Audit Logs

When audit logging is enabled, daily log files are written under `TOTALIPCONTROL\`, split into three folders:

| Folder | Contents |
|---|---|
| `PROXCLIP LOGS\` | Proxy header processing, untrusted-source rejections, profile IP writes |
| `DENIED CONNECTIONS\` | Global per-IP connection-limit refusals |
| `DENIED MODULE ACCESS\` | Per-module gateway denials |

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
