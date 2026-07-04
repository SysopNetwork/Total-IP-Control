# ADR 0001 — Asynchronous GeoIP lookups via a background worker thread

**Status:** Accepted (v1.1.0, 2026-07-04)

## Context

The GeoIP Location feature must resolve a caller's City / State / Country from
their IP address at login and store it in a profile field. Resolution requires an
outbound HTTP(S) request to a third-party provider, which can take from tens of
milliseconds to several seconds (or time out entirely).

The Major BBS v10 runs a **single cooperative scheduler thread**. Every module
hook — including the logon supplement (`lonrou`) where an IP first becomes known —
executes on that thread. Any blocking call made from a hook stalls *every* user on
the board for its full duration. The feature requirements are explicit that a
lookup must never delay a login and that a provider failure must never prevent a
user from logging in.

## Decision

Perform the HTTP request on a **dedicated background worker thread**, and marshal
the result back to the main thread for application. Concretely:

1. **Enqueue (main thread, `sntipctl_logon`).** Skip private/reserved IPs; serve
   cache hits immediately; otherwise snapshot a *self-contained* request
   (`struct geo_req`: channel, IP, userid, host, path, HTTPS, timeout, provider,
   retries, format) into a `CRITICAL_SECTION`-guarded queue and signal an event.
   Returns instantly.
2. **Worker thread (`geoip_worker`).** Pops requests, performs one blocking
   WinHTTP GET (`geoip_http_get`, every leg bounded by the configured timeout),
   parses the JSON, and pushes a result. **It calls no Major BBS SDK function**
   and reads no BBS global — only the inert snapshot — because SDK routines are
   not thread-safe and channel-indexed globals (`usrnum`, `tcpipinf`, `usaptr`)
   are reused the instant a channel disconnects. Its only outward action is file
   logging, which is CRT/`fopen`-based and serialized by a critical section.
3. **Drain (main thread, `rtkick(1, geoip_drain)`).** Once per second, applies
   results via `updaccu(uacoff(channel))` after re-checking the channel still
   holds the *same userid* that requested the lookup. This is the only point at
   which a result re-enters the BBS.

A per-IP cache (main-thread only, default 24 h) avoids repeat lookups.

## Alternatives considered

- **Synchronous blocking call in `lonrou`.** Rejected: stalls the whole board for
  the request duration; a slow or dead provider would freeze logins — a direct
  violation of the requirements.
- **Non-blocking sockets polled from a real-time routine.** Rejected: would
  require hand-rolling an HTTP/TLS client over raw sockets. WinHTTP handles TLS
  and redirects correctly; the cost is that its simple API is synchronous, which
  the worker thread absorbs.
- **Applying results directly from the worker thread** (e.g. `curusr`/`updacc`).
  Rejected: the SDK is not thread-safe. All BBS state changes happen on the main
  thread in the `rtkick` drain.

## Consequences

- Login latency is unaffected; a failed, slow, or unreachable provider only
  results in a logged, dropped lookup.
- Correctness depends on the worker never touching BBS state — enforced by passing
  only a value snapshot and by the userid re-validation in the drain.
- Shutdown must join the worker before the DLL unloads: `finrou` → `geoip_stop()`
  signals the stop event, waits for the thread, then frees the events and critical
  section. The drain is guarded so a stray queued `rtkick` after shutdown is a
  no-op.
- Adds a link-time dependency on `winhttp.lib` (standard Windows SDK).

## Related

- Provider abstraction: `geoip_build_url()` / `geoip_parse_body()` — adding a
  provider is one `case` in each. Default provider: **ipwho.is**.
- See `TECHNICAL.MD` → *GeoIP Location* for the full data-flow description.
