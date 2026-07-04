# Total IP Control — Sample Configuration

Total IP Control stores its settings in a Btrieve record (`SNTIPCTL.DAT`), edited
live from the **`/TOTALIP`** full-screen editor (Master key required). There is no
text configuration file to hand-edit; this document lists recommended values to
enter in the editor, with worked examples for the GeoIP Location feature added in
1.1.0.

Open the editor with `/TOTALIP` and choose a form:

```
1. General Settings
2. Trusted Proxy IP/CIDRs
3. Connection Limit Whitelist
4. GeoIP Location
```

Each form saves independently; changes take effect immediately and persist across
restarts.

---

## GeoIP Location — recommended baseline

Form **4. GeoIP Location**. This baseline works out of the box with no signup or
API key.

| Setting | Recommended value | Notes |
|---|---|---|
| Enable GeoIP lookups | `YES` | Turns the feature on |
| Write mode | `SPLIT` | City/state and country in separate fields (default) |
| City/State field | `3` | Address line 3 |
| Country field | `4` | Address line 4 (used in SPLIT mode) |
| Country format | `FULL` | `United States` (or `CODE` for `US`) |
| GeoIP provider | `IPWHO.IS` | Cycle with the space bar |
| API host | `ipwho.is` | Keyless free endpoint |
| API key (blank = free tier) | *(blank)* | Leave empty for the free tier |
| Use HTTPS | `YES` | Encrypt the lookup |
| Lookup timeout (seconds) | `5` | Per-request network timeout |
| Cache mode | `TIME` | Cache per IP; re-look-up after the duration (see below) |
| Cache duration (minutes) | `1440` | 24 hours (used in TIME mode) |
| Retries on failure | `1` | One extra attempt on a failed lookup |
| Log level | `NORMAL` | Log successes + failures (see below) |
| Location format | `{city}, {region}, {country}` | See *Format template* |

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

Set **Write mode** to `COMBINED` to store the whole location in the City/State
field instead. The country then comes from the location template, so you control
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
cleanly. If the assembled value is longer than the target profile field (Address
lines hold 30 characters, Phone holds 16) it is truncated to fit.

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
| API host | *(the provider's paid host, if different)* |
| API key (blank = free tier) | `your-api-key-here` |

The key is sent with the request; caching still applies, so you only pay for
distinct IP addresses within the cache window.

---

## Example: high-traffic board

To minimize API usage on a busy system, use per-IP caching and keep logging quiet:

| Setting | Value | Effect |
|---|---|---|
| Cache mode | `IP` | Each IP is looked up once, then never again while the BBS is up |
| Retries on failure | `0` | Do not retry (fail fast) |
| Log level | `ERRORS` | Log only failures / rate limiting |

In `IP` mode the **Cache duration** is ignored — a known IP is never re-queried,
so the only lookups are for IPs not seen since the last restart. Use `TIME` mode
with a long duration (e.g. `10080` = 7 days) instead if you prefer locations to
refresh periodically.

---

## Log levels

The GeoIP log folder is `TOTALIPCONTROL\GEOIP LOGS\` (daily `YYYY-MM-DD.LOG`
files), controlled by the GeoIP **Log level** independently of the main audit
logging switch:

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
  *User profile IP recording* (General Settings) so the two do not overwrite each
  other.
