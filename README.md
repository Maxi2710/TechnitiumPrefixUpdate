# TechnitiumPrefixUpdate

An app for [Technitium DNS Server](https://technitium.com/dns/) ([source](https://github.com/TechnitiumSoftware/DnsServer)). that automatically updates AAAA records and IPv6 PTR zones when your ISP's IPv6 prefix changes. This is an independent project and not affiliated with Technitium.

The app runs inside the DNS server process and opens its own HTTP endpoint. Your router/script calls it on a prefix change with an address from the new prefix.

---
## Features

- Updates AAAA records in primary zones. The ISP prefix is replaced, the host bits and comments stay intact.
- Migrates PTR zones: creates a new zone for the new prefix, copies all PTR records including comments, and deletes the old zone.
- Copies zone options (catalog zone, query access, zone transfer, ...) and permissions to the new PTR zone.
- Configurable prefix filter with allowed and ignored prefixes, e.g. to keep a static tunnelbroker.net or ULA prefix untouched.
- Optional compact response with just an `OK` if no major errors occurred. Helpful for routers that can't handle detailed responses.

> [!WARNING]
> Migrating PTR zones breaks DNSSEC. DNSSEC signed PTR zones are therefore skipped by default.

---
## Requirements

- Technitium DNS Server v15.3 or newer
- A Technitium API token
- A client that can send an HTTP GET request on prefix change

---
## How it works

1. The router or script calls the endpoint with `ip=<any address from the new prefix>`.
2. The app calculates the prefix from the address and `general.ispPrefixLength`, e.g. `2001:db8:abcd:1::5` with `56` becomes `2001:db8:abcd::/56`.
3. **AAAA:** In every zone listed in `zones`, each AAAA record that passes the prefix filter gets its first `ispPrefixLength` bits replaced by the new prefix. Everything after that is kept.
4. **PTR:** Every primary IPv6 PTR zone that passes the prefix filter is recreated under the new prefix, and all its PTR records are copied to the new zone. The old zone is then deleted.

> [!IMPORTANT]
> Every AAAA record in a configured zone that passes the prefix filter is rewritten, regardless of its current prefix. Records pointing to hosts outside your network must be excluded via `ignoredPrefixes`. Export your zones before the first run.

---
## Installation

1. Technitium Web UI → `Apps` → `Install` → upload the zip → `Install`
2. Click `Config` next to the app and adjust the configuration
3. Click `Save`. The app will restart automatically.

If the configuration is invalid, the app stays disabled. The reason is written to the Technitium log.

---
## Configuration

```json
{
    "general": {
        "technitiumUrl": "http://localhost:5380",
        "apiToken": "change-me",
        "ispPrefixLength": 56,
        "listenPort": 8080
    },
    "zones": [
        "example.home.arpa"
    ],
    "dns": {
        "ttl": 300,
        "ptr": true,
        "migrateSignedZones": false,
        "copyZoneSettings": true
    },
    "prefixFilter": {
        "allowedPrefixes": [
            "2000::/3"
        ],
        "ignoredPrefixes": [
            "2001:db8::/32",
            "3fff::/20",
            "2002::/16",
            "2001::/32"
        ]
    }
}
```

| Key                            | Type     | Description                                                                                               |
| ------------------------------ | -------- | --------------------------------------------------------------------------------------------------------- |
| `general.technitiumUrl`        | String   | Technitium URL                                                                                            |
| `general.apiToken`             | String   | API token, created in the Technitium Web UI. The same token must be provided in the Update URL            |
| `general.ispPrefixLength`      | Int      | IPv6 prefix length delegated by your ISP (1–64)                                                           |
| `general.listenPort`           | Int      | Port of the update endpoint                                                                               |
| `zones`                        | String[] | Primary zones whose AAAA records should be updated by the app                                             |
| `dns.ttl`                      | Int      | TTL for updated AAAA records and migrated PTR records                                                     |
| `dns.ptr`                      | Bool     | Enable/disable migration of PTR zones                                                                     |
| `dns.migrateSignedZones`       | Bool     | Enable/disable migration of DNSSEC signed PTR zones. New zones are not re-signed, see the warning above   |
| `dns.copyZoneSettings`         | Bool     | Enable/disable migration of zone options and permissions (catalog zone, query access, zone transfer, ...) |
| `prefixFilter.allowedPrefixes` | String[] | Only addresses and PTR zones inside one of these prefixes are updated. At least one entry is required     |
| `prefixFilter.ignoredPrefixes` | String[] | Addresses and PTR zones inside one of these prefixes are never touched.                                   |

> [!NOTE]
> The token is sent over plain HTTP. Restrict access to the listener port to your router/script for better security.

### Prefix Filter

The filter defines which records the app is allowed to update. It applies to AAAA records, PTR zones, and the address submitted in the HTTP request. The values in the example are conservative defaults, meant to be changed to fit your setup.

- An address is eligible if it is inside at least one allowed prefix and inside no ignored prefix. If it matches both, the ignored prefix wins.
- A PTR zone must be completely inside an allowed prefix and must not overlap any ignored prefix.

The example config limits updates to global unicast addresses (`2000::/3`) and ignores these ranges:

| Prefix      | Usage         |
| ----------- | ------------- |
| `2001::/32` | Documentation |
| `3fff::/20` | Documentation |
| `2002::/16` | 6to4          |
| `2001::/32` | Teredo        |
ULA (`fc00::/7`) is not listed because it is already outside `2000::/3`.

---
## Usage

```bash
curl "http://[fd00:1234:abcd:1::53]:8080/?ip=2001:abcd:abcd::1&token=change-me"
```

| `ip`      | Any address from the new IPv6 prefix, without a `/length` suffix. The prefix is calculated from it using `general.ispPrefixLength` |
| --------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `token`   | The `general.apiToken` from the configuration                                                                                      |

### Response example

```
Prefix update processed: 2001:db8:abcd::/56
AAAA zones:
  [OK] example.home.arpa: 5 updated, 0 unchanged, 0 failed (of 5 eligible AAAA records), 0 excluded by prefix filter.
PTR zones:
  [OK] 0.0.0.0.x.x.x.x.ip6.arpa -> 0.0.0.0.y.y.y.y.ip6.arpa: Migrated successfully: 5 PTR record(s) copied to '...'.
```

### HTTP status codes

| Code  | Meaning                                                                  |
| ----- | ------------------------------------------------------------------------ |
| `200` | Everything OK                                                            |
| `207` | One or more zones were skipped or failed                                 |
| `400` | `ip` is missing, not an IPv6 address, or does not pass the prefix filter |
| `403` | Wrong token                                                              |
| `500` | Unexpected error                                                         |
| `502` | Technitium API unreachable or token invalid                              |

### Compact response

Some routers can't handle multi line responses. With `short=yes` in the update URL, the app replies with just `OK` if no major problem occurred. On real errors it returns `207` with a short error message.

```bash
curl "http://[fd00:1234:abcd:1::53]:8080/?ip=2001:abcd:abcd::1&token=change-me&short=yes"
```

---
## Build

Requirements: [.NET 10 SDK](https://learn.microsoft.com/en-us/dotnet/core/install), `zip`, and the DLLs from the Technitium installation the app will run on.

1. Install the .NET SDK:
```bash
   sudo apt-get update && sudo apt-get install -y dotnet-sdk-10.0 zip
```
 
2. Clone the repository:
```bash
   git clone <repository-url>
   cd TechnitiumPrefixUpdate
```
 
3. Copy the required DLLs from your Technitium installation into `libs/`:
```bash
   mkdir libs
   cp /opt/technitium/dns/DnsServerCore.ApplicationCommon.dll libs/
   cp /opt/technitium/dns/TechnitiumLibrary.Net.dll libs/
```
 
4. Build:
```bash
   dotnet build -c Release
```
 
5. Create the zip for the app import:
```bash
   cd bin/Release
   zip -j TechnitiumPrefixUpdate.zip TechnitiumPrefixUpdate.dll dnsApp.config
```