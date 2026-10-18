// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Maxi2710

using System.Text.Json;
using System.Web;

namespace TechnitiumPrefixUpdate
{
    /// Summary: Raised whenever the Technitium API responds with a non-"ok" status or a transport error occurs.
    public sealed class TechnitiumApiException : Exception
    {
        /// Summary:
        /// True when the API rejected the request because the API token/user lacks permission
        /// for the requested zone/operation (as opposed to e.g. a network or "zone not found"
        /// error). Detected heuristically from the error message text returned by Technitium,
        /// since the API does not expose a distinct machine-readable error code for this.
        public bool IsPermissionError { get; }

        public TechnitiumApiException(string message, bool isPermissionError = false) : base(message)
        {
            IsPermissionError = isPermissionError;
        }

        public TechnitiumApiException(string message, Exception inner) : base(message, inner) { }
    }

    /// Summary: Small typed wrapper around the subset of the Technitium DNS Server HTTP API used by this app.
    public sealed class TechnitiumApiClient
    {
        private readonly HttpClient _http;
        private readonly string _baseUrl;
        private readonly string _apiToken;

        public TechnitiumApiClient(HttpClient http, string baseUrl, string apiToken)
        {
            _http = http;
            _baseUrl = baseUrl.TrimEnd('/');
            _apiToken = apiToken;
        }

        /// Summary: Performs a GET request against the Technitium API and validates the "status" field of the response.
        private async Task<JsonElement> ApiGetAsync(string path, IDictionary<string, string> parameters, CancellationToken cancellationToken)
        {
            var query = HttpUtility.ParseQueryString(string.Empty);
            query["token"] = _apiToken;
            foreach (var (key, value) in parameters)
                query[key] = value;

            string url = $"{_baseUrl}{path}?{query}";

            HttpResponseMessage response;
            try
            {
                response = await _http.GetAsync(url, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                throw new TechnitiumApiException($"HTTP/API connection error calling {path}: {ex.Message}", ex);
            }

            string body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

            JsonDocument document;
            try
            {
                document = JsonDocument.Parse(body);
            }
            catch (JsonException ex)
            {
                throw new TechnitiumApiException($"API error: response from {path} is not valid JSON.", ex);
            }

            using (document)
            {
                JsonElement root = document.RootElement.Clone();

                string? status = root.TryGetProperty("status", out JsonElement statusEl) ? statusEl.GetString() : null;
                if (!string.Equals(status, "ok", StringComparison.OrdinalIgnoreCase))
                {
                    string? errorMessage = root.TryGetProperty("errorMessage", out JsonElement errEl) ? errEl.GetString() : body;

                    // Technitium doesn't return a distinct error code for permission failures,
                    // so detect them from the message text.
                    bool isPermissionError = errorMessage is not null &&
                        (errorMessage.Contains("permission", StringComparison.OrdinalIgnoreCase) ||
                         errorMessage.Contains("not authorized", StringComparison.OrdinalIgnoreCase) ||
                         errorMessage.Contains("access was denied", StringComparison.OrdinalIgnoreCase) ||
                         errorMessage.Contains("access denied", StringComparison.OrdinalIgnoreCase));

                    throw new TechnitiumApiException($"API returned error for {path}: {errorMessage}", isPermissionError);
                }

                return root;
            }
        }

        /// Summary:
        /// GET /api/zones/list, parsed into <see cref="ZoneInfo"/> entries (type, DNSSEC status,
        /// disabled flag, catalog membership). Shared by the AAAA update and PTR migration paths.
        public async Task<List<ZoneInfo>> GetAllZonesAsync(CancellationToken cancellationToken)
        {
            JsonElement root = await ApiGetAsync("/api/zones/list", new Dictionary<string, string>(), cancellationToken).ConfigureAwait(false);

            var zones = new List<ZoneInfo>();
            if (root.TryGetProperty("response", out JsonElement responseEl) &&
                responseEl.TryGetProperty("zones", out JsonElement zonesEl))
            {
                foreach (JsonElement zoneEl in zonesEl.EnumerateArray())
                {
                    string name = zoneEl.GetProperty("name").GetString() ?? "";
                    bool isInternal = zoneEl.TryGetProperty("internal", out JsonElement internalEl) && internalEl.GetBoolean();
                    string type = zoneEl.TryGetProperty("type", out JsonElement typeEl) ? typeEl.GetString() ?? "" : "";
                    string? catalog = zoneEl.TryGetProperty("catalog", out JsonElement catalogEl) ? catalogEl.GetString() : null;
                    bool disabled = zoneEl.TryGetProperty("disabled", out JsonElement disabledEl) && disabledEl.GetBoolean();
                    // "dnssecStatus" is e.g. "Unsigned", "SignedWithNSEC". A missing field
                    // (older Technitium versions) is treated as "Unsigned".
                    string dnssecStatus = zoneEl.TryGetProperty("dnssecStatus", out JsonElement dnssecEl) ? dnssecEl.GetString() ?? "Unsigned" : "Unsigned";

                    zones.Add(new ZoneInfo(name, catalog, type, isInternal, disabled, dnssecStatus));
                }
            }

            return zones;
        }

        /// Summary: GET /api/zones/list, filtered down to primary, non-internal ip6.arpa (PTR) zones.
        public async Task<List<ZoneInfo>> GetIpv6PtrZonesAsync(CancellationToken cancellationToken)
        {
            List<ZoneInfo> allZones = await GetAllZonesAsync(cancellationToken).ConfigureAwait(false);

            return allZones
                .Where(z => z.Name.EndsWith(".ip6.arpa", StringComparison.OrdinalIgnoreCase) &&
                            !z.Internal &&
                            string.Equals(z.Type, "Primary", StringComparison.OrdinalIgnoreCase))
                .ToList();
        }

        /// Summary:
        /// GET /api/zones/options/get - returns the raw zone options object (query/transfer/notify/
        /// update ACLs, disabled flag, ...). Kept as a raw JsonElement so fields this app doesn't
        /// know about are still forwarded by <see cref="ApplyZoneOptionsAsync"/>.
        public async Task<JsonElement?> GetZoneOptionsAsync(string zoneName, CancellationToken cancellationToken)
        {
            JsonElement root = await ApiGetAsync("/api/zones/options/get", new Dictionary<string, string>
            {
                ["zone"] = zoneName,
                ["includeAvailableCatalogZoneNames"] = "false"
            }, cancellationToken).ConfigureAwait(false);

            return root.TryGetProperty("response", out JsonElement responseEl) ? responseEl.Clone() : null;
        }

        /// Summary:
        /// Fields returned by /api/zones/options/get that must NOT be forwarded as-is to
        /// /api/zones/options/set: identifying/read-only fields, fields with a dedicated endpoint
        /// (DNSSEC, catalog via <see cref="SetZoneCatalogAsync"/>), and updateSecurityPolicies,
        /// which needs special formatting and is handled explicitly in <see cref="ApplyZoneOptionsAsync"/>.
        private static readonly HashSet<string> ZoneOptionsReadOnlyFields = new(StringComparer.OrdinalIgnoreCase)
        {
            "name", "type", "internal", "dnssecStatus", "soaSerial", "notifyFailed", "notifyFailedFor",
            "catalog", "availableCatalogZoneNames", "availableTsigKeyNames", "updateSecurityPolicies"
        };

        /// Summary:
        /// Applies the options of the old zone (<paramref name="oldZoneName"/>, as returned by
        /// <see cref="GetZoneOptionsAsync"/>) to <paramref name="zoneName"/> via
        /// /api/zones/options/set. Preserves the ACLs, zone transfer TSIG key names, dynamic
        /// update security policies and the disabled flag across a PTR zone recreation.
        public async Task ApplyZoneOptionsAsync(string zoneName, string oldZoneName, JsonElement sourceOptions, CancellationToken cancellationToken)
        {
            var parameters = new Dictionary<string, string> { ["zone"] = zoneName };

            foreach (JsonProperty property in sourceOptions.EnumerateObject())
            {
                if (ZoneOptionsReadOnlyFields.Contains(property.Name))
                    continue;

                string? value = property.Value.ValueKind switch
                {
                    JsonValueKind.String => property.Value.GetString(),
                    JsonValueKind.True => "true",
                    JsonValueKind.False => "false",
                    JsonValueKind.Number => property.Value.GetRawText(),
                    // Array fields (network ACLs, zoneTransferTsigKeyNames, notify name servers,
                    // etc.) are sent as comma-separated lists. An empty array must be sent as the
                    // literal string "false", that's the documented way to clear such a field.
                    JsonValueKind.Array => property.Value.GetArrayLength() == 0
                        ? "false"
                        : string.Join(',', property.Value.EnumerateArray()
                            .Select(e => e.ValueKind == JsonValueKind.String ? e.GetString() : e.GetRawText())),
                    _ => null
                };

                if (value is not null)
                    parameters[property.Name] = value;
            }

            // updateSecurityPolicies is a table of {tsigKeyName, domain, allowedTypes[]} rows,
            // flattened by Technitium into one string using "|" as both column and row
            // separator, e.g.:
            //   key.example.com|example.com|A,AAAA|key.example.com|*.example.com|ANY
            // The domains still point into the OLD zone, but options/set rejects domains that are
            // not part of the zone being configured (and aborts the whole call), so they have to
            // be remapped to the new zone first.
            if (sourceOptions.TryGetProperty("updateSecurityPolicies", out JsonElement policiesEl) && policiesEl.ValueKind == JsonValueKind.Array)
            {
                List<string> rowParts = new();
                foreach (JsonElement policy in policiesEl.EnumerateArray())
                {
                    string tsigKeyName = policy.TryGetProperty("tsigKeyName", out JsonElement k) ? k.GetString() ?? "" : "";
                    string domain = policy.TryGetProperty("domain", out JsonElement d) ? d.GetString() ?? "" : "";
                    string allowedTypes = policy.TryGetProperty("allowedTypes", out JsonElement t) && t.ValueKind == JsonValueKind.Array
                        ? string.Join(',', t.EnumerateArray().Select(e => e.GetString()))
                        : "";

                    rowParts.Add(tsigKeyName);
                    rowParts.Add(Ipv6Helper.MapRecordDomainToNewZone(domain, oldZoneName, zoneName));
                    rowParts.Add(allowedTypes);
                }

                // An empty table must be sent as "false" (see above), not as an empty string.
                parameters["updateSecurityPolicies"] = rowParts.Count > 0 ? string.Join('|', rowParts) : "false";
            }

            await ApiGetAsync("/api/zones/options/set", parameters, cancellationToken).ConfigureAwait(false);
        }

        /// Summary: GET /api/zones/permissions/get - the zone's "Permissions" tab data (per-user and per-group View/Modify/Delete grants).
        public async Task<JsonElement?> GetZonePermissionsAsync(string zoneName, CancellationToken cancellationToken)
        {
            JsonElement root = await ApiGetAsync("/api/zones/permissions/get", new Dictionary<string, string>
            {
                ["zone"] = zoneName,
                ["includeUsersAndGroups"] = "false"
            }, cancellationToken).ConfigureAwait(false);

            return root.TryGetProperty("response", out JsonElement responseEl) ? responseEl.Clone() : null;
        }

        /// Summary:
        /// Applies another zone's user/group permissions to <paramref name="zoneName"/>. Both
        /// parameters use Technitium's "|"-flattened table format (name, canView, canModify,
        /// canDelete per row). Skips the call if there is nothing to copy.
        public async Task ApplyZonePermissionsAsync(string zoneName, JsonElement sourcePermissions, CancellationToken cancellationToken)
        {
            var parameters = new Dictionary<string, string> { ["zone"] = zoneName };

            if (sourcePermissions.TryGetProperty("userPermissions", out JsonElement usersEl) && usersEl.ValueKind == JsonValueKind.Array)
            {
                string? userTable = FlattenPermissionTable(usersEl, "username");
                if (userTable is not null)
                    parameters["userPermissions"] = userTable;
            }

            if (sourcePermissions.TryGetProperty("groupPermissions", out JsonElement groupsEl) && groupsEl.ValueKind == JsonValueKind.Array)
            {
                string? groupTable = FlattenPermissionTable(groupsEl, "name");
                if (groupTable is not null)
                    parameters["groupPermissions"] = groupTable;
            }

            if (parameters.Count <= 1)
                return;

            await ApiGetAsync("/api/zones/permissions/set", parameters, cancellationToken).ConfigureAwait(false);
        }

        /// Summary: Flattens an array of {identifierField, canView, canModify, canDelete} objects into Technitium's "|"-separated table format. Returns null if the array is empty.
        private static string? FlattenPermissionTable(JsonElement entries, string identifierField)
        {
            List<string> parts = new();

            foreach (JsonElement entry in entries.EnumerateArray())
            {
                string identifier = entry.TryGetProperty(identifierField, out JsonElement idEl) ? idEl.GetString() ?? "" : "";
                bool canView = entry.TryGetProperty("canView", out JsonElement v) && v.GetBoolean();
                bool canModify = entry.TryGetProperty("canModify", out JsonElement m) && m.GetBoolean();
                bool canDelete = entry.TryGetProperty("canDelete", out JsonElement del) && del.GetBoolean();

                if (string.IsNullOrEmpty(identifier))
                    continue;

                parts.Add(identifier);
                parts.Add(canView ? "true" : "false");
                parts.Add(canModify ? "true" : "false");
                parts.Add(canDelete ? "true" : "false");
            }

            return parts.Count > 0 ? string.Join('|', parts) : null;
        }

        /// Summary: GET /api/zones/records/get for the given zone.
        public async Task<List<DnsRecord>> GetRecordsAsync(string zoneName, CancellationToken cancellationToken)
        {
            JsonElement root = await ApiGetAsync("/api/zones/records/get", new Dictionary<string, string>
            {
                ["domain"] = zoneName,
                ["zone"] = zoneName,
                ["listZone"] = "true"
            }, cancellationToken).ConfigureAwait(false);

            var records = new List<DnsRecord>();
            if (root.TryGetProperty("response", out JsonElement responseEl) &&
                responseEl.TryGetProperty("records", out JsonElement recordsEl))
            {
                foreach (JsonElement recordEl in recordsEl.EnumerateArray())
                    records.Add(DnsRecord.FromJson(recordEl));
            }

            return records;
        }

        /// Summary:
        /// GET /api/zones/records/update for an AAAA record. The existing comment is re-sent
        /// explicitly because Technitium clears it when the "comments" parameter is omitted.
        public Task UpdateAaaaRecordAsync(string domain, string zoneName, string oldIp, string newIp, int ttl, string? comments, CancellationToken cancellationToken)
        {
            var parameters = new Dictionary<string, string>
            {
                ["domain"] = domain,
                ["zone"] = zoneName,
                ["type"] = "AAAA",
                ["IpAddress"] = oldIp,
                ["newIpAddress"] = newIp,
                ["ttl"] = ttl.ToString()
            };

            if (!string.IsNullOrEmpty(comments))
                parameters["comments"] = comments;

            return ApiGetAsync("/api/zones/records/update", parameters, cancellationToken);
        }

        /// Summary: GET /api/zones/create for a new Primary zone.
        public Task CreateZoneAsync(string zoneName, CancellationToken cancellationToken)
        {
            return ApiGetAsync("/api/zones/create", new Dictionary<string, string>
            {
                ["zone"] = zoneName,
                ["type"] = "Primary"
            }, cancellationToken);
        }

        /// Summary: GET /api/zones/delete.
        public Task DeleteZoneAsync(string zoneName, CancellationToken cancellationToken)
        {
            return ApiGetAsync("/api/zones/delete", new Dictionary<string, string>
            {
                ["zone"] = zoneName
            }, cancellationToken);
        }

        /// Summary: GET /api/zones/options/set to apply a catalog zone assignment.
        public Task SetZoneCatalogAsync(string zoneName, string catalogZoneName, CancellationToken cancellationToken)
        {
            return ApiGetAsync("/api/zones/options/set", new Dictionary<string, string>
            {
                ["zone"] = zoneName,
                ["catalog"] = catalogZoneName
            }, cancellationToken);
        }

        /// Summary: GET /api/zones/records/add for a PTR record.
        public Task AddPtrRecordAsync(string zoneName, string domain, string ptrTarget, int ttl, string? comments, CancellationToken cancellationToken)
        {
            var parameters = new Dictionary<string, string>
            {
                ["zone"] = zoneName,
                ["domain"] = domain,
                ["type"] = "PTR",
                ["ptrName"] = ptrTarget,
                ["ttl"] = ttl.ToString()
            };

            if (!string.IsNullOrEmpty(comments))
                parameters["comments"] = comments;

            return ApiGetAsync("/api/zones/records/add", parameters, cancellationToken);
        }
    }

    /// Summary: Represents a zone entry as returned by /api/zones/list.
    public sealed record ZoneInfo(string Name, string? CatalogZoneName, string Type, bool Internal, bool Disabled, string DnssecStatus)
    {
        /// Summary: True if Technitium reports this zone as DNSSEC-signed in any form.
        public bool IsDnssecSigned => !string.Equals(DnssecStatus, "Unsigned", StringComparison.OrdinalIgnoreCase);
    }

    /// Summary: Represents a single DNS resource record as returned by /api/zones/records/get.
    public sealed class DnsRecord
    {
        public required string Name { get; init; }
        public required string Type { get; init; }

        /// Summary: The IPv6 address, only populated for AAAA records.
        public string? IpAddress { get; init; }

        /// Summary: The PTR target domain name, only populated for PTR records.
        public string? PtrName { get; init; }

        /// Summary: The free-text comment of this record (Technitium only has per-record comments, no zone-level ones).
        public string? Comments { get; init; }

        public static DnsRecord FromJson(JsonElement element)
        {
            string name = element.GetProperty("name").GetString() ?? "";
            string type = element.GetProperty("type").GetString() ?? "";
            string? comments = element.TryGetProperty("comments", out JsonElement commentsEl) ? commentsEl.GetString() : null;

            string? ipAddress = null;
            string? ptrName = null;

            if (element.TryGetProperty("rData", out JsonElement rData))
            {
                if (type == "AAAA" && rData.TryGetProperty("ipAddress", out JsonElement ipEl))
                    ipAddress = ipEl.GetString();

                if (type == "PTR")
                {
                    if (rData.TryGetProperty("ptrName", out JsonElement ptrEl))
                        ptrName = ptrEl.GetString();
                    else if (rData.TryGetProperty("value", out JsonElement valueEl))
                        ptrName = valueEl.GetString();
                }
            }

            return new DnsRecord { Name = name, Type = type, IpAddress = ipAddress, PtrName = ptrName, Comments = comments };
        }
    }
}
