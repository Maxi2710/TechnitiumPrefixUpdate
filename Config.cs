// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Maxi2710

using System.Net;
using System.Text.Json.Serialization;

namespace TechnitiumPrefixUpdate
{
    /// Summary: Root configuration object, deserialized from the "dnsApp.config" content that Technitium passes into InitializeAsync().
    public sealed class AppConfig
    {
        [JsonPropertyName("general")]
        public GeneralConfig General { get; set; } = new();

        [JsonPropertyName("zones")]
        public List<string> Zones { get; set; } = new();

        [JsonPropertyName("dns")]
        public DnsConfig Dns { get; set; } = new();

        [JsonPropertyName("prefixFilter")]
        public PrefixFilterConfig PrefixFilter { get; set; } = new();

        /// Summary: Throws a descriptive exception if something required is missing or out of range.
        public void Validate()
        {
            if (string.IsNullOrWhiteSpace(General.TechnitiumUrl))
                throw new InvalidOperationException("Config error: 'general.technitiumUrl' is empty.");

            if (string.IsNullOrWhiteSpace(General.ApiToken))
                throw new InvalidOperationException("Config error: 'general.apiToken' is empty.");

            if (General.IspPrefixLength is < 1 or > 64)
                throw new InvalidOperationException("Config error: 'general.ispPrefixLength' must be an integer between 1 and 64.");

            if (General.ListenPort is < 1 or > 65535)
                throw new InvalidOperationException("Config error: 'general.listenPort' must be a valid TCP port (1-65535).");

            if (Zones is null || Zones.Count == 0)
                throw new InvalidOperationException("Config error: 'zones' must be a non empty list.");

            if (Dns.Ttl <= 0)
                throw new InvalidOperationException("Config error: 'dns.ttl' must be a positive integer.");

            PrefixFilter.Parse();
        }
    }

    public sealed class GeneralConfig
    {
        /// Summary: Base URL of the Technitium DNS Server HTTP API (e.g. "http://localhost:5380").
        [JsonPropertyName("technitiumUrl")]
        public string TechnitiumUrl { get; set; } = "http://localhost:5380";

        /// Summary: API token created in Technitium. Must also be supplied by clients calling this app's HTTP endpoint.
        [JsonPropertyName("apiToken")]
        public string ApiToken { get; set; } = "";

        /// Summary: IPv6 prefix length assigned by the ISP. Must be between 1 and 64 (e.g. 56, 60, 64).
        [JsonPropertyName("ispPrefixLength")]
        public int IspPrefixLength { get; set; } = 56;

        /// Summary: TCP port this app's own HTTP update endpoint listens on.
        [JsonPropertyName("listenPort")]
        public int ListenPort { get; set; } = 8080;
    }

    public sealed class DnsConfig
    {
        /// Summary: TTL (in seconds) applied to updated AAAA and PTR records.
        [JsonPropertyName("ttl")]
        public int Ttl { get; set; } = 300;

        /// Summary:
        /// Enables automatic PTR zone migration when the prefix changes.
        /// Zone recreation means deleting the old zone and creating a new one (see MigrateSignedZones).
        [JsonPropertyName("ptr")]
        public bool Ptr { get; set; } = true;

        /// Summary:
        /// If false (default, recommended), PTR zones that are DNSSEC-signed are SKIPPED
        /// during migration instead of being silently recreated unsigned. Recreating a signed
        /// zone breaks DNSSEC validation for that zone's resolvers, so this app refuses to do
        /// it unless explicitly opted in. Even with this enabled, the new zone will NOT be
        /// re-signed automatically. You would need to re enable DNSSEC manually afterwards.
        [JsonPropertyName("migrateSignedZones")]
        public bool MigrateSignedZones { get; set; } = false;

        /// Summary:
        /// If true (default), zone options (ACLs, TSIG keys and update security policies,
        /// disabled flag) and zone permissions are copied from the old PTR zone to the newly
        /// created one instead of being reset to Technitium's defaults.
        [JsonPropertyName("copyZoneSettings")]
        public bool CopyZoneSettings { get; set; } = true;
    }

    /// Summary:
    /// Decides which addresses / reverse zones the updater may touch. Everything is driven by
    /// the config, nothing is hard-coded. An address is eligible if it lies inside at least one
    /// allowed prefix AND inside no ignored prefix.
    public sealed class PrefixFilterConfig
    {
        /// Summary:
        /// Only addresses inside one of these prefixes are updated.
        [JsonPropertyName("allowedPrefixes")]
        public List<string> AllowedPrefixes { get; set; } = new();

        /// Summary:
        /// Addresses inside one of these prefixes are never touched, even if they are inside an
        /// allowed prefix (e.g. a static tunnel broker network). Default: empty.
        [JsonPropertyName("ignoredPrefixes")]
        public List<string> IgnoredPrefixes { get; set; } = new();

        private IReadOnlyList<Ipv6Range> _allowed = Array.Empty<Ipv6Range>();
        private IReadOnlyList<Ipv6Range> _ignored = Array.Empty<Ipv6Range>();

        /// Summary: Parses both lists. Throws a descriptive exception on invalid entries (called from AppConfig.Validate).
        public void Parse()
        {
            _allowed = ParseList(AllowedPrefixes, "prefixFilter.allowedPrefixes");
            _ignored = ParseList(IgnoredPrefixes, "prefixFilter.ignoredPrefixes");

            if (_allowed.Count == 0)
                throw new InvalidOperationException("Config error: 'prefixFilter.allowedPrefixes' must contain at least one prefix (e.g. \"2000::/3\").");
        }

        private static List<Ipv6Range> ParseList(List<string>? entries, string keyName)
        {
            var result = new List<Ipv6Range>();
            foreach (string entry in entries ?? new List<string>())
            {
                if (!Ipv6Range.TryParse(entry, out Ipv6Range? range, out string? error))
                    throw new InvalidOperationException($"Config error: '{keyName}' entry '{entry}' is invalid: {error}.");
                result.Add(range!);
            }
            return result;
        }

        /// Summary: Checks a single address (AAAA record value, or the address supplied by the router).
        public bool IsAddressEligible(IPAddress address, out string? reason)
        {
            Ipv6Range? ignoredHit = _ignored.FirstOrDefault(r => r.Contains(address));
            if (ignoredHit is not null)
            {
                reason = $"inside ignored prefix {ignoredHit}";
                return false;
            }

            if (!_allowed.Any(r => r.Contains(address)))
            {
                reason = "not inside any allowed prefix";
                return false;
            }

            reason = null;
            return true;
        }

        /// Summary:
        /// Checks a whole network (e.g. the network of a PTR zone). It must be completely inside
        /// an allowed prefix and must not overlap any ignored prefix (overlap, not just
        /// containment, so a zone that is larger than an ignored prefix is skipped as well).
        public bool IsNetworkEligible(IPAddress network, int prefixLength, out string? reason)
        {
            Ipv6Range? ignoredHit = _ignored.FirstOrDefault(r => r.Overlaps(network, prefixLength));
            if (ignoredHit is not null)
            {
                reason = $"overlaps ignored prefix {ignoredHit}";
                return false;
            }

            if (!_allowed.Any(r => r.Covers(network, prefixLength)))
            {
                reason = "not inside any allowed prefix";
                return false;
            }

            reason = null;
            return true;
        }
    }
}
