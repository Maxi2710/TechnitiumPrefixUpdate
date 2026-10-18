// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Maxi2710

using System.Net;
using System.Text.Json;
using DnsServerCore.ApplicationCommon;

namespace TechnitiumPrefixUpdate
{
    /// Summary: Outcome of updating a single configured AAAA zone.
    /// <param name="IsMajorFailure">
    /// Only meaningful when <see cref="Success"/> is false. True for problems that indicate a
    /// real, actionable issue (missing permissions, unreachable API, a record update actually
    /// being rejected). False for expected/benign skips (e.g. the zone is intentionally
    /// disabled). Used to decide what counts as an "error" in the HTTP endpoint's short/quiet response mode.
    /// </param>
    public sealed record ZoneUpdateResult(string ZoneName, bool Success, string Message, bool IsMajorFailure = false);

    /// Summary: Outcome of migrating a single PTR (*.ip6.arpa) zone.
    /// <param name="IsMajorFailure">See <see cref="ZoneUpdateResult.IsMajorFailure"/>.</param>
    public sealed record PtrMigrationResult(string OldZone, string? NewZone, bool Success, string Message, bool IsMajorFailure = false);

    /// Summary:
    /// Coordinates the actual prefix update work: rewriting AAAA records in the configured
    /// zones and, optionally, migrating PTR (reverse DNS) zones to the new prefix.
    ///
    /// Design principle for this whole class: a problem with ONE zone (or one record within a
    /// zone) must never prevent the other configured zones from being processed. Every unit of
    /// work therefore catches its own exceptions and reports a result instead of throwing, and
    /// the only exceptions that propagate out of the public methods are ones that make any
    /// further work pointless (e.g. the Technitium API being unreachable).
    public sealed class PrefixUpdateService
    {
        private readonly TechnitiumApiClient _api;
        private readonly IDnsServer _dnsServer;
        private readonly DnsConfig _dnsConfig;
        private readonly PrefixFilterConfig _filter;

        public PrefixUpdateService(TechnitiumApiClient api, IDnsServer dnsServer, DnsConfig dnsConfig, PrefixFilterConfig filter)
        {
            _api = api;
            _dnsServer = dnsServer;
            _dnsConfig = dnsConfig;
            _filter = filter;
        }

        /// Summary:
        /// Updates every AAAA record in the given zone that passes the prefix filter (see
        /// PrefixFilterConfig) so that it uses the new prefix while keeping its existing host bits.
        /// Never throws: any failure is captured in the returned <see cref="ZoneUpdateResult"/>
        /// so that the caller can keep processing the remaining configured zones.
        public async Task<ZoneUpdateResult> UpdateZoneAaaaRecordsAsync(
            string zoneName, IPAddress newPrefixNetwork, int newPrefixLength, IReadOnlyDictionary<string, ZoneInfo> knownZones, CancellationToken cancellationToken)
        {
            try
            {
                // Validate the zone before touching it. Attempting record updates against a
                // zone that doesn't exist, isn't a Primary zone (e.g. Secondary/Stub/Forwarder),
                // or is disabled either fails confusingly or silently does nothing
                // useful, so we check this explicitly and report a clear reason instead.
                if (!knownZones.TryGetValue(zoneName, out ZoneInfo? zoneInfo))
                    return new ZoneUpdateResult(zoneName, false, $"Zone '{zoneName}' does not exist on this DNS server. Check spelling in config and API token zone permissions.", IsMajorFailure: true);

                if (!string.Equals(zoneInfo.Type, "Primary", StringComparison.OrdinalIgnoreCase))
                    return new ZoneUpdateResult(zoneName, false, $"Zone '{zoneName}' is of type '{zoneInfo.Type}', not 'Primary'. Only Primary zones can have their AAAA records edited directly; skipping.", IsMajorFailure: false);

                if (zoneInfo.Disabled)
                    return new ZoneUpdateResult(zoneName, false, $"Zone '{zoneName}' is disabled in Technitium; skipping to avoid re enabling it implicitly.", IsMajorFailure: false);

                List<DnsRecord> allRecords;
                try
                {
                    allRecords = await _api.GetRecordsAsync(zoneName, cancellationToken).ConfigureAwait(false);
                }
                catch (TechnitiumApiException ex)
                {
                    string hint = ex.IsPermissionError ? " The configured API token may not have permission for this zone." : "";
                    return new ZoneUpdateResult(zoneName, false, $"Could not read records for zone '{zoneName}': {ex.Message}.{hint}", IsMajorFailure: true);
                }

                // Only records that pass the configured prefix filter (allowed/ignored prefixes)
                // are candidates; everything else is left untouched.
                var candidates = new List<DnsRecord>();
                int excluded = 0;
                foreach (DnsRecord r in allRecords)
                {
                    if (r.Type != "AAAA" || r.IpAddress is null || !IPAddress.TryParse(r.IpAddress, out IPAddress? parsed))
                        continue;

                    if (!_filter.IsAddressEligible(parsed, out string? reason))
                    {
                        _dnsServer.WriteLog($"[{zoneName}] Exclude {r.Name}: {r.IpAddress} is {reason}.");
                        excluded++;
                        continue;
                    }

                    candidates.Add(r);
                }

                if (candidates.Count == 0)
                {
                    _dnsServer.WriteLog($"[{zoneName}] No AAAA records to update ({excluded} excluded by prefix filter).");
                    return new ZoneUpdateResult(zoneName, true, $"No AAAA records to update ({excluded} excluded by prefix filter); nothing to do.");
                }

                int updated = 0, skipped = 0, failed = 0;

                foreach (DnsRecord record in candidates)
                {
                    // A single malformed/unparsable or API rejected record must not abort the
                    // rest of the zone's updates.
                    try
                    {
                        IPAddress oldIp = IPAddress.Parse(record.IpAddress!);
                        IPAddress newIp = Ipv6Helper.RebuildAddressWithNewPrefix(oldIp, newPrefixNetwork, newPrefixLength);
                        string newIpString = newIp.ToString();

                        if (string.Equals(record.IpAddress, newIpString, StringComparison.OrdinalIgnoreCase))
                        {
                            _dnsServer.WriteLog($"[{zoneName}] Skip {record.Name}: IP unchanged ({record.IpAddress}).");
                            skipped++;
                            continue;
                        }

                        _dnsServer.WriteLog($"[{zoneName}] Update {record.Name}: {record.IpAddress} -> {newIpString}");
                        await _api.UpdateAaaaRecordAsync(record.Name, zoneName, record.IpAddress!, newIpString, _dnsConfig.Ttl, record.Comments, cancellationToken).ConfigureAwait(false);
                        updated++;
                    }
                    catch (Exception ex) when (ex is TechnitiumApiException or FormatException)
                    {
                        _dnsServer.WriteLog(new Exception($"[{zoneName}] Failed to update record '{record.Name}' ({record.IpAddress}); continuing with remaining records.", ex));
                        failed++;
                    }
                }

                bool success = failed == 0;
                string message = $"{updated} updated, {skipped} unchanged, {failed} failed (of {candidates.Count} eligible AAAA records), {excluded} excluded by prefix filter.";
                return new ZoneUpdateResult(zoneName, success, message, IsMajorFailure: !success);
            }
            catch (Exception ex)
            {
                // Safety net: any unexpected error for this zone is still reported per zone
                // rather than bubbling up and cancelling the other configured zones.
                _dnsServer.WriteLog(new Exception($"[{zoneName}] Unexpected error while updating AAAA records.", ex));
                return new ZoneUpdateResult(zoneName, false, $"Unexpected error: {ex.Message}", IsMajorFailure: true);
            }
        }

        /// Summary:
        /// Migrates every global, nibble aligned, primary ip6.arpa PTR zone to a new zone
        /// name matching the new prefix, copying all PTR records across and preserving the
        /// catalog zone assignment and (optionally) the zone options and permissions.
        public async Task<List<PtrMigrationResult>> MigratePtrZonesAsync(IPAddress newPrefixNetwork, int newPrefixLength, CancellationToken cancellationToken)
        {
            var results = new List<PtrMigrationResult>();

            List<ZoneInfo> ptrZones = await _api.GetIpv6PtrZonesAsync(cancellationToken).ConfigureAwait(false);

            if (ptrZones.Count == 0)
            {
                _dnsServer.WriteLog("[PTR] No IPv6 PTR zones found.");
                return results;
            }

            foreach (ZoneInfo zone in ptrZones)
                results.Add(await MigrateSinglePtrZoneAsync(zone, newPrefixNetwork, newPrefixLength, cancellationToken).ConfigureAwait(false));

            return results;
        }

        private async Task<PtrMigrationResult> MigrateSinglePtrZoneAsync(ZoneInfo zone, IPAddress newPrefixNetwork, int newPrefixLength, CancellationToken cancellationToken)
        {
            string oldZone = zone.Name;
            _dnsServer.WriteLog($"[PTR] Processing zone: {oldZone}");

            if (zone.Disabled)
            {
                _dnsServer.WriteLog($"[PTR]   Skipping '{oldZone}': zone is disabled.");
                return new PtrMigrationResult(oldZone, null, true, "Skipped: zone is disabled.");
            }

            // DNSSEC awareness: recreating a signed zone via delete+create silently destroys its
            // signing state and breaks validation for any resolver enforcing DNSSEC on it. Unless
            // opted in via config, refuse to touch signed zones.
            if (zone.IsDnssecSigned && !_dnsConfig.MigrateSignedZones)
            {
                string msg = $"Skipped: zone is DNSSEC signed ({zone.DnssecStatus}). Recreating it would break DNSSEC validation. " +
                              "Set \"dns.migrateSignedZones\": true to override (the new zone will NOT be automatically re signed).";
                _dnsServer.WriteLog($"[PTR]   {msg}");
                return new PtrMigrationResult(oldZone, null, false, msg, IsMajorFailure: false);
            }

            (IPAddress oldNetworkAddress, int oldPrefixLength) oldNet;
            try
            {
                oldNet = Ipv6Helper.ReverseZoneToPrefix(oldZone);
            }
            catch (Exception ex)
            {
                string msg = $"Skipping: cannot parse zone as an ip6.arpa network ({ex.Message}).";
                _dnsServer.WriteLog($"[PTR]   {msg}");
                return new PtrMigrationResult(oldZone, null, false, msg, IsMajorFailure: false);
            }

            if (!_filter.IsNetworkEligible(oldNet.oldNetworkAddress, oldNet.oldPrefixLength, out string? filterReason))
            {
                string msg = $"Skipping: zone network {oldNet.oldNetworkAddress}/{oldNet.oldPrefixLength} is {filterReason}.";
                _dnsServer.WriteLog($"[PTR]   {msg}");
                return new PtrMigrationResult(oldZone, null, false, msg, IsMajorFailure: false);
            }

            if (oldNet.oldPrefixLength % 4 != 0)
            {
                string msg = "Skipping: prefix is not nibble aligned.";
                _dnsServer.WriteLog($"[PTR]   {msg}");
                return new PtrMigrationResult(oldZone, null, false, msg, IsMajorFailure: false);
            }

            (IPAddress NetworkAddress, int PrefixLength) newNet;
            try
            {
                newNet = Ipv6Helper.RemapPrefix(oldNet.oldNetworkAddress, oldNet.oldPrefixLength, newPrefixNetwork, newPrefixLength);
            }
            catch (Exception ex)
            {
                string msg = $"Skipping: {ex.Message}";
                _dnsServer.WriteLog($"[PTR]   {msg}");
                return new PtrMigrationResult(oldZone, null, false, msg, IsMajorFailure: false);
            }

            string newZone = Ipv6Helper.PrefixToReverseZone(newNet.NetworkAddress, newNet.PrefixLength);

            // If the computed new zone name is identical to the old one, the
            // prefix hasn't actually changed for this zone (e.g. a duplicate/retried request).
            // Recreating a zone with itself would just fail on CreateZoneAsync, so
            // detect this up front and report it cleanly.
            if (string.Equals(newZone, oldZone, StringComparison.OrdinalIgnoreCase))
            {
                _dnsServer.WriteLog($"[PTR]   '{oldZone}' already matches the new prefix; nothing to do.");
                return new PtrMigrationResult(oldZone, newZone, true, "Already up to date; no migration needed.");
            }

            _dnsServer.WriteLog($"[PTR]   Old prefix: {oldNet.oldNetworkAddress}/{oldNet.oldPrefixLength}");
            _dnsServer.WriteLog($"[PTR]   New prefix: {newNet.NetworkAddress}/{newNet.PrefixLength}");
            _dnsServer.WriteLog($"[PTR]   New zone:   {newZone}");
            _dnsServer.WriteLog(string.IsNullOrEmpty(zone.CatalogZoneName)
                ? "[PTR]   Catalog zone: (none)"
                : $"[PTR]   Catalog zone: {zone.CatalogZoneName}");

            // Fetch the old zone's options and permissions before creating anything, so a failure
            // here aborts cleanly without having created (and potentially orphaning) a new zone yet.
            JsonElement? oldZoneOptions = null;
            JsonElement? oldZonePermissions = null;
            if (_dnsConfig.CopyZoneSettings)
            {
                try
                {
                    oldZoneOptions = await _api.GetZoneOptionsAsync(oldZone, cancellationToken).ConfigureAwait(false);
                }
                catch (TechnitiumApiException ex)
                {
                    _dnsServer.WriteLog($"[PTR]   Warning: could not read zone options of '{oldZone}' ({ex.Message}). New zone will use Technitium defaults.");
                }

                try
                {
                    oldZonePermissions = await _api.GetZonePermissionsAsync(oldZone, cancellationToken).ConfigureAwait(false);
                }
                catch (TechnitiumApiException ex)
                {
                    _dnsServer.WriteLog($"[PTR]   Warning: could not read zone permissions of '{oldZone}' ({ex.Message}). New zone will use default (no explicit) permissions.");
                }
            }

            try
            {
                await _api.CreateZoneAsync(newZone, cancellationToken).ConfigureAwait(false);
                _dnsServer.WriteLog("[PTR]   New zone created.");
            }
            catch (TechnitiumApiException ex)
            {
                string hint = ex.IsPermissionError ? " The configured API token may not have permission to create zones." : "";
                string msg = $"Failed to create new zone '{newZone}': {ex.Message}.{hint}";
                _dnsServer.WriteLog($"[PTR]   {msg}");
                return new PtrMigrationResult(oldZone, newZone, false, msg, IsMajorFailure: true);
            }

            // From this point on, the new zone exists. If anything below fails hard enough that
            // we bail out, we must clean up the empty new zone rather than leaving an orphan
            // behind. The old zone (with its data) is always left untouched until we're sure
            // the new zone is a working replacement.
            bool newZoneHasData = false;

            try
            {
                if (_dnsConfig.CopyZoneSettings && oldZoneOptions is JsonElement optionsValue)
                {
                    try
                    {
                        await _api.ApplyZoneOptionsAsync(newZone, oldZone, optionsValue, cancellationToken).ConfigureAwait(false);
                        _dnsServer.WriteLog("[PTR]   Zone options copied from old zone.");
                    }
                    catch (TechnitiumApiException ex)
                    {
                        _dnsServer.WriteLog($"[PTR]   Warning: failed to copy zone options to new zone ({ex.Message}). New zone keeps Technitium defaults. Continuing anyway.");
                    }
                }

                if (_dnsConfig.CopyZoneSettings && oldZonePermissions is JsonElement permissionsValue)
                {
                    try
                    {
                        await _api.ApplyZonePermissionsAsync(newZone, permissionsValue, cancellationToken).ConfigureAwait(false);
                        _dnsServer.WriteLog("[PTR]   Zone permissions (user/group View-Modify-Delete grants) copied from old zone.");
                    }
                    catch (TechnitiumApiException ex)
                    {
                        _dnsServer.WriteLog($"[PTR]   Warning: failed to copy zone permissions to new zone ({ex.Message}). Continuing anyway.");
                    }
                }

                if (!string.IsNullOrEmpty(zone.CatalogZoneName))
                {
                    try
                    {
                        await _api.SetZoneCatalogAsync(newZone, zone.CatalogZoneName, cancellationToken).ConfigureAwait(false);
                        _dnsServer.WriteLog($"[PTR]   Catalog zone '{zone.CatalogZoneName}' applied to new zone.");
                    }
                    catch (TechnitiumApiException ex)
                    {
                        _dnsServer.WriteLog($"[PTR]   Warning: failed to set catalog zone on new zone ({ex.Message}). Continuing anyway.");
                    }
                }

                List<DnsRecord> records;
                try
                {
                    records = await _api.GetRecordsAsync(oldZone, cancellationToken).ConfigureAwait(false);
                }
                catch (TechnitiumApiException ex)
                {
                    // We couldn't even read the source records. The new zone is useless (empty)
                    // at this point, so roll it back instead of leaving an orphaned duplicate zone.
                    string msg = $"Failed to read records from old zone '{oldZone}': {ex.Message}. Rolling back the newly created zone.";
                    _dnsServer.WriteLog($"[PTR]   {msg}");
                    await TryDeleteZoneAsync(newZone, cancellationToken).ConfigureAwait(false);
                    return new PtrMigrationResult(oldZone, newZone, false, msg, IsMajorFailure: true);
                }

                int copied = 0, failed = 0;

                foreach (DnsRecord record in records)
                {
                    if (record.Type != "PTR")
                        continue;

                    if (string.IsNullOrEmpty(record.PtrName))
                    {
                        _dnsServer.WriteLog($"[PTR]     Skipping PTR record without ptrName/value: {record.Name}");
                        continue;
                    }

                    string newDomain;
                    try
                    {
                        newDomain = Ipv6Helper.MapRecordDomainToNewZone(record.Name, oldZone, newZone);
                    }
                    catch (InvalidOperationException ex)
                    {
                        _dnsServer.WriteLog($"[PTR]     Skipping: {ex.Message}");
                        continue;
                    }

                    // A single record that fails to copy (e.g. transient API hiccup, duplicate,
                    // odd characters) must not abort copying the rest of the zone's records.
                    try
                    {
                        await _api.AddPtrRecordAsync(newZone, newDomain, record.PtrName, _dnsConfig.Ttl, record.Comments, cancellationToken).ConfigureAwait(false);
                        copied++;
                    }
                    catch (TechnitiumApiException ex)
                    {
                        _dnsServer.WriteLog(new Exception($"[PTR]     Failed to copy record '{record.Name}' -> '{newDomain}'; continuing with remaining records.", ex));
                        failed++;
                    }
                }

                newZoneHasData = copied > 0;
                int copiedWithComments = records.Count(r => r.Type == "PTR" && !string.IsNullOrEmpty(r.Comments));
                _dnsServer.WriteLog($"[PTR]   Copied {copied} PTR records" + (failed > 0 ? $" ({failed} failed)." : ".") +
                    (copiedWithComments > 0 ? $" {copiedWithComments} of them had a per record comment, carried over too." : ""));

                if (!newZoneHasData)
                {
                    // Nothing could be copied over. If the old zone had no PTR records,
                    // that's a legitimate (empty) migration and we still proceed; if records
                    // existed but ALL failed to copy, keeping an empty "new" zone while deleting
                    // the old, populated one would be data loss, so we roll back instead.
                    bool oldZoneHadPtrRecords = records.Any(r => r.Type == "PTR");
                    if (oldZoneHadPtrRecords)
                    {
                        string msg = $"All {failed} PTR record(s) failed to copy; rolling back the new zone and leaving the old zone untouched.";
                        _dnsServer.WriteLog($"[PTR]   {msg}");
                        await TryDeleteZoneAsync(newZone, cancellationToken).ConfigureAwait(false);
                        return new PtrMigrationResult(oldZone, newZone, false, msg, IsMajorFailure: true);
                    }
                }

                try
                {
                    await _api.DeleteZoneAsync(oldZone, cancellationToken).ConfigureAwait(false);
                    _dnsServer.WriteLog("[PTR]   Old zone deleted.");
                }
                catch (TechnitiumApiException ex)
                {
                    string msg = $"Migrated {copied} record(s) to '{newZone}', but failed to delete old zone '{oldZone}': {ex.Message}. Both zones now exist - please remove the old one manually.";
                    _dnsServer.WriteLog($"[PTR]   {msg}");
                    return new PtrMigrationResult(oldZone, newZone, false, msg, IsMajorFailure: true);
                }

                string successMsg = failed > 0
                    ? $"Migrated with {failed} record failure(s): {copied} PTR record(s) copied to '{newZone}'."
                    : $"Migrated successfully: {copied} PTR record(s) copied to '{newZone}'.";
                return new PtrMigrationResult(oldZone, newZone, failed == 0, successMsg, IsMajorFailure: failed > 0);
            }
            catch (Exception ex)
            {
                // Safety net for anything unexpected after zone creation: never silently swallow,
                // but also don't let it take down the migration of other zones.
                _dnsServer.WriteLog(new Exception($"[PTR]   Unexpected error migrating '{oldZone}' to '{newZone}'.", ex));

                if (!newZoneHasData)
                    await TryDeleteZoneAsync(newZone, cancellationToken).ConfigureAwait(false);

                return new PtrMigrationResult(oldZone, newZone, false, $"Unexpected error: {ex.Message}", IsMajorFailure: true);
            }
        }

        /// Summary: Best-effort zone deletion used for rollback; failures are logged, not thrown.
        private async Task TryDeleteZoneAsync(string zoneName, CancellationToken cancellationToken)
        {
            try
            {
                await _api.DeleteZoneAsync(zoneName, cancellationToken).ConfigureAwait(false);
                _dnsServer.WriteLog($"[PTR]   Rollback: deleted zone '{zoneName}'.");
            }
            catch (TechnitiumApiException ex)
            {
                _dnsServer.WriteLog($"[PTR]   Rollback FAILED for zone '{zoneName}': {ex.Message}. Please check/delete it manually to avoid a leftover empty zone.");
            }
        }
    }
}
