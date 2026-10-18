// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Maxi2710

using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DnsServerCore.ApplicationCommon;

namespace TechnitiumPrefixUpdate
{
    /// Summary:
    /// Technitium DNS Server app that dynamically updates AAAA (and optionally PTR) records
    /// when the ISP's IPv6 prefix changes. It runs inside the DNS server process, opens its own
    /// lightweight HTTP listener on the configured port and talks to the DNS server's HTTP API
    /// to perform the record updates.
    public sealed class App : IDnsApplication
    {
        #region variables

        private IDnsServer? _dnsServer;
        private AppConfig? _config;
        private HttpClient? _httpClient;

        private TcpListener? _tcpListener;
        private CancellationTokenSource? _listenerCts;
        private Task? _listenerTask;

        /// Summary: Ensures only one prefix update run (AAAA update + PTR migration) executes at a time; concurrent requests queue behind it.
        private readonly SemaphoreSlim _updateLock = new(1, 1);

        /// Summary: Maximum time allowed to read the request line/headers before the connection is dropped.
        private static readonly TimeSpan RequestReadTimeout = TimeSpan.FromSeconds(10);

        #endregion

        #region IDnsApplication

        public string Description => "Dynamically updates AAAA records and primary PTR zones when the ISP's IPv6 prefix changes. " +
                                      "Exposes an HTTP endpoint that a router/script can call with an IPv6 address from the ISPs current global prefix.";

        /// Summary:
        /// Called by Technitium on app start and whenever the app config is saved/reloaded
        /// from the web console. Re-creates the HTTP listener with the (possibly changed) config.
        public async Task InitializeAsync(IDnsServer dnsServer, string? config)
        {
            _dnsServer = dnsServer;

            // Stop any previously running listener before applying the new config
            // (InitializeAsync is also called again after a config edit/save).
            await StopListenerAsync().ConfigureAwait(false);

            if (string.IsNullOrWhiteSpace(config))
            {
                _dnsServer.WriteLog("TechnitiumPrefixUpdate: no configuration found, app is disabled until a valid app config is provided.");
                return;
            }

            AppConfig parsedConfig;
            try
            {
                parsedConfig = JsonSerializer.Deserialize<AppConfig>(config) ?? throw new InvalidOperationException("Config is empty.");
                parsedConfig.Validate();
            }
            catch (Exception ex)
            {
                _dnsServer.WriteLog($"TechnitiumPrefixUpdate: invalid configuration, app is disabled. {ex.Message}");
                return;
            }

            _config = parsedConfig;

            _httpClient?.Dispose();
            _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };

            StartListener();
        }

        public void Dispose()
        {
            StopListenerAsync().GetAwaiter().GetResult();
            _httpClient?.Dispose();
            _updateLock.Dispose();
        }

        #endregion

        #region HTTP listener

        private void StartListener()
        {
            if (_dnsServer is null || _config is null)
                return;

            _listenerCts = new CancellationTokenSource();

            // "::" wildcard socket also accepts IPv4 clients.
            _tcpListener = new TcpListener(IPAddress.IPv6Any, _config.General.ListenPort);

            try
            {
                _tcpListener.Server.DualMode = true;
                _tcpListener.Start();
            }
            catch (Exception ex)
            {
                _dnsServer.WriteLog(new Exception($"TechnitiumPrefixUpdate: failed to start HTTP listener on [::]:{_config.General.ListenPort}. " +
                    "On Linux, binding to a port below 1024 may require elevated privileges/capabilities, IPv6 may be disabled on this host, or the port may already be in use.", ex));
                _tcpListener = null;
                return;
            }

            _dnsServer.WriteLog($"TechnitiumPrefixUpdate: listening on [::]:{_config.General.ListenPort}");

            _listenerTask = Task.Run(() => AcceptLoopAsync(_tcpListener, _listenerCts.Token));
        }

        private async Task StopListenerAsync()
        {
            if (_listenerCts is not null)
                await _listenerCts.CancelAsync().ConfigureAwait(false);

            try { _tcpListener?.Stop(); } catch { /* already stopped */ }

            if (_listenerTask is not null)
            {
                try { await _listenerTask.ConfigureAwait(false); } catch { /* expected on cancellation */ }
            }

            _tcpListener = null;
            _listenerCts?.Dispose();
            _listenerCts = null;
            _listenerTask = null;
        }

        private async Task AcceptLoopAsync(TcpListener listener, CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                Socket socket;
                try
                {
                    socket = await listener.AcceptSocketAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (Exception) when (cancellationToken.IsCancellationRequested)
                {
                    break; // listener was stopped, this is expected
                }
                catch (Exception ex)
                {
                    _dnsServer?.WriteLog(new Exception("TechnitiumPrefixUpdate: error accepting HTTP request.", ex));
                    continue;
                }

                // Handle each request on its own task so a slow update doesn't block new requests.
                _ = Task.Run(() => HandleRequestAsync(socket, cancellationToken), cancellationToken);
            }
        }

        private async Task HandleRequestAsync(Socket socket, CancellationToken cancellationToken)
        {
            using (socket)
            {
                try
                {
                    await ProcessRequestAsync(socket, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _dnsServer?.WriteLog(new Exception("TechnitiumPrefixUpdate: unhandled error while processing HTTP request.", ex));
                    try
                    {
                        await WriteResponseAsync(socket, 500, "internal error").ConfigureAwait(false);
                    }
                    catch { /* client already gone */ }
                }
            }
        }

        private async Task ProcessRequestAsync(Socket socket, CancellationToken cancellationToken)
        {
            AppConfig config = _config!;
            IDnsServer dnsServer = _dnsServer!;

            // Bounds how long we wait for the client to send its request; does not cover the update work itself.
            using CancellationTokenSource readCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            readCts.CancelAfter(RequestReadTimeout);

            await using NetworkStream networkStream = new(socket, ownsSocket: false);
            using StreamReader reader = new(networkStream, Encoding.ASCII, detectEncodingFromByteOrderMarks: false, bufferSize: 1024, leaveOpen: true);

            string? requestLine;
            try
            {
                // Minimal HTTP/1.1 parsing because only the request target's query string is needed.
                requestLine = await reader.ReadLineAsync(readCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                return; // client was too slow sending its request; drop the connection silently.
            }

            if (string.IsNullOrEmpty(requestLine))
                return;

            string[] requestLineParts = requestLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            string target = requestLineParts.Length >= 2 ? requestLineParts[1] : "/";

            try
            {
                // Drain the request headers up to the blank line before responding.
                string? headerLine;
                while (!string.IsNullOrEmpty(headerLine = await reader.ReadLineAsync(readCts.Token).ConfigureAwait(false)))
                {
                    // headers themselves are not used by this app.
                }
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                return;
            }

            System.Collections.Specialized.NameValueCollection query = ParseQueryString(target);

            // Optional quiet mode for routers that choke on multi line responses
            // run without major failures (see IsMajorFailure) replies with a bare "OK".
            // Everything is still logged.
            bool shortMode = query["short"] is { } shortValue &&
                (string.Equals(shortValue, "yes", StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(shortValue, "true", StringComparison.OrdinalIgnoreCase) ||
                 shortValue == "1");

            // Validate the shared secret token using a constant-time comparison.
            string? token = query["token"];
            if (!FixedTimeEquals(token, config.General.ApiToken))
            {
                await WriteResponseAsync(socket, 403, "forbidden").ConfigureAwait(false);
                return;
            }

            // Validate that an IP was supplied.
            string? ipParam = query["ip"];
            if (string.IsNullOrEmpty(ipParam))
            {
                await WriteResponseAsync(socket, 400, "missing ip").ConfigureAwait(false);
                return;
            }

            // Validate that it parses as an IPv6 address.
            if (!IPAddress.TryParse(ipParam, out IPAddress? ipv6) || ipv6.AddressFamily != AddressFamily.InterNetworkV6)
            {
                await WriteResponseAsync(socket, 400, "invalid IPv6").ConfigureAwait(false);
                return;
            }

            // Validate that the address passes the configured prefix filter (allowed/ignored prefixes).
            if (!config.PrefixFilter.IsAddressEligible(ipv6, out string? filterReason))
            {
                await WriteResponseAsync(socket, 400, $"Given address {ipv6} is {filterReason}").ConfigureAwait(false);
                return;
            }

            // Extract the new prefix from the given address using the configured prefix length.
            int prefixLength = config.General.IspPrefixLength;
            System.Numerics.BigInteger networkValue = Ipv6Helper.ToUInt128(ipv6) & Ipv6Helper.PrefixMask(prefixLength);
            IPAddress newPrefixNetwork = Ipv6Helper.FromUInt128(networkValue);

            dnsServer.WriteLog($"TechnitiumPrefixUpdate: received update request for prefix {newPrefixNetwork}/{prefixLength} from {ipv6}.");

            // Only one update run at a time (see _updateLock).
            await _updateLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var api = new TechnitiumApiClient(_httpClient!, config.General.TechnitiumUrl, config.General.ApiToken);
                var updateService = new PrefixUpdateService(api, dnsServer, config.Dns, config.PrefixFilter);

                List<ZoneInfo> knownZones;
                try
                {
                    knownZones = await api.GetAllZonesAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (TechnitiumApiException ex)
                {
                    // Without a zone list no per-zone work can succeed (API unreachable or token
                    // invalid), so the whole request fails here.
                    dnsServer.WriteLog(new Exception("TechnitiumPrefixUpdate: could not reach Technitium API / list zones.", ex));
                    await WriteResponseAsync(socket, 502, $"Technitium API unreachable: {ex.Message}").ConfigureAwait(false);
                    return;
                }

                Dictionary<string, ZoneInfo> zonesByName = knownZones.ToDictionary(z => z.Name, StringComparer.OrdinalIgnoreCase);

                // Each configured zone is updated independently. One failing zone must not
                // prevent the others from being updated.
                var zoneResults = new List<ZoneUpdateResult>();
                foreach (string zone in config.Zones)
                    zoneResults.Add(await updateService.UpdateZoneAaaaRecordsAsync(zone, newPrefixNetwork, prefixLength, zonesByName, cancellationToken).ConfigureAwait(false));

                List<PtrMigrationResult> ptrResults = new();
                if (config.Dns.Ptr)
                    ptrResults = await updateService.MigratePtrZonesAsync(newPrefixNetwork, prefixLength, cancellationToken).ConfigureAwait(false);

                bool anyMajorFailure = zoneResults.Any(r => !r.Success && r.IsMajorFailure) || ptrResults.Any(r => !r.Success && r.IsMajorFailure);
                bool anyFailure = zoneResults.Any(r => !r.Success) || ptrResults.Any(r => !r.Success);

                if (shortMode)
                {
                    if (!anyMajorFailure)
                    {
                        await WriteResponseAsync(socket, 200, "OK").ConfigureAwait(false);
                    }
                    else
                    {
                        string shortError = BuildShortErrorSummary(zoneResults, ptrResults);
                        await WriteResponseAsync(socket, 207, shortError).ConfigureAwait(false);
                    }

                    return;
                }

                string responseBody = BuildSummary(newPrefixNetwork, prefixLength, zoneResults, ptrResults);

                // 200 if everything succeeded, 207 if any zone failed or was skipped.
                await WriteResponseAsync(socket, anyFailure ? 207 : 200, responseBody).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                dnsServer.WriteLog(new Exception("TechnitiumPrefixUpdate: update run failed unexpectedly.", ex));
                await WriteResponseAsync(socket, 500, $"internal error: {ex.Message}").ConfigureAwait(false);
            }
            finally
            {
                _updateLock.Release();
            }
        }

        /// Summary: Constant time string comparison for the shared secret token check.
        private static bool FixedTimeEquals(string? provided, string configured)
        {
            if (provided is null)
                return false;

            byte[] providedBytes = Encoding.UTF8.GetBytes(provided);
            byte[] configuredBytes = Encoding.UTF8.GetBytes(configured);

            if (providedBytes.Length != configuredBytes.Length)
                return false;

            return CryptographicOperations.FixedTimeEquals(providedBytes, configuredBytes);
        }

        /// Summary: Builds a short human readable (and easy to grep/parse) plain text summary of one update run.
        private static string BuildSummary(IPAddress newPrefixNetwork, int prefixLength, List<ZoneUpdateResult> zoneResults, List<PtrMigrationResult> ptrResults)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"Prefix update processed: {newPrefixNetwork}/{prefixLength}");

            sb.AppendLine("AAAA zones:");
            if (zoneResults.Count == 0)
                sb.AppendLine("  (none configured)");
            foreach (ZoneUpdateResult r in zoneResults)
                sb.AppendLine($"  [{ResultTag(r.Success, r.IsMajorFailure)}] {r.ZoneName}: {r.Message}");

            sb.AppendLine("PTR zones:");
            if (ptrResults.Count == 0)
                sb.AppendLine("  (none found or PTR migration disabled)");
            foreach (PtrMigrationResult r in ptrResults)
                sb.AppendLine($"  [{ResultTag(r.Success, r.IsMajorFailure)}] {r.OldZone} -> {r.NewZone ?? "(unchanged)"}: {r.Message}");

            return sb.ToString();
        }

        /// Summary: OK = fully succeeded, SKIP = a benign/expected non change, FAIL = a real, actionable problem.
        private static string ResultTag(bool success, bool isMajorFailure) => success ? "OK" : (isMajorFailure ? "FAIL" : "SKIP");

        /// Summary:Builds the short=yes error response: only major failures, no benign skips.
        private static string BuildShortErrorSummary(List<ZoneUpdateResult> zoneResults, List<PtrMigrationResult> ptrResults)
        {
            var sb = new StringBuilder();

            foreach (ZoneUpdateResult r in zoneResults.Where(r => !r.Success && r.IsMajorFailure))
                sb.AppendLine($"{r.ZoneName}: {r.Message}");

            foreach (PtrMigrationResult r in ptrResults.Where(r => !r.Success && r.IsMajorFailure))
                sb.AppendLine($"{r.OldZone}: {r.Message}");

            return sb.Length > 0 ? sb.ToString().TrimEnd() : "error";
        }

        private static System.Collections.Specialized.NameValueCollection ParseQueryString(string requestTarget)
        {
            var result = new System.Collections.Specialized.NameValueCollection();

            int queryStart = requestTarget.IndexOf('?');
            if (queryStart < 0 || queryStart == requestTarget.Length - 1)
                return result;

            string query = requestTarget[(queryStart + 1)..];

            foreach (string pair in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                int eq = pair.IndexOf('=');
                string rawKey = eq >= 0 ? pair[..eq] : pair;
                string rawValue = eq >= 0 ? pair[(eq + 1)..] : string.Empty;

                string key = Uri.UnescapeDataString(rawKey.Replace('+', ' '));
                string value = Uri.UnescapeDataString(rawValue.Replace('+', ' '));

                result.Add(key, value);
            }

            return result;
        }

        private static async Task WriteResponseAsync(Socket socket, int statusCode, string body)
        {
            byte[] bodyBytes = Encoding.UTF8.GetBytes(body + "\n");
            string statusText = statusCode switch
            {
                200 => "OK",
                207 => "Multi-Status",
                400 => "Bad Request",
                403 => "Forbidden",
                500 => "Internal Server Error",
                502 => "Bad Gateway",
                _ => "Unknown"
            };

            string headers =
                $"HTTP/1.1 {statusCode} {statusText}\r\n" +
                "Content-Type: text/plain; charset=utf-8\r\n" +
                $"Content-Length: {bodyBytes.Length}\r\n" +
                "Connection: close\r\n" +
                "\r\n";

            byte[] headerBytes = Encoding.ASCII.GetBytes(headers);

            await using NetworkStream networkStream = new(socket, ownsSocket: false);
            await networkStream.WriteAsync(headerBytes).ConfigureAwait(false);
            await networkStream.WriteAsync(bodyBytes).ConfigureAwait(false);
            await networkStream.FlushAsync().ConfigureAwait(false);
        }

        #endregion
    }
}
