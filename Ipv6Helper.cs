// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Maxi2710

using System.Net;
using System.Numerics;

namespace TechnitiumPrefixUpdate
{
    /// Summary: Static helper methods for IPv6 prefix math.
    public static class Ipv6Helper
    {
        /// Summary: Converts an IPv6 address into an unsigned 128-bit integer (network byte order).
        public static BigInteger ToUInt128(IPAddress address)
        {
            Span<byte> bytes = stackalloc byte[16];
            if (!address.TryWriteBytes(bytes, out int written) || written != 16)
                throw new ArgumentException("Address must be a 16-byte IPv6 address.", nameof(address));

            // BigInteger expects little endian; IP address bytes are big-endian (network order).
            Span<byte> littleEndian = stackalloc byte[17]; // extra 0 byte forces an unsigned reading
            for (int i = 0; i < 16; i++)
                littleEndian[i] = bytes[15 - i];
            littleEndian[16] = 0;

            return new BigInteger(littleEndian);
        }

        /// Summary: Converts an unsigned 128-bit integer back into an IPv6 address.
        public static IPAddress FromUInt128(BigInteger value)
        {
            byte[] littleEndian = value.ToByteArray(isUnsigned: true, isBigEndian: false);
            Span<byte> bytes = stackalloc byte[16];
            for (int i = 0; i < 16 && i < littleEndian.Length; i++)
                bytes[15 - i] = littleEndian[i];

            return new IPAddress(bytes);
        }

        /// Summary: Returns a bitmask with the top <paramref name="prefixLength"/> bits set to 1 (a network mask).
        public static BigInteger PrefixMask(int prefixLength)
        {
            if (prefixLength <= 0)
                return BigInteger.Zero;
            if (prefixLength >= 128)
                return (BigInteger.One << 128) - 1;

            return ((BigInteger.One << prefixLength) - 1) << (128 - prefixLength);
        }

        /// Summary: Returns a bitmask with the low <paramref name="bitCount"/> bits set to 1 (a host mask).
        public static BigInteger LowBitsMask(int bitCount)
        {
            if (bitCount <= 0)
                return BigInteger.Zero;
            if (bitCount >= 128)
                return (BigInteger.One << 128) - 1;

            return (BigInteger.One << bitCount) - 1;
        }

        /// Summary: Rebuilds an IPv6 address by combining a new prefix with the host bits of an existing address.
        public static IPAddress RebuildAddressWithNewPrefix(IPAddress oldAddress, IPAddress newPrefixNetwork, int newPrefixLength)
        {
            BigInteger hostMask = LowBitsMask(128 - newPrefixLength);
            BigInteger hostBits = ToUInt128(oldAddress) & hostMask;
            BigInteger newValue = (ToUInt128(newPrefixNetwork) & PrefixMask(newPrefixLength)) | hostBits;

            return FromUInt128(newValue);
        }

        /// Summary: Converts an "*.ip6.arpa" reverse zone name into its IPv6 network (address + prefix length).
        public static (IPAddress NetworkAddress, int PrefixLength) ReverseZoneToPrefix(string zoneName)
        {
            const string suffix = ".ip6.arpa";
            if (!zoneName.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException($"'{zoneName}' is not an ip6.arpa zone.", nameof(zoneName));

            string withoutSuffix = zoneName[..^suffix.Length];
            string[] nibbles = withoutSuffix.Length == 0
                ? Array.Empty<string>()
                : withoutSuffix.Split('.');

            // Nibbles in a reverse zone name are stored in reverse (least significant first).
            Array.Reverse(nibbles);

            string hex = string.Concat(nibbles);
            int prefixLength = hex.Length * 4;

            // Pad the remaining low bits with zeroes to get a full 32-nibble (128-bit) value.
            hex = hex.PadRight(32, '0');

            BigInteger value = BigInteger.Parse("0" + hex, System.Globalization.NumberStyles.HexNumber);
            return (FromUInt128(value), prefixLength);
        }

        /// Summary:
        /// Converts an IPv6 network (address + prefix length) into its "*.ip6.arpa" reverse
        /// zone name. Only nibble-aligned prefix lengths (multiples of 4) are supported.
        public static string PrefixToReverseZone(IPAddress networkAddress, int prefixLength)
        {
            if (prefixLength % 4 != 0)
                throw new ArgumentException("Prefix length must be nibble-aligned (a multiple of 4).", nameof(prefixLength));

            BigInteger value = ToUInt128(networkAddress);
            string hex = value.ToString("x32"); // 32 hex chars = 128 bits, zero-padded

            int nibbleCount = prefixLength / 4;
            string relevantNibbles = hex[..nibbleCount];

            IEnumerable<char> reversed = relevantNibbles.Reverse();
            return string.Join('.', reversed) + ".ip6.arpa";
        }

        /// Summary:
        /// Rebuilds a subnet under the new global prefix while preserving the "local" bits
        /// of the old subnet (the bits between the old ISP prefix and the new one, plus any
        /// deeper subnetting).
        public static (IPAddress NetworkAddress, int PrefixLength) RemapPrefix(
            IPAddress oldNetworkAddress, int oldPrefixLength,
            IPAddress newGlobalNetworkAddress, int newGlobalPrefixLength)
        {
            int subnetBits = oldPrefixLength - newGlobalPrefixLength;
            if (subnetBits < 0)
                throw new InvalidOperationException("New prefix is smaller than existing zone prefix.");

            BigInteger offsetMask = LowBitsMask(128 - newGlobalPrefixLength);
            BigInteger offset = ToUInt128(oldNetworkAddress) & offsetMask;
            BigInteger newAddress = (ToUInt128(newGlobalNetworkAddress) & PrefixMask(newGlobalPrefixLength)) | offset;

            return (FromUInt128(newAddress), oldPrefixLength);
        }

        /// Summary: Removes a trailing dot from a fully-qualified domain name, if present.
        public static string NormalizeFqdn(string name) => name.EndsWith('.') ? name[..^1] : name;

        /// Summary: Maps a domain name (PTR record name, security policy domain, ...) from the old reverse zone to the new one.
        public static string MapRecordDomainToNewZone(string recordName, string oldZone, string newZone)
        {
            recordName = NormalizeFqdn(recordName);
            oldZone = NormalizeFqdn(oldZone);
            newZone = NormalizeFqdn(newZone);

            if (string.Equals(recordName, oldZone, StringComparison.OrdinalIgnoreCase))
                return newZone;

            string suffix = "." + oldZone;
            if (recordName.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                return recordName[..^suffix.Length] + "." + newZone;

            if (!recordName.Contains('.') || !recordName.EndsWith(".ip6.arpa", StringComparison.OrdinalIgnoreCase))
                return recordName + "." + newZone;

            throw new InvalidOperationException($"Record '{recordName}' is not inside old zone '{oldZone}'.");
        }
    }
}
