// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Maxi2710

using System.Net;
using System.Net.Sockets;

namespace TechnitiumPrefixUpdate
{
    /// Summary: An IPv6 CIDR block (network address + prefix length), e.g. 2000::/3.
    public sealed record Ipv6Range(IPAddress Network, int PrefixLength)
    {
        /// Summary:
        /// Parses "address/length" (e.g. "2001:db8::/32"). Host bits are cleared, so
        /// "2001:db8::1/32" and "2001:db8::/32" result in the same range.
        public static bool TryParse(string? text, out Ipv6Range? range, out string? error)
        {
            range = null;
            error = null;

            if (string.IsNullOrWhiteSpace(text))
            {
                error = "entry is empty";
                return false;
            }

            string[] parts = text.Trim().Split('/');
            if (parts.Length != 2
                || !IPAddress.TryParse(parts[0], out IPAddress? address)
                || address.AddressFamily != AddressFamily.InterNetworkV6
                || !int.TryParse(parts[1], out int length)
                || length is < 0 or > 128)
            {
                error = "expected IPv6 CIDR notation like 2000::/3";
                return false;
            }

            IPAddress network = Ipv6Helper.FromUInt128(Ipv6Helper.ToUInt128(address) & Ipv6Helper.PrefixMask(length));
            range = new Ipv6Range(network, length);
            return true;
        }

        /// Summary: True if the address lies inside this range.
        public bool Contains(IPAddress address)
            => (Ipv6Helper.ToUInt128(address) & Ipv6Helper.PrefixMask(PrefixLength)) == Ipv6Helper.ToUInt128(Network);

        /// Summary: True if the whole network (otherNetwork/otherPrefixLength) lies inside this range.
        public bool Covers(IPAddress otherNetwork, int otherPrefixLength)
            => otherPrefixLength >= PrefixLength && Contains(otherNetwork);

        /// Summary: True if the two networks share any addresses (one contains the other).
        public bool Overlaps(IPAddress otherNetwork, int otherPrefixLength)
        {
            var mask = Ipv6Helper.PrefixMask(Math.Min(PrefixLength, otherPrefixLength));
            return (Ipv6Helper.ToUInt128(Network) & mask) == (Ipv6Helper.ToUInt128(otherNetwork) & mask);
        }

        public override string ToString() => $"{Network}/{PrefixLength}";
    }
}
