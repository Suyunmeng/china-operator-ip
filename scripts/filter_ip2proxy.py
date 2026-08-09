#!/usr/bin/env python3
import argparse
import ipaddress
import re
import struct
from collections import defaultdict

COUNTRY_POSITION = (0, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3)


class IP2ProxyDatabase:
    def __init__(self, path):
        self.file = open(path, "rb")
        header = self.file.read(32)
        if len(header) != 32:
            raise ValueError("IP2Proxy BIN header is incomplete")
        self.db_type = header[0]
        self.columns = header[1]
        self.ipv4_count = struct.unpack_from("<I", header, 5)[0]
        self.ipv4_addr = struct.unpack_from("<I", header, 9)[0]
        self.ipv6_count = struct.unpack_from("<I", header, 13)[0]
        self.ipv6_addr = struct.unpack_from("<I", header, 17)[0]
        if header[29] != 2:
            raise ValueError("database is not an IP2Proxy BIN file")
        if self.db_type >= len(COUNTRY_POSITION):
            raise ValueError("database does not provide the country field")

    def close(self):
        self.file.close()

    def lookup(self, address):
        if address.version == 4:
            return self._lookup_v4(int(address))
        return self._lookup_v6(int(address))

    def _lookup_v4(self, value):
        low, high = 0, self.ipv4_count
        while low <= high:
            mid = (low + high) // 2
            offset = self.ipv4_addr - 1 + mid * self.columns * 4
            self.file.seek(offset)
            row = self.file.read((self.columns + 1) * 4)
            start = struct.unpack_from("<I", row, 0)[0]
            end = struct.unpack_from("<I", row, self.columns * 4)[0]
            if start <= value < end:
                return end, self._fields(row, 4)
            if value < start:
                high = mid - 1
            else:
                low = mid + 1
        raise ValueError(f"no IP2Proxy record for {ipaddress.IPv4Address(value)}")

    def _lookup_v6(self, value):
        low, high = 0, self.ipv6_count
        row_size = self.columns * 4 + 12 + 16
        while low <= high:
            mid = (low + high) // 2
            offset = self.ipv6_addr - 1 + mid * (self.columns * 4 + 12)
            self.file.seek(offset)
            row = self.file.read(row_size)
            start = self._read_u128(row, 0)
            end = self._read_u128(row, self.columns * 4 + 12)
            if start <= value < end:
                return end, self._fields(row, 6)
            if value < start:
                high = mid - 1
            else:
                low = mid + 1
        return None

    @staticmethod
    def _read_u128(row, offset):
        words = struct.unpack_from("<IIII", row, offset)
        return words[0] | (words[1] << 32) | (words[2] << 64) | (words[3] << 96)

    def _fields(self, row, version):
        prefix = 0 if version == 4 else 12
        country_offset = prefix + 4 * (COUNTRY_POSITION[self.db_type] - 1)
        country_pointer = struct.unpack_from("<I", row, country_offset)[0]
        self.file.seek(country_pointer)
        country_length = self.file.read(1)[0]
        country = self.file.read(country_length).decode("iso-8859-1")
        return country


def parse_networks(path):
    with open(path, encoding="utf-8") as networks:
        for line in networks:
            value = line.strip()
            if value:
                yield ipaddress.ip_network(value, strict=False)


def merge_ranges(ranges):
    ranges.sort()
    merged = []
    for start, end in ranges:
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True)
    parser.add_argument("--network-file", required=True)
    parser.add_argument("--country", default="")
    args = parser.parse_args()

    country = args.country.upper()
    if country and not re.fullmatch(r"[A-Z]{2}", country):
        parser.error("--country must be an ISO 3166-1 alpha-2 code")

    database = IP2ProxyDatabase(args.database)
    try:
        selected = defaultdict(list)
        for network in parse_networks(args.network_file):
            current = int(network.network_address)
            end = int(network.broadcast_address)
            while current <= end:
                lookup = database.lookup(network.network_address.__class__(current))
                if lookup is None:
                    break
                record_end, record_country = lookup
                selected_end = min(end, record_end - 1)
                if not country or record_country.upper() == country:
                    selected[network.version].append((current, selected_end))
                current = selected_end + 1

        for version in (4, 6):
            address = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
            for start, end in merge_ranges(selected[version]):
                for network in ipaddress.summarize_address_range(address(start), address(end)):
                    print(network)
    finally:
        database.close()


if __name__ == "__main__":
    main()
