import json
import sys

names = [
    "TCP_NEW_ALLOW",
    "TCP_ESTABLISHED",
    "TCP_DROP",
    "UDP_PASS",
    "UDP_DROP",
    "IPv4_OTHER",
    "IPv6_ICMP",
    "FRAG_DROP",
    "ARP_NON_IP",
    "TCP_CT_MISS",
    "ICMP_DROP",
    "SYN_RATE_DROP",
    "UDP_RATE_DROP",
    "UDP_GBL_DROP",
    "TCP_NULL",
    "TCP_XMAS",
    "TCP_SYN_FIN",
    "TCP_SYN_RST",
    "TCP_RST_FIN",
    "TCP_BAD_DOFF",
    "TCP_PORT0",
    "VLAN_DROP",
    "SLOT_CALL",
    "SLOT_PASS",
    "SLOT_DROP",
    "UDP_PORT0",
    "UDP_BAD_LEN",
    "BOGON_DROP",
]

def norm(values):
    if isinstance(values, int):
        return values
    if isinstance(values, str):
        try:
            return int(values, 0)
        except ValueError:
            return 0
    if isinstance(values, list):
        return sum(norm(item) for item in values)
    if isinstance(values, dict):
        if "value" in values:
            return norm(values["value"])
        if "values" in values:
            return norm(values["values"])
        total = 0
        for key, item in values.items():
            if key in {"cpu", "index", "key"}:
                continue
            total += norm(item)
        return total
    return 0

def parse_key(key):
    if isinstance(key, int):
        return key
    if isinstance(key, str):
        try:
            return int(key, 0)
        except ValueError:
            return 0
    if isinstance(key, list):
        val = 0
        for i, b in enumerate(key):
            try:
                v = int(b, 0) if isinstance(b, str) else int(b)
                val |= (v & 0xFF) << (i * 8)
            except ValueError:
                pass
        return val
    return -1

rows = json.loads('[{"key":["0x01","0x00","0x00","0x00"],"values":[{"cpu":0,"value":5}]},{"key":28,"values":[{"cpu":0,"value":10}]}]')

key_packets = {}
for row in rows:
    values = row.get("values")
    if values is None:
        values = row.get("value")
    packets = norm(values)
    k = parse_key(row.get("key"))
    if k >= 0:
        key_packets[k] = packets

total = 0
for idx in range(32):
    packets = key_packets.get(idx, 0)
    total += packets
    name = names[idx] if idx < len(names) else f"COUNTER_{idx}"
    print(f"{name}|{packets}|-1")

for idx in sorted(key_packets.keys()):
    if idx >= 32:
        print(f"COUNTER_{idx}|{key_packets[idx]}|-1")

print(f"XDP_TOTAL|{total}|-1")
