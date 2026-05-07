"""
Feature extraction module.

Reads a list of packets (either Scapy packet objects or synthetic dicts) and
computes the statistics required to assemble a network fingerprint.
"""
from statistics import mean


def _packet_view(pkt):
    """Normalize a packet (Scapy or dict) to a uniform dict view."""
    if isinstance(pkt, dict):
        return pkt
    try:
        from scapy.all import IP, TCP, UDP, DNS, ICMP
        size = len(pkt)
        ts = float(getattr(pkt, "time", 0)) or 0.0
        proto = "OTHER"
        dst = None
        is_dns = False
        dns_name = None
        if pkt.haslayer(IP):
            dst = pkt[IP].dst
            if pkt.haslayer(TCP):
                sport = getattr(pkt[TCP], 'sport', None)
                dport = getattr(pkt[TCP], 'dport', None)
                if sport == 80 or dport == 80:
                    proto = "HTTP"
                elif sport == 443 or dport == 443:
                    proto = "HTTPS"
                else:
                    proto = "TCP"
            elif pkt.haslayer(UDP):
                proto = "UDP"
                if pkt.haslayer(DNS):
                    proto = "DNS"
                    is_dns = True
                    try:
                        q = pkt[DNS].qd
                        if q is not None:
                            dns_name = q.qname.decode(errors="ignore")
                    except Exception:
                        pass
                else:
                    proto = "UDP"
            elif pkt.haslayer(ICMP):
                proto = "ICMP"
        return {"ts": ts, "size": size, "proto": proto, "dst": dst,
                "is_dns": is_dns, "dns_name": dns_name}
    except Exception:
        return {"ts": 0, "size": 0, "proto": "OTHER", "dst": None,
                "is_dns": False, "dns_name": None}


def extract_features(packets, host=None, allowed_ips=None, duration=10):
    views = [_packet_view(p) for p in packets]
    if not views:
        return _empty_features(duration)

    sizes = [v["size"] for v in views]
    total_packets = len(views)
    total_bytes = sum(sizes)

    # Initialize all known protocols to 0
    known_protos = ["TCP", "UDP", "DNS", "ICMP", "HTTP", "HTTPS", "OTHER"]
    proto_counts = {p: 0 for p in known_protos}
    
    for v in views:
        proto = v["proto"]
        if proto in proto_counts:
            proto_counts[proto] += 1
        else:
            proto_counts["OTHER"] += 1
    
    # Calculate percentages for non-zero protocols only
    protocol_distribution = {
        k: round(100 * c / total_packets, 1) for k, c in proto_counts.items() if c > 0
    }
    top_protocol = max(proto_counts.items(), key=lambda x: x[1])[0]
    top_protocol_pct = protocol_distribution[top_protocol]

    unique_ips = sorted({v["dst"] for v in views if v["dst"]})
    dns_names = sorted({v["dns_name"] for v in views if v.get("dns_name")})

    # Inter-arrival times
    ts = sorted([v["ts"] for v in views if v["ts"] > 0])
    iats = [round(ts[i] - ts[i - 1], 4) for i in range(1, len(ts))]

    # Histogram buckets
    buckets = {"0-100": 0, "101-500": 0, "501-1000": 0,
               "1001-1500": 0, "1500+": 0}
    for s in sizes:
        if s <= 100:
            buckets["0-100"] += 1
        elif s <= 500:
            buckets["101-500"] += 1
        elif s <= 1000:
            buckets["501-1000"] += 1
        elif s <= 1500:
            buckets["1001-1500"] += 1
        else:
            buckets["1500+"] += 1

    # Bytes per second timeline (1s buckets across capture window)
    if ts:
        t0 = ts[0]
        bps = [0] * max(1, int(duration))
        for v in views:
            idx = int(v["ts"] - t0)
            if 0 <= idx < len(bps):
                bps[idx] += v["size"]
    else:
        bps = [0] * max(1, int(duration))

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "mean_packet_size": int(mean(sizes)),
        "max_packet_size": int(max(sizes)),
        "min_packet_size": int(min(sizes)),
        "top_protocol": top_protocol,
        "top_protocol_pct": top_protocol_pct,
        "protocol_distribution": protocol_distribution,
        "unique_ips": unique_ips,
        "dns_queries": dns_names,
        "inter_arrival_times": iats[:200],
        "packet_size_buckets": buckets,
        "bytes_per_second": bps,
    }


def _empty_features(duration):
    return {
        "total_packets": 0, "total_bytes": 0,
        "mean_packet_size": 0, "max_packet_size": 0, "min_packet_size": 0,
        "top_protocol": "N/A", "top_protocol_pct": 0,
        "protocol_distribution": {},
        "unique_ips": [], "dns_queries": [],
        "inter_arrival_times": [],
        "packet_size_buckets": {"0-100": 0, "101-500": 0, "501-1000": 0,
                                "1001-1500": 0, "1500+": 0},
        "bytes_per_second": [0] * max(1, int(duration)),
    }
