"""
Packet capture module.

Uses Scapy to sniff packets on the active interface for a configurable window
while simultaneously triggering HTTP requests to the target URL to generate
traffic. Captured packets are written to a temporary .pcap file and also
returned in-memory for downstream processing.

If Scapy cannot capture packets (e.g. running without root privileges, or in
an environment with no live interface), a deterministic synthetic packet
trace is generated so the rest of the pipeline still works for demos.
"""
import os
import time
import threading
import tempfile
import random
from urllib.parse import urlparse

try:
    from scapy.all import sniff, wrpcap, IP, TCP, UDP, DNS, Ether, Raw
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


def _generate_traffic(url, duration):
    """Hit the target URL repeatedly to generate live traffic during sniff."""
    try:
        import requests
    except ImportError:
        return
    end = time.time() + duration
    while time.time() < end:
        try:
            requests.get(url, timeout=3)
        except Exception:
            pass
        time.sleep(0.5)


def _live_capture(url, host, allowed_ips, duration):
    pcap_dir = tempfile.gettempdir()
    pcap_path = os.path.join(pcap_dir, f"capture_{int(time.time())}.pcap")

    bpf = None
    if allowed_ips:
        bpf = " or ".join([f"host {ip}" for ip in allowed_ips])
        bpf = f"({bpf}) or port 53"
    else:
        bpf = "port 53"

    t = threading.Thread(target=_generate_traffic, args=(url, duration),
                         daemon=True)
    t.start()

    packets = sniff(filter=bpf, timeout=duration, store=True)
    try:
        wrpcap(pcap_path, packets)
    except Exception:
        pcap_path = None
    return pcap_path, list(packets)


def _synthetic_capture(url, host, duration):
    """Produce a deterministic-but-realistic synthetic packet trace."""
    random.seed(hash(host) & 0xFFFFFFFF)
    is_streaming = any(x in host for x in ("netflix", "youtube", "video",
                                           "stream", "twitch"))
    is_static = any(x in host for x in ("bbc", "wiki", "news", "blog"))
    is_api = any(x in host for x in ("api.", "graphql", "rest"))

    if is_streaming:
        n_packets, mean_size, proto_mix = 8000, 1100, ("HTTPS", 0.75)
    elif is_static:
        n_packets, mean_size, proto_mix = 1200, 500, ("HTTP", 0.65)
    elif is_api:
        n_packets, mean_size, proto_mix = 2000, 200, ("HTTPS", 0.85)
    else:
        n_packets, mean_size, proto_mix = 3000, 700, ("TCP", 0.75)

    n_packets = int(n_packets * (duration / 10.0))
    packets = []
    start = time.time()
    proto_name, proto_pct = proto_mix
    n_unique_ips = 25 if not is_static else 12
    fake_ips = [f"203.0.113.{i+1}" for i in range(n_unique_ips)]
    dns_count = max(5, int(n_unique_ips * 0.7))

    for i in range(n_packets):
        r = random.random()
        if r < proto_pct:
            proto = "TCP"
            size = max(60, int(random.gauss(mean_size, mean_size * 0.4)))
        elif r < proto_pct + 0.08:
            proto = "UDP"
            size = random.randint(60, 400)
        elif r < proto_pct + 0.12:
            proto = "DNS"
            size = random.randint(60, 200)
        elif r < proto_pct + 0.16:
            proto = "ICMP"
            size = random.randint(60, 120)
        elif r < proto_pct + 0.20:
            proto = "TCP" if proto_name != "TCP" else "HTTP"
            size = max(60, int(random.gauss(mean_size * 0.5, mean_size * 0.3)))
        else:
            proto = "OTHER"
            size = random.randint(60, 200)

        ts = start + (i / n_packets) * duration
        dst = random.choice(fake_ips)
        packets.append({
            "ts": ts,
            "size": size,
            "proto": proto,
            "dst": dst,
            "is_dns": proto == "DNS",
            "dns_name": (host if proto == "DNS" else None),
        })

    # Add explicit DNS queries for variety
    for i in range(dns_count):
        packets.append({
            "ts": start + (i / dns_count) * 0.5,
            "size": random.randint(60, 150),
            "proto": "DNS",
            "dst": "8.8.8.8",
            "is_dns": True,
            "dns_name": f"sub{i}.{host}",
        })
    packets.sort(key=lambda p: p["ts"])
    return None, packets


def capture_traffic(url, host, allowed_ips, duration):
    """
    Returns (pcap_path_or_None, packets_list).
    `packets_list` items are either Scapy packet objects or normalized dicts
    when running in synthetic mode. The extractor handles both.
    """
    return _live_capture(url, host, allowed_ips, duration)
    if SCAPY_AVAILABLE and os.environ.get("USE_LIVE_CAPTURE", "0") == "1":
        try:
            return _live_capture(url, host, allowed_ips, duration)
        except PermissionError:
            pass
        except Exception:
            pass
    return _synthetic_capture(url, host, duration)
