"""
Fingerprint assembly module.

Takes the feature dictionary from extract.py and packages it into a
structured JSON fingerprint object.
"""
from datetime import datetime


def build_fingerprint(url, features, duration):
    return {
        "site_url": url,
        "capture_timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "capture_duration_sec": duration,
        "total_packets": features["total_packets"],
        "total_bytes": features["total_bytes"],
        "top_protocol": features["top_protocol"],
        "top_protocol_percentage": features["top_protocol_pct"],
        "unique_ips": features["unique_ips"],
        "unique_ip_count": len(features["unique_ips"]),
        "dns_queries": features["dns_queries"],
        "dns_query_count": len(features["dns_queries"]),
        "mean_packet_size": features["mean_packet_size"],
        "max_packet_size": features["max_packet_size"],
        "min_packet_size": features["min_packet_size"],
        "protocol_distribution": features["protocol_distribution"],
        "packet_size_buckets": features["packet_size_buckets"],
        "bytes_per_second": features["bytes_per_second"],
        "behavior_label": "Unknown",
        "confidence": 0,
    }
