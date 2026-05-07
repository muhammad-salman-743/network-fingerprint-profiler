"""
Rule-based behavior classifier.

Reads a fingerprint dictionary and returns (label, confidence_percent).
Categories: Streaming, Social Media, Static Content, API-Heavy.
"""


def _clamp(value, minimum, maximum):
    return max(minimum, min(maximum, value))


def _score_streaming(fp):
    total_bytes = fp.get("total_bytes", 0)
    mean_size = fp.get("mean_packet_size", 0)
    top_proto = fp.get("top_protocol", "")
    top_pct = fp.get("top_protocol_percentage", 0)

    score = 0
    if top_proto in ("TCP", "UDP", "HTTP", "HTTPS"):
        score += 20
    score += _clamp((mean_size - 400) / 1100 * 40, 0, 40)
    score += _clamp((total_bytes - 1_000_000) / 4_000_000 * 30, 0, 30)
    score += _clamp((top_pct - 60) / 40 * 10, 0, 10)
    return _clamp(score, 0, 100)


def _score_api(fp):
    total_packets = fp.get("total_packets", 0)
    mean_size = fp.get("mean_packet_size", 0)
    top_proto = fp.get("top_protocol", "")
    top_pct = fp.get("top_protocol_percentage", 0)
    dns_q = fp.get("dns_query_count", 0)

    score = 0
    if top_proto in ("TCP", "HTTP", "HTTPS"):
        score += 25
    score += _clamp((350 - mean_size) / 350 * 30, 0, 30)
    score += _clamp((total_packets - 120) / 380 * 25, 0, 25)
    score += _clamp((top_pct - 50) / 50 * 10, 0, 10)
    score += _clamp(dns_q / 10 * 15, 0, 15)
    return _clamp(score, 0, 100)


def _score_social(fp):
    unique_ips = fp.get("unique_ip_count", 0)
    total_packets = fp.get("total_packets", 0)
    top_pct = fp.get("top_protocol_percentage", 0)
    dns_q = fp.get("dns_query_count", 0)

    score = 0
    score += _clamp((unique_ips - 4) / 20 * 35, 0, 35)
    if top_pct < 90:
        score += _clamp((90 - top_pct) / 90 * 25, 0, 25)
    score += _clamp(dns_q / 12 * 20, 0, 20)
    score += _clamp((total_packets - 150) / 500 * 20, 0, 20)
    return _clamp(score, 0, 100)


def _score_static(fp):
    total_bytes = fp.get("total_bytes", 0)
    total_packets = fp.get("total_packets", 0)
    mean_size = fp.get("mean_packet_size", 0)
    top_pct = fp.get("top_protocol_percentage", 0)

    score = 0
    score += _clamp((1_200_000 - total_bytes) / 1_200_000 * 40, 0, 40)
    score += _clamp((420 - total_packets) / 420 * 30, 0, 30)
    score += _clamp((750 - mean_size) / 750 * 20, 0, 20)
    if top_pct >= 70:
        score += _clamp((top_pct - 70) / 30 * 10, 0, 10)
    return _clamp(score, 0, 100)


def classify_behavior(fp):
    total_bytes = fp.get("total_bytes", 0)
    total_packets = fp.get("total_packets", 0)
    mean_size = fp.get("mean_packet_size", 0)
    unique_ips = fp.get("unique_ip_count", 0)
    dns_q = fp.get("dns_query_count", 0)
    top_proto = fp.get("top_protocol", "")
    top_pct = fp.get("top_protocol_percentage", 0)

    # Strong signature rules for clearly identifiable behavior.
    if mean_size >= 900 and total_bytes >= 1_500_000 and top_proto in ("TCP", "UDP", "HTTP", "HTTPS"):
        return "Streaming", min(95, int(80 + top_pct / 5))

    if mean_size <= 350 and top_proto in ("TCP", "HTTP", "HTTPS") and total_packets >= 120:
        return "API-Heavy", min(92, int(70 + (100 - top_pct) / 5))

    if unique_ips >= 12 and dns_q >= 4 and top_pct < 88:
        return "Social Media", min(90, int(70 + unique_ips / 2))

    if total_bytes < 1_200_000 and total_packets < 700 and dns_q <= 6:
        return "Static Content", min(88, int(65 + (100 - top_pct) / 6))

    # Fallback scoring ensures every fingerprint gets a label.
    scores = {
        "Streaming": _score_streaming(fp),
        "API-Heavy": _score_api(fp),
        "Social Media": _score_social(fp),
        "Static Content": _score_static(fp),
    }
    label = max(scores, key=scores.get)
    top_score = scores[label]
    second_best = max(v for k, v in scores.items() if k != label)
    confidence = int(_clamp(top_score - (second_best * 0.1), 50, 95))
    return label, confidence
