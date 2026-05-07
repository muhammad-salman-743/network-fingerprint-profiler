"""
Network Fingerprint Generator & Website Behavior Profiler
Flask backend - main entry point.
"""
import os
import json
import time
import socket
from urllib.parse import urlparse
from flask import Flask, render_template, request, jsonify, send_file, abort

from backend.capture import capture_traffic
from backend.extract import extract_features
from backend.fingerprint import build_fingerprint
from backend.classify import classify_behavior

app = Flask(__name__, static_folder="static", template_folder="templates")

# In-memory store for last fingerprint(s) so /api/download works.
LAST_RESULTS = {}


def resolve_host(url: str):
    try:
        host = urlparse(url).hostname
        if not host:
            return None, []
        infos = socket.getaddrinfo(host, None)
        ips = sorted({i[4][0] for i in infos})
        return host, ips
    except Exception:
        return None, []


def analyze_url(url: str, duration: int):
    host, ips = resolve_host(url)
    if not host:
        raise ValueError("Could not resolve host for URL: " + url)

    pcap_path, packets = capture_traffic(url, host, ips, duration)
    features = extract_features(packets, host=host, allowed_ips=ips,
                                duration=duration)
    fp = build_fingerprint(url, features, duration)
    label, confidence = classify_behavior(fp)
    fp["behavior_label"] = label
    fp["confidence"] = confidence
    fp["pcap_file"] = os.path.basename(pcap_path) if pcap_path else None
    return fp


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/validate-url", methods=["POST"])
def api_validate_url():
    """Validate URL format and hostname resolution before analysis."""
    data = request.get_json(force=True, silent=True) or {}
    url = (data.get("url") or "").strip()
    
    # Check if URL is empty
    if not url:
        return jsonify({"valid": False, "error": "URL is required"}), 400
    
    # Check protocol
    if not url.startswith(("http://", "https://")):
        return jsonify({"valid": False, "error": "URL must start with http:// or https://"}), 400
    
    # Validate URL format
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if not parsed.netloc:
            return jsonify({"valid": False, "error": "URL must include a domain (e.g., https://example.com)"}), 400
    except Exception as e:
        return jsonify({"valid": False, "error": f"Invalid URL format: {str(e)}"}), 400
    
    # Try to resolve hostname
    host, ips = resolve_host(url)
    if not host or not ips:
        return jsonify({"valid": False, "error": f"Cannot resolve hostname. Check if the domain is valid and accessible."}), 400
    
    return jsonify({"valid": True, "host": host, "ips": ips, "message": "URL is valid and resolvable"}), 200


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json(force=True, silent=True) or {}
    url = (data.get("primaryUrl") or "").strip()
    duration = int(data.get("captureDuration") or 10)
    if not url.startswith(("http://", "https://")):
        return jsonify({"error": "Invalid URL. Must start with http:// or https://"}), 400
    try:
        fp = analyze_url(url, duration)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    LAST_RESULTS["A"] = fp
    return jsonify({"siteA": fp})


@app.route("/api/compare", methods=["POST"])
def api_compare():
    data = request.get_json(force=True, silent=True) or {}
    url_a = (data.get("primaryUrl") or "").strip()
    url_b = (data.get("compareUrl") or "").strip()
    duration = int(data.get("captureDuration") or 10)
    for u in (url_a, url_b):
        if not u.startswith(("http://", "https://")):
            return jsonify({"error": f"Invalid URL: {u}"}), 400
    try:
        fp_a = analyze_url(url_a, duration)
        fp_b = analyze_url(url_b, duration)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    LAST_RESULTS["A"] = fp_a
    LAST_RESULTS["B"] = fp_b

    diff = build_diff(fp_a, fp_b)
    return jsonify({"siteA": fp_a, "siteB": fp_b, "diff": diff})


def build_diff(a, b):
    metrics = ["total_bytes", "total_packets", "unique_ips",
               "mean_packet_size", "dns_queries"]
    result = {}
    for m in metrics:
        va, vb = a.get(m, 0) or 0, b.get(m, 0) or 0
        if isinstance(va, list):
            va = len(va)
        if isinstance(vb, list):
            vb = len(vb)
        if va == vb:
            who = "equal"
            ratio = "="
        else:
            who = a["site_url"] if va > vb else b["site_url"]
            ratio = f"{(max(va, vb) / max(min(va, vb), 1)):.2f}x"
        result[m] = {"a": va, "b": vb, "who_has_more": who, "ratio": ratio}
    result["top_protocol"] = {
        "a": a.get("top_protocol"),
        "b": b.get("top_protocol"),
        "who_has_more": "equal" if a.get("top_protocol") == b.get("top_protocol")
        else a["site_url"],
    }
    result["behavior_label"] = {
        "a": a.get("behavior_label"),
        "b": b.get("behavior_label"),
    }
    return result


@app.route("/api/download")
def api_download():
    which = request.args.get("site", "A").upper()
    fp = LAST_RESULTS.get(which)
    if not fp:
        return abort(404, "No fingerprint available. Run an analysis first.")
    payload = json.dumps(fp, indent=2, default=str)
    from io import BytesIO
    buf = BytesIO(payload.encode("utf-8"))
    return send_file(buf, as_attachment=True,
                     download_name=f"fingerprint_{which}.json",
                     mimetype="application/json")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
