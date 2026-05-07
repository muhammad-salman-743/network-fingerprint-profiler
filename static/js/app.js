// ============================================================
// Network Fingerprint & Website Behavior Profiler — Frontend
// ============================================================

const $ = (id) => document.getElementById(id);
let analysisMode = "compare"; // "single" | "compare"
let charts = {};
let lastResult = null;

// ---- Helpers ----
function fmtBytes(n) {
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
  return (n / 1024 / 1024).toFixed(2) + " MB";
}
function fmtNum(n) { return (n || 0).toLocaleString(); }

function setStep(active) {
  document.querySelectorAll("#stepper .step").forEach(el => {
    const n = parseInt(el.dataset.step, 10);
    el.classList.remove("active", "done");
    if (n < active) el.classList.add("done");
    else if (n === active) el.classList.add("active");
  });
}

function setStatus(state, title, msg) {
  document.body.classList.toggle("loading", state === "loading");
  $("statusTitle").textContent = title;
  $("statusMsg").textContent = msg;
}

function validateUrl(input, validationEl, required) {
  const v = input.value.trim();
  if (!v) {
    validationEl.textContent = required ? "URL required" : "";
    validationEl.className = "validation" + (required ? " err" : "");
    return !required;
  }
  
  // Check protocol
  if (!/^https?:\/\/.+/.test(v)) {
    validationEl.textContent = "✗ Must start with http:// or https://";
    validationEl.className = "validation err";
    return false;
  }
  
  // Try to parse as URL
  try {
    new URL(v);
  } catch (e) {
    validationEl.textContent = "✗ Invalid URL format";
    validationEl.className = "validation err";
    return false;
  }
  
  validationEl.textContent = "✓ Valid URL format";
  validationEl.className = "validation ok";
  return true;
}

// Validate URL with backend (checks hostname resolution)
async function validateUrlWithBackend(url) {
  try {
    const res = await fetch("/api/validate-url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url.trim() }),
    });
    const data = await res.json();
    return { valid: res.ok, error: data.error, host: data.host, ips: data.ips };
  } catch (err) {
    return { valid: false, error: "Network error: " + err.message };
  }
}

// ---- Toggle / theme / about ----
document.querySelectorAll("#analysisMode button").forEach(b => {
  b.addEventListener("click", () => {
    document.querySelectorAll("#analysisMode button").forEach(x => x.classList.remove("active"));
    b.classList.add("active");
    analysisMode = b.dataset.mode;
  });
});

$("themeToggle").addEventListener("click", () => {
  document.body.classList.toggle("light");
  document.body.classList.toggle("dark");
  $("themeToggle").textContent = document.body.classList.contains("light") ? "☀️" : "🌙";
});

$("aboutBtn").addEventListener("click", () => $("aboutModal").classList.remove("hidden"));
$("closeAbout").addEventListener("click", () => $("aboutModal").classList.add("hidden"));

$("primaryUrl").addEventListener("input", () =>
  validateUrl($("primaryUrl"), $("primaryValidation"), true));
$("compareUrl").addEventListener("input", () =>
  validateUrl($("compareUrl"), $("compareValidation"), false));

// Initial validation
validateUrl($("primaryUrl"), $("primaryValidation"), true);
validateUrl($("compareUrl"), $("compareValidation"), false);

// ---- Start analysis ----
$("startBtn").addEventListener("click", async () => {
  const okA = validateUrl($("primaryUrl"), $("primaryValidation"), true);
  const okB = analysisMode === "compare"
    ? validateUrl($("compareUrl"), $("compareValidation"), true)
    : true;
  
  if (!okA || !okB) {
    setStatus("error", "Validation failed", "Please check the URL format and try again.");
    return;
  }

  const primaryUrl = $("primaryUrl").value.trim();
  const compareUrl = $("compareUrl").value.trim();

  // Validate URLs with backend before starting analysis
  setStatus("loading", "Validating URLs...", "Checking if URLs are reachable...");
  $("startBtn").disabled = true;

  try {
    // Validate primary URL
    const validA = await validateUrlWithBackend(primaryUrl);
    if (!validA.valid) {
      setStatus("error", "Primary URL Invalid", validA.error || "Could not validate primary URL");
      $("startBtn").disabled = false;
      return;
    }

    // Validate compare URL if in compare mode
    if (analysisMode === "compare") {
      const validB = await validateUrlWithBackend(compareUrl);
      if (!validB.valid) {
        setStatus("error", "Compare URL Invalid", validB.error || "Could not validate compare URL");
        $("startBtn").disabled = false;
        return;
      }
    }

    // URLs are valid, proceed with analysis
    const payload = {
      primaryUrl: primaryUrl,
      compareUrl: compareUrl,
      captureDuration: parseInt($("captureDuration").value, 10),
    };

    setStep(2);
    setStatus("loading", "Capturing network traffic...",
      "Scapy is sniffing packets while traffic is generated to the target URL.");

    // Animate through stages for UX
    setTimeout(() => {
      setStep(3);
      setStatus("loading", "Analyzing packets...",
        "Extracting features and building the fingerprint.");
    }, 1500);

    const endpoint = analysisMode === "compare" ? "/api/compare" : "/api/analyze";
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Analysis failed");
    lastResult = data;
    renderResults(data);
    setStep(4);
    setStatus("done", "Analysis complete",
      "Fingerprints generated — explore the summary, charts, and JSON below.");
  } catch (err) {
    setStatus("error", "Error", err.message);
    setStep(1);
  } finally {
    $("startBtn").disabled = false;
  }
});

// ---- Render fingerprint card ----
function renderCard(el, fp, label, isCompare) {
  if (!fp) {
    el.classList.add("empty");
    el.innerHTML = `<div class="fp-empty">No data</div>`;
    return;
  }
  el.classList.remove("empty");
  const conf = fp.confidence || 0;
  el.innerHTML = `
    <div class="fp-head">
      <div>
        <div class="fp-title">Site ${label}</div>
        <div class="fp-url">${fp.site_url}</div>
      </div>
      <div class="fp-badge">${fp.behavior_label}</div>
    </div>
    <div class="fp-rows">
      <div class="fp-row"><span class="k">📅 Captured At</span><span class="v">${fp.capture_timestamp}</span></div>
      <div class="fp-row"><span class="k">⏱ Capture Duration</span><span class="v">${fp.capture_duration_sec}s</span></div>
      <div class="fp-row"><span class="k">📦 Total Packets</span><span class="v">${fmtNum(fp.total_packets)}</span></div>
      <div class="fp-row"><span class="k">📊 Total Bytes</span><span class="v">${fmtBytes(fp.total_bytes)}</span></div>
      <div class="fp-row"><span class="k">🔝 Top Protocol</span><span class="v">${fp.top_protocol} (${fp.top_protocol_percentage}%)</span></div>
      <div class="fp-row"><span class="k">🌐 Unique Dest IPs</span><span class="v">${fp.unique_ip_count}</span></div>
      <div class="fp-row"><span class="k">🔍 DNS Queries</span><span class="v">${fp.dns_query_count}</span></div>
      <div class="fp-row"><span class="k">📏 Mean Packet Size</span><span class="v">${fmtNum(fp.mean_packet_size)} bytes</span></div>
      <div class="fp-row"><span class="k">📐 Max Packet Size</span><span class="v">${fmtNum(fp.max_packet_size)} bytes</span></div>
      <div class="fp-row"><span class="k">🏷 Behavior</span><span class="v">${fp.behavior_label}</span></div>
      <div class="fp-row"><span class="k">✅ Confidence</span><span class="v">${conf}%</span></div>
    </div>
    <div class="confidence-bar"><div style="width:${conf}%"></div></div>
    <div class="fp-actions">
      <a href="#" class="view-details" data-site="${label}">🔍 View Details</a>
      <a href="/api/download?site=${label}">⬇ Download JSON</a>
    </div>
  `;
}

// ---- Render diff card ----
function renderDiffCard(diff, fpA, fpB) {
  const el = $("diffCard");
  if (!diff) {
    el.classList.add("empty");
    el.innerHTML = `<div class="fp-empty">Differences appear in compare mode.</div>`;
    return;
  }
  el.classList.remove("empty");
  const rows = [
    ["Total Bytes", fmtBytes(diff.total_bytes.a), fmtBytes(diff.total_bytes.b), diff.total_bytes],
    ["Total Packets", fmtNum(diff.total_packets.a), fmtNum(diff.total_packets.b), diff.total_packets],
    ["Unique IPs", diff.unique_ips.a, diff.unique_ips.b, diff.unique_ips],
    ["Mean Packet Size", fmtNum(diff.mean_packet_size.a) + " B", fmtNum(diff.mean_packet_size.b) + " B", diff.mean_packet_size],
    ["DNS Queries", diff.dns_queries.a, diff.dns_queries.b, diff.dns_queries],
  ];
  el.innerHTML = `
    <div class="fp-head"><div class="fp-title">Key Differences</div>
      <div class="fp-badge">A vs B</div></div>
    <div class="fp-rows">
      ${rows.map(([label, av, bv, d]) => {
        const aMore = d.who_has_more === fpA.site_url;
        const bMore = d.who_has_more === fpB.site_url;
        const aClass = aMore ? "higher" : (bMore ? "lower" : "equal");
        const bClass = bMore ? "higher" : (aMore ? "lower" : "equal");
        return `<div class="diff-row">
          <span class="diff-label">${label}</span>
          <span class="diff-val a-val ${aClass}">${av} ${aMore ? '↑' : (bMore ? '↓' : '')}</span>
          <span class="diff-ratio">${d.ratio || ''}</span>
          <span class="diff-val b-val ${bClass}">${bv} ${bMore ? '↑' : (aMore ? '↓' : '')}</span>
        </div>`;
      }).join("")}
      <div class="diff-row">
        <span class="diff-label">Behavior</span>
        <span class="diff-val a-val">${diff.behavior_label.a}</span>
        <span class="diff-ratio">vs</span>
        <span class="diff-val b-val">${diff.behavior_label.b}</span>
      </div>
    </div>
  `;
}

// ---- Render charts ----
const TEXT_COLOR = "#d6e4ff";
const GRID_COLOR = "rgba(122, 144, 184, 0.15)";
Chart.defaults.color = TEXT_COLOR;
Chart.defaults.borderColor = GRID_COLOR;
Chart.defaults.font.family = "Inter, sans-serif";

const COLOR_A = "#2ee27a";
const COLOR_B = "#4ea8ff";
const PROTO_COLORS = {
  TCP: "#2e8bff", UDP: "#ffb547", DNS: "#00e5ff",
  ICMP: "#ff5470", HTTP: "#4cabff", HTTPS: "#a0e", OTHER: "#7a90b8"
};

function destroyChart(name) {
  if (charts[name]) { charts[name].destroy(); delete charts[name]; }
}

function renderCharts(fpA, fpB) {
  // Protocol Doughnut
  destroyChart("protocol");
  const protoData = fpA.protocol_distribution || {};
  const labels = Object.keys(protoData);
  charts.protocol = new Chart($("protocolChart"), {
    type: "doughnut",
    data: {
      labels,
      datasets: [{
        data: labels.map(k => protoData[k]),
        backgroundColor: labels.map(k => PROTO_COLORS[k] || "#7a90b8"),
        borderColor: "#0c1a36", borderWidth: 2,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { position: "right" } },
      cutout: "62%"
    }
  });
  $("protocolNote").textContent = `Dominant: ${fpA.top_protocol} (${fpA.top_protocol_percentage}%)`;

  // Packet histogram (compare or single)
  destroyChart("histogram");
  const buckets = Object.keys(fpA.packet_size_buckets);
  const datasets = [{
    label: hostOf(fpA.site_url),
    data: buckets.map(b => fpA.packet_size_buckets[b]),
    backgroundColor: COLOR_A,
  }];
  if (fpB) {
    datasets.push({
      label: hostOf(fpB.site_url),
      data: buckets.map(b => fpB.packet_size_buckets[b]),
      backgroundColor: COLOR_B,
    });
  }
  charts.histogram = new Chart($("histogramChart"), {
    type: "bar",
    data: { labels: buckets, datasets },
    options: {
      scales: {
        x: {
          grid: { color: GRID_COLOR },
          title: { display: true, text: "Packet size bucket (bytes)", color: TEXT_COLOR, font: { weight: "600" } }
        },
        y: {
          grid: { color: GRID_COLOR },
          beginAtZero: true,
          title: { display: true, text: "Packet count", color: TEXT_COLOR, font: { weight: "600" } }
        },
      }
    }
  });

  // Timeline
  destroyChart("timeline");
  const tlLabels = fpA.bytes_per_second.map((_, i) => i);
  const tlDatasets = [{
    label: hostOf(fpA.site_url), data: fpA.bytes_per_second,
    borderColor: COLOR_A, backgroundColor: COLOR_A + "33",
    tension: 0.3, fill: true,
  }];
  if (fpB) {
    tlDatasets.push({
      label: hostOf(fpB.site_url), data: fpB.bytes_per_second,
      borderColor: COLOR_B, backgroundColor: COLOR_B + "33",
      tension: 0.3, fill: true,
    });
  }
  charts.timeline = new Chart($("timelineChart"), {
    type: "line",
    data: { labels: tlLabels, datasets: tlDatasets },
    options: {
      scales: {
        x: { title: { display: true, text: "Time (seconds)" }, grid: { color: GRID_COLOR } },
        y: { title: { display: true, text: "Bytes/sec" }, grid: { color: GRID_COLOR } },
      }
    }
  });

  // Overlay (same as timeline for compare report)
  destroyChart("overlay");
  charts.overlay = new Chart($("overlayChart"), {
    type: "line",
    data: { labels: tlLabels, datasets: tlDatasets },
    options: {
      scales: {
        x: { grid: { color: GRID_COLOR } },
        y: { grid: { color: GRID_COLOR } },
      }
    }
  });
}

function hostOf(url) {
  try { return new URL(url).hostname; } catch { return url; }
}

// ---- Compare table ----
function renderCompareTable(fpA, fpB, diff) {
  const tbody = $("compareTable").querySelector("tbody");
  if (!fpB || !diff) {
    tbody.innerHTML = `<tr><td colspan="5" class="muted">Run compare mode to populate this report.</td></tr>`;
    return;
  }
  const rows = [
    ["Total Bytes", fmtBytes(fpA.total_bytes), fmtBytes(fpB.total_bytes), diff.total_bytes],
    ["Total Packets", fmtNum(fpA.total_packets), fmtNum(fpB.total_packets), diff.total_packets],
    ["Unique Dest IPs", fpA.unique_ip_count, fpB.unique_ip_count, diff.unique_ips],
    ["Mean Packet Size", fpA.mean_packet_size + " B", fpB.mean_packet_size + " B", diff.mean_packet_size],
    ["DNS Queries", fpA.dns_query_count, fpB.dns_query_count, diff.dns_queries],
    ["Capture Duration", fpA.capture_duration_sec + "s", fpB.capture_duration_sec + "s",
      { ratio: fpA.capture_duration_sec === fpB.capture_duration_sec ? "=" : "—",
        who_has_more: fpA.capture_duration_sec === fpB.capture_duration_sec ? "Equal" : "—" }],
    ["Top Protocol", `${fpA.top_protocol} (${fpA.top_protocol_percentage}%)`,
      `${fpB.top_protocol} (${fpB.top_protocol_percentage}%)`, diff.top_protocol],
  ];
  tbody.innerHTML = rows.map(([m, a, b, d]) => {
    const ratio = d.ratio || "—";
    const who = d.who_has_more === fpA.site_url ? hostOf(fpA.site_url)
              : d.who_has_more === fpB.site_url ? hostOf(fpB.site_url)
              : (d.who_has_more || "Equal");
    const cls = (who === "Equal" || who === "equal") ? "equal" : "higher";
    return `<tr>
      <td>${m}</td><td>${a}</td><td>${b}</td>
      <td class="diff-cell ${cls}">${ratio}</td>
      <td>${who}</td>
    </tr>`;
  }).join("");
}

// ---- JSON output ----
function renderJson(fpA, fpB) {
  const trunc = (fp) => {
    if (!fp) return "{ }";
    const small = {
      site_url: fp.site_url,
      capture_timestamp: fp.capture_timestamp,
      capture_duration_sec: fp.capture_duration_sec,
      total_packets: fp.total_packets,
      total_bytes: fp.total_bytes,
      top_protocol: fp.top_protocol,
      top_protocol_percentage: fp.top_protocol_percentage,
      protocol_distribution: fp.protocol_distribution,
      behavior_label: fp.behavior_label,
      confidence: fp.confidence,
    };
    return JSON.stringify(small, null, 2);
  };
  $("jsonA").textContent = trunc(fpA);
  $("jsonB").textContent = trunc(fpB);
}

// ---- Master render ----
function renderResults(data) {
  const fpA = data.siteA;
  const fpB = data.siteB || null;
  renderCard($("cardA"), fpA, "A");
  renderCard($("cardB"), fpB, "B");
  renderDiffCard(data.diff, fpA, fpB);
  renderCharts(fpA, fpB);
  renderCompareTable(fpA, fpB, data.diff);
  renderJson(fpA, fpB);
}

// Initial empty doughnut so canvas shows
window.addEventListener("DOMContentLoaded", () => {
  charts.protocol = new Chart($("protocolChart"), {
    type: "doughnut",
    data: { labels: ["Awaiting data"], datasets: [{ data: [1], backgroundColor: ["#1a2f5c"] }] },
    options: { plugins: { legend: { display: false } }, cutout: "62%" }
  });
});
