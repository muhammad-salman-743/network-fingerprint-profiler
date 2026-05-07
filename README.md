# Network Fingerprint & Website Behavior Profiler

An educational web tool that captures live network traffic to a website,
extracts features, generates a structured **network fingerprint**, classifies
the site's behavior (Streaming, Social Media, Static Content, API-Heavy), and
visualizes everything with Chart.js. Two URLs can be compared side-by-side.

## Tech Stack
- **Python 3** — backend logic
- **Scapy** — packet capture & parsing
- **Flask** — REST API + template serving
- **HTML / CSS** — single-page UI (dark theme)
- **JavaScript** — API calls and DOM updates
- **Chart.js** — pie / bar / line visualizations
- **pcap / JSON** — raw + structured data formats

## Project Structure
```
netfp/
├── app.py                  # Flask app & API routes
├── backend/
│   ├── capture.py          # Scapy packet capture
│   ├── extract.py          # Feature extraction
│   ├── fingerprint.py      # Fingerprint assembly
│   └── classify.py         # Rule-based behavior classifier
├── templates/index.html    # Single-page UI
├── static/
│   ├── css/style.css
│   └── js/app.js
├── requirements.txt
└── README.md
```

## Setup
```bash
python -m venv venv
source venv/bin/activate         # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```
Open http://localhost:5000 in your browser.

## Live capture (optional, requires admin/root)
By default the app runs in **demo mode** with deterministic synthetic packet
traces so it works in any environment (including classrooms without raw socket
permission). To enable real Scapy live capture:

```bash
USE_LIVE_CAPTURE=1 sudo python app.py        # Linux/macOS
# Windows: install Npcap, then run as Administrator with USE_LIVE_CAPTURE=1
```

## API Endpoints
| Method | Endpoint        | Body                                            | Returns |
|--------|-----------------|-------------------------------------------------|---------|
| POST   | `/api/analyze`  | `{ primaryUrl, captureDuration }`               | `{ siteA }` |
| POST   | `/api/compare`  | `{ primaryUrl, compareUrl, captureDuration }`   | `{ siteA, siteB, diff }` |
| GET    | `/api/download?site=A|B` | —                                       | downloads JSON |

## Workflow
1. User enters URL(s) and clicks Analyze.
2. Flask resolves the domain to IPs.
3. Scapy captures packets for N seconds while traffic is generated.
4. `extract.py` computes statistics from the packet list.
5. `fingerprint.py` assembles the structured JSON fingerprint.
6. `classify.py` assigns a behavior label + confidence.
7. Frontend renders summary cards, comparison table, and Chart.js visuals.

## Educational Use Only
Always capture traffic on networks and websites you own or have permission to test.
