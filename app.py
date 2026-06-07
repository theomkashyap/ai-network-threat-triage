import subprocess
import csv
import json
import os
import uuid
import threading
import requests
from collections import Counter
from datetime import datetime
from flask import Flask, jsonify, request, Response, send_from_directory

app = Flask(__name__)

# ================================================
# CONFIGURATION — edit these before running
# ================================================

INTERFACE        = "eth0"          # your network interface (check with: ip a)
CAPTURE_DURATION = 60              # capture window in seconds
ICMP_THRESHOLD   = 40             # ICMP packets from one IP to trigger alert
PORT_SCAN_THRESHOLD   = 15        # unique ports hit by one IP to trigger alert
SSH_ATTEMPT_THRESHOLD = 5         # SSH packets from one IP to trigger alert

LOG_FILE = "/tmp/alerts_log.json"

# ---- Airia AI Agent ----
# Sign up at airia.ai, create an agent with soc_playbook.md as instructions,
# publish it, and paste your pipeline URL and API key below.
AIRIA_API_URL = "YOUR_AIRIA_PIPELINE_URL"
AIRIA_API_KEY = "YOUR_AIRIA_API_KEY"

# ---- Target server ----
DESTINATION_HOST = "Internal-server"   # label for your server
DESTINATION_IP   = "YOUR_SERVER_IP"    # IP of the machine running this tool

# ================================================

# live capture state (shown in dashboard)
capture_status = {
    "running":        False,
    "message":        "Idle",
    "attack_type":    "",
    "live_packets":   0,
    "live_breakdown": {}
}

# ------------------------------------------------
# LOG HELPERS
# ------------------------------------------------
def load_log():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE) as f:
            try:
                return json.load(f)
            except Exception:
                return []
    return []

def save_log(entries):
    with open(LOG_FILE, "w") as f:
        json.dump(entries, f, indent=2)

def append_to_log(entry):
    entries = load_log()
    entries.insert(0, entry)
    save_log(entries)

# ------------------------------------------------
# LIVE PACKET COUNTER
# Runs in a background thread during capture,
# reads the growing pcap every 2s and updates
# the live packet count shown in the dashboard.
# ------------------------------------------------
def live_counter(pcap_file, stop_event):
    while not stop_event.is_set():
        stop_event.wait(2)
        if os.path.exists(pcap_file):
            try:
                result = subprocess.run(
                    ["tshark", "-r", pcap_file, "-T", "fields",
                     "-e", "ip.src", "-E", "header=n", "-E", "separator=,"],
                    capture_output=True, text=True, timeout=5
                )
                lines = [l.strip().strip('"') for l in result.stdout.splitlines() if l.strip()]
                capture_status["live_packets"] = len(lines)
                c = Counter(lines)
                capture_status["live_breakdown"] = dict(c.most_common(5))
            except Exception:
                pass

# ------------------------------------------------
# AUTO-DETECT ATTACK TYPE
# Analyzes a completed pcap against three
# detection rules and returns the highest-priority
# finding as a structured alert dict.
# ------------------------------------------------
def detect_attack_type(pcap_file):
    findings = []

    # Rule 1 — ICMP Flood
    try:
        r = subprocess.run([
            "tshark", "-r", pcap_file, "-Y", "icmp",
            "-T", "fields", "-e", "ip.src",
            "-E", "header=n", "-E", "separator=,"
        ], capture_output=True, text=True, timeout=10)
        icmp_counter = Counter(
            l.strip().strip('"') for l in r.stdout.splitlines() if l.strip()
        )
        for ip, count in icmp_counter.items():
            if count > ICMP_THRESHOLD:
                findings.append(("icmp", ip, count, {
                    "packet_count":        count,
                    "time_window_seconds": CAPTURE_DURATION,
                    "data_source":         os.path.basename(pcap_file)
                }))
    except Exception:
        pass

    # Rule 2 — Port Scan (TCP SYN without ACK)
    try:
        r = subprocess.run([
            "tshark", "-r", pcap_file,
            "-Y", f"tcp.flags.syn==1 and tcp.flags.ack==0 and ip.dst=={DESTINATION_IP}",
            "-T", "fields", "-e", "ip.src", "-e", "tcp.dstport",
            "-E", "header=n", "-E", "separator=,"
        ], capture_output=True, text=True, timeout=10)
        scan_map = {}
        for line in r.stdout.splitlines():
            parts = line.replace('"', '').split(',')
            if len(parts) >= 2:
                src, port = parts[0].strip(), parts[1].strip()
                if src and port:
                    scan_map.setdefault(src, set()).add(port)
        for ip, ports in scan_map.items():
            if len(ports) >= PORT_SCAN_THRESHOLD:
                findings.append(("portscan", ip, len(ports), {
                    "packet_count":          len(ports),
                    "unique_ports_scanned":  sorted(list(ports))[:20],
                    "time_window_seconds":   CAPTURE_DURATION,
                    "data_source":           os.path.basename(pcap_file)
                }))
    except Exception:
        pass

    # Rule 3 — SSH Brute Force
    try:
        r = subprocess.run([
            "tshark", "-r", pcap_file,
            "-Y", f"tcp.dstport==22 and ip.dst=={DESTINATION_IP}",
            "-T", "fields", "-e", "ip.src",
            "-E", "header=n", "-E", "separator=,"
        ], capture_output=True, text=True, timeout=10)
        ssh_counter = Counter(
            l.strip().strip('"') for l in r.stdout.splitlines() if l.strip()
        )
        for ip, count in ssh_counter.items():
            if count >= SSH_ATTEMPT_THRESHOLD:
                findings.append(("ssh", ip, count, {
                    "packet_count":        count,
                    "target_port":         22,
                    "time_window_seconds": CAPTURE_DURATION,
                    "data_source":         os.path.basename(pcap_file)
                }))
    except Exception:
        pass

    if not findings:
        return None, None

    # highest packet count wins
    findings.sort(key=lambda x: x[2], reverse=True)
    atk_type, ip, count, evidence = findings[0]

    type_map = {
        "icmp":     ("ICMP Flood",                       "ICMP"),
        "portscan": ("Network Reconnaissance / Scanning", "TCP"),
        "ssh":      ("Brute Force Attempt",               "TCP/SSH"),
    }
    alert_type, protocol = type_map[atk_type]

    alert = {
        "alert_id":         f"SOC-{uuid.uuid4().hex[:8].upper()}",
        "alert_type":       alert_type,
        "indicator_type":   "ip",
        "indicator_value":  ip,
        "source_host":      ip,
        "destination_host": DESTINATION_HOST,
        "destination_ip":   DESTINATION_IP,
        "protocol":         protocol,
        "evidence":         evidence,
        "analyst_question": "Analyze this alert and provide full triage."
    }
    return atk_type, alert

# ------------------------------------------------
# AIRIA AI TRIAGE
# ------------------------------------------------
def send_to_airia(alert):
    headers = {
        "Content-Type": "application/json",
        "X-API-KEY":    AIRIA_API_KEY
    }
    response = requests.post(
        AIRIA_API_URL,
        headers=headers,
        json={"userInput": json.dumps(alert), "asyncOutput": False},
        timeout=120
    )
    response.raise_for_status()
    return response.json()

def parse_triage(airia_response):
    output_text = ""
    if isinstance(airia_response, dict):
        output_text = (
            airia_response.get("output") or
            airia_response.get("result") or
            json.dumps(airia_response)
        )
    if isinstance(output_text, str):
        try:
            return json.loads(output_text)
        except Exception:
            return {"raw": output_text}
    return {}

# ------------------------------------------------
# MAIN CAPTURE PIPELINE
# ------------------------------------------------
def run_pipeline():
    global capture_status
    pcap_file = "/tmp/universal_capture.pcap"

    try:
        capture_status.update({
            "running":        True,
            "message":        "Capturing all traffic...",
            "attack_type":    "",
            "live_packets":   0,
            "live_breakdown": {}
        })

        if os.path.exists(pcap_file):
            os.remove(pcap_file)

        # start live counter in background
        stop_event = threading.Event()
        counter_thread = threading.Thread(
            target=live_counter, args=(pcap_file, stop_event), daemon=True
        )

        # start tshark capture
        capture_proc = subprocess.Popen([
            "tshark", "-i", INTERFACE,
            "-f", f"(icmp or tcp) and dst host {DESTINATION_IP}",
            "-a", f"duration:{CAPTURE_DURATION}",
            "-w", pcap_file
        ])

        counter_thread.start()
        capture_proc.wait()
        stop_event.set()

        if not os.path.exists(pcap_file):
            raise RuntimeError("Capture failed — no pcap file created.")

        capture_status["message"] = "Analyzing traffic — detecting attack type..."

        atk_type, alert = detect_attack_type(pcap_file)

        if alert:
            capture_status["message"] = f"Detected: {alert['alert_type']} — sending to AI agent..."
            capture_status["attack_type"] = atk_type

            airia_response = send_to_airia(alert)
            triage = parse_triage(airia_response)

            log_entry = {
                "timestamp":   datetime.now().isoformat(),
                "attack_type": atk_type,
                "alert":       alert,
                "triage":      triage,
                "raw_airia":   airia_response
            }
            append_to_log(log_entry)
            capture_status.update({
                "running":     False,
                "message":     f"Done — {alert['alert_id']} triaged as {alert['alert_type']}.",
                "attack_type": atk_type
            })
        else:
            capture_status.update({
                "running":     False,
                "message":     "Capture complete — no suspicious activity detected.",
                "attack_type": ""
            })

    except Exception as e:
        capture_status.update({
            "running":     False,
            "message":     f"Error: {str(e)}",
            "attack_type": ""
        })

# ------------------------------------------------
# FLASK ROUTES
# ------------------------------------------------
@app.route("/")
def index():
    return send_from_directory("templates", "dashboard.html")

@app.route("/api/alerts")
def get_alerts():
    return jsonify(load_log())

@app.route("/api/status")
def get_status():
    return jsonify(capture_status)

@app.route("/api/trigger", methods=["POST"])
def trigger_capture():
    if capture_status["running"]:
        return jsonify({"error": "Capture already running"}), 400
    thread = threading.Thread(target=run_pipeline, daemon=True)
    thread.start()
    return jsonify({"message": "Capture started"})

@app.route("/api/clear", methods=["POST"])
def clear_log():
    save_log([])
    return jsonify({"message": "Log cleared"})

@app.route("/api/export")
def export_json():
    data = load_log()
    return Response(
        json.dumps(data, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=soc_alerts_export.json"}
    )

@app.route("/api/stats")
def get_stats():
    entries  = load_log()
    by_type  = Counter(e.get("attack_type", "unknown") for e in entries)
    by_level = Counter()
    timeline = {}
    for e in entries:
        lvl = (e.get("triage") or {}).get("risk_level", "Unknown")
        by_level[lvl] += 1
        day = e.get("timestamp", "")[:10]
        if day:
            timeline.setdefault(day, 0)
            timeline[day] += 1
    return jsonify({
        "total":          len(entries),
        "by_attack_type": dict(by_type),
        "by_risk_level":  dict(by_level),
        "timeline":       timeline
    })

if __name__ == "__main__":
    try:
        from flask_cors import CORS
        CORS(app)
    except ImportError:
        pass
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
