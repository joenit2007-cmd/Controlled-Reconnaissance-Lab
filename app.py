"""
Controlled Reconnaissance Lab - Main Flask Application.
Combines Linux fundamentals, passive/active reconnaissance, tool integration,
security findings management, and professional PDF assessment reporting.
"""
import os
import time
from datetime import datetime
from pathlib import Path
from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    send_from_directory,
    abort
)
from werkzeug.utils import secure_filename

from core.config import (
    SECRET_KEY,
    MAX_CONTENT_LENGTH,
    ALLOWED_EXTENSIONS,
    UPLOADS_DIR,
    REPORTS_DIR,
    SAMPLES_DIR,
    NMAP_PATH,
    TSHARK_PATH
)
from core.db import (
    init_db,
    save_scan,
    get_all_scans,
    get_scan_by_id,
    delete_scan_by_id,
    save_finding,
    get_all_findings,
    update_finding,
    delete_finding,
    save_report_meta,
    get_all_reports,
    get_linux_progress,
    update_linux_progress,
    get_dashboard_metrics
)
from core.target_validator import validate_target
from core.nmap_scanner import execute_scan, SCAN_PROFILES
from core.dns_recon import execute_dns_recon
from core.net_enum import get_local_interfaces, sweep_subnet, grab_service_banner
from core.pcap_analyzer import (
    PcapAnalyzer,
    generate_sample_pcap,
    WIRESHARK_FILTERS
)
from core.web_security import (
    BURP_GUIDE,
    ZAP_GUIDE,
    probe_proxy_status,
    analyze_web_security_headers
)
from core.linux_fundamentals import (
    LINUX_MODULES,
    calculate_permissions,
    simulate_linux_command,
    QUIZ_QUESTIONS,
    evaluate_quiz
)
from core.pdf_reporter import generate_security_report

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

# Initialize database and ensure sample PCAP exists
init_db()
sample_pcap_path = SAMPLES_DIR / "recon_lab_sample.pcap"
if not sample_pcap_path.exists():
    try:
        generate_sample_pcap(str(sample_pcap_path))
    except Exception as e:
        print(f"Sample PCAP generation warning: {e}")

# Helper: Allowed upload extensions
def is_allowed_file(filename: str) -> bool:
    return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS

# --- Frontend Route ---
@app.route("/")
def index():
    """Render main cybersecurity dashboard."""
    return render_template("index.html")

# --- Overview & Metrics API ---
@app.route("/api/overview", methods=["GET"])
def api_overview():
    """Return dashboard metrics, tool availability statuses, and recent activity."""
    metrics = get_dashboard_metrics()
    
    # Check tool availability
    nmap_status = {
        "installed": bool(NMAP_PATH),
        "path": NMAP_PATH or "Not Detected (Using Built-in Python Socket Scanner)",
        "version": "Nmap 7.992" if NMAP_PATH else "Pure-Python Socket Engine"
    }
    tshark_status = {
        "installed": bool(TSHARK_PATH),
        "path": TSHARK_PATH or "Not Detected (Using Native Python PCAP Decoder)",
        "version": "Native Decoder Engine"
    }

    burp_probe = probe_proxy_status("127.0.0.1", 8080)
    zap_probe = probe_proxy_status("127.0.0.1", 8090)

    recent_scans = get_all_scans(limit=5)
    recent_findings = get_all_findings()[:5]

    return jsonify({
        "success": True,
        "metrics": metrics,
        "tools": {
            "nmap": nmap_status,
            "tshark": tshark_status,
            "burp": burp_probe,
            "zap": zap_probe
        },
        "recent_scans": recent_scans,
        "recent_findings": recent_findings
    })

# --- Nmap Scanning API ---
@app.route("/api/scan/nmap", methods=["POST"])
def api_scan_nmap():
    """Execute Nmap scan on target."""
    data = request.get_json() or {}
    target = data.get("target", "").strip()
    profile = data.get("profile", "quick")
    custom_ports = data.get("custom_ports", "").strip()

    start_iso = datetime.now().isoformat()
    scan_result = execute_scan(target, profile, custom_ports)
    end_iso = datetime.now().isoformat()

    status = "Completed" if scan_result.get("success") else "Failed"
    duration = scan_result.get("duration", 0.0)
    raw_output = scan_result.get("raw_output", scan_result.get("error", ""))
    open_count = scan_result.get("open_count", 0)

    summary = f"Scanned {target} ({profile} profile). Found {open_count} open port(s)."

    scan_id = save_scan(
        scan_type="nmap",
        target=target,
        profile=profile,
        status=status,
        start_time=start_iso,
        end_time=end_iso,
        duration=duration,
        summary=summary,
        raw_output=raw_output,
        parsed_json=scan_result
    )

    # Auto-add detected security findings
    findings = scan_result.get("findings", [])
    for f in findings:
        save_finding(
            title=f["title"],
            severity=f["severity"],
            category=f["category"],
            target=target,
            description=f["description"],
            evidence=f["evidence"],
            remediation=f["remediation"],
            status="Open",
            scan_id=scan_id
        )

    scan_result["scan_id"] = scan_id
    return jsonify(scan_result)

@app.route("/api/scan/profiles", methods=["GET"])
def api_scan_profiles():
    """Return available scanning profiles."""
    return jsonify({"success": True, "profiles": SCAN_PROFILES})

# --- DNS Reconnaissance API ---
@app.route("/api/scan/dns", methods=["POST"])
def api_scan_dns():
    """Execute DNS reconnaissance on domain."""
    data = request.get_json() or {}
    domain = data.get("domain", "").strip()

    start_iso = datetime.now().isoformat()
    dns_res = execute_dns_recon(domain)
    end_iso = datetime.now().isoformat()

    status = "Completed" if dns_res.get("success") else "Failed"
    duration = dns_res.get("duration", 0.0)
    raw_output = dns_res.get("raw_output", dns_res.get("error", ""))

    summary = f"DNS Recon on {domain}. Discovered {dns_res.get('subdomain_count', 0)} subdomains."

    scan_id = save_scan(
        scan_type="dns",
        target=domain,
        profile="dns_recon",
        status=status,
        start_time=start_iso,
        end_time=end_iso,
        duration=duration,
        summary=summary,
        raw_output=raw_output,
        parsed_json=dns_res
    )

    for f in dns_res.get("findings", []):
        save_finding(
            title=f["title"],
            severity=f["severity"],
            category=f["category"],
            target=domain,
            description=f["description"],
            evidence=f["evidence"],
            remediation=f["remediation"],
            status="Open",
            scan_id=scan_id
        )

    dns_res["scan_id"] = scan_id
    return jsonify(dns_res)

# --- Network Enumeration API ---
@app.route("/api/scan/net-enum", methods=["POST"])
def api_net_enum():
    """Handle network interface queries, subnet sweeps, and banner grabs."""
    data = request.get_json() or {}
    action = data.get("action", "interfaces")

    if action == "interfaces":
        interfaces = get_local_interfaces()
        return jsonify({"success": True, "interfaces": interfaces})

    elif action == "sweep":
        cidr = data.get("cidr", "127.0.0.1/32")
        sweep_res = sweep_subnet(cidr)
        if sweep_res.get("success"):
            now_iso = datetime.now().isoformat()
            save_scan(
                scan_type="net_enum",
                target=cidr,
                profile="subnet_sweep",
                status="Completed",
                start_time=now_iso,
                end_time=now_iso,
                duration=sweep_res.get("duration", 0.0),
                summary=f"Subnet sweep on {cidr}: {sweep_res.get('live_count')} live hosts.",
                raw_output=sweep_res.get("raw_output", ""),
                parsed_json=sweep_res
            )
        return jsonify(sweep_res)

    elif action == "banner":
        target = data.get("target", "127.0.0.1")
        port = int(data.get("port", 80))
        banner_res = grab_service_banner(target, port)
        return jsonify(banner_res)

    return jsonify({"success": False, "error": f"Unknown action '{action}'"})

# --- PCAP Packet Analysis API ---
@app.route("/api/pcap/upload", methods=["POST"])
def api_pcap_upload():
    """Receive and analyze an uploaded PCAP/PCAPNG file."""
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No file part in request."}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"success": False, "error": "No file selected."}), 400

    if not is_allowed_file(file.filename):
        return jsonify({"success": False, "error": f"Invalid file extension. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"}), 400

    filename = secure_filename(file.filename)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    stored_name = f"{timestamp}_{filename}"
    save_path = UPLOADS_DIR / stored_name
    file.save(str(save_path))

    start_iso = datetime.now().isoformat()
    try:
        analyzer = PcapAnalyzer(str(save_path))
        analysis = analyzer.parse()
    except Exception as e:
        return jsonify({"success": False, "error": f"PCAP parsing error: {str(e)}"}), 400

    end_iso = datetime.now().isoformat()

    scan_id = save_scan(
        scan_type="pcap",
        target=filename,
        profile="packet_analysis",
        status="Completed",
        start_time=start_iso,
        end_time=end_iso,
        duration=0.5,
        summary=f"PCAP {filename}: {analysis['total_packets']} packets, {len(analysis['security_alerts'])} alerts.",
        raw_output=f"Processed capture file {filename}\nPackets: {analysis['total_packets']}\nBytes: {analysis['total_bytes']}",
        parsed_json=analysis
    )

    # Save security alerts as findings
    for alert in analysis.get("security_alerts", []):
        save_finding(
            title=f"[PCAP Alert] {alert['title']}",
            severity=alert["severity"],
            category="Traffic Analysis",
            target=filename,
            description=alert["details"],
            evidence=f"Observed in packet capture '{filename}'",
            remediation=alert.get("recommendation", "Inspect traffic flows."),
            status="Open",
            scan_id=scan_id
        )

    analysis["scan_id"] = scan_id
    return jsonify({"success": True, "analysis": analysis})

@app.route("/api/pcap/sample", methods=["GET"])
def api_pcap_sample():
    """Analyze the built-in sample PCAP capture file."""
    if not sample_pcap_path.exists() or sample_pcap_path.stat().st_size < 24:
        try:
            generate_sample_pcap(str(sample_pcap_path))
        except Exception as e:
            return jsonify({"success": False, "error": f"Failed to generate sample PCAP: {str(e)}"}), 500

    try:
        analyzer = PcapAnalyzer(str(sample_pcap_path))
        analysis = analyzer.parse()
        return jsonify({"success": True, "analysis": analysis})
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to parse sample capture: {str(e)}"}), 500

@app.route("/api/pcap/filters", methods=["GET"])
def api_pcap_filters():
    """Return Wireshark display filter cheatsheet."""
    return jsonify({"success": True, "filters": WIRESHARK_FILTERS})

# --- Web Security & Proxy API ---
@app.route("/api/web-security/guides", methods=["GET"])
def api_web_security_guides():
    """Return Burp Suite and OWASP ZAP walkthrough guides."""
    return jsonify({"success": True, "burp": BURP_GUIDE, "zap": ZAP_GUIDE})

@app.route("/api/web-security/status", methods=["GET"])
def api_web_security_status():
    """Probe status of Burp and ZAP proxy listeners."""
    burp = probe_proxy_status("127.0.0.1", 8080)
    zap = probe_proxy_status("127.0.0.1", 8090)
    return jsonify({"success": True, "burp": burp, "zap": zap})

@app.route("/api/web-security/headers", methods=["POST"])
def api_web_security_headers():
    """Analyze HTTP response security headers on authorized lab target."""
    data = request.get_json() or {}
    url = data.get("url", "http://127.0.0.1:5000")
    res = analyze_web_security_headers(url)

    if res.get("success"):
        for f in res.get("findings", []):
            save_finding(
                title=f["title"],
                severity=f["severity"],
                category=f["category"],
                target=url,
                description=f["description"],
                evidence=f["evidence"],
                remediation=f["remediation"],
                status="Open"
            )

    return jsonify(res)

# --- Linux Fundamentals API ---
@app.route("/api/linux/modules", methods=["GET"])
def api_linux_modules():
    """Return Linux Fundamentals educational modules and user progress."""
    progress = get_linux_progress()
    return jsonify({
        "success": True,
        "modules": LINUX_MODULES,
        "progress": progress
    })

@app.route("/api/linux/calc-perms", methods=["POST"])
def api_linux_calc_perms():
    """Calculate Linux permissions and evaluate risk."""
    data = request.get_json() or {}
    res = calculate_permissions(
        user_r=data.get("user_r", False),
        user_w=data.get("user_w", False),
        user_x=data.get("user_x", False),
        group_r=data.get("group_r", False),
        group_w=data.get("group_w", False),
        group_x=data.get("group_x", False),
        other_r=data.get("other_r", False),
        other_w=data.get("other_w", False),
        other_x=data.get("other_x", False),
        suid=data.get("suid", False),
        sgid=data.get("sgid", False),
        sticky=data.get("sticky", False)
    )
    return jsonify({"success": True, "result": res})

@app.route("/api/linux/cmd", methods=["POST"])
def api_linux_cmd():
    """Execute simulated Linux command with security guidance."""
    data = request.get_json() or {}
    cmd = data.get("command", "")
    res = simulate_linux_command(cmd)
    return jsonify({"success": True, "result": res})

@app.route("/api/linux/quiz", methods=["GET"])
def api_linux_quiz_get():
    """Return quiz questions without leaking answers."""
    sanitized = []
    for q in QUIZ_QUESTIONS:
        sanitized.append({
            "id": q["id"],
            "question": q["question"],
            "options": q["options"]
        })
    return jsonify({"success": True, "questions": sanitized})

@app.route("/api/linux/quiz/submit", methods=["POST"])
def api_linux_quiz_submit():
    """Score quiz submission and save progress."""
    data = request.get_json() or {}
    answers = data.get("answers", {})
    eval_res = evaluate_quiz(answers)

    # Award progress
    update_linux_progress("permissions", score_delta=eval_res["score"] * 10, completed=eval_res["passed"])

    return jsonify({"success": True, "evaluation": eval_res})

# --- Findings Management API ---
@app.route("/api/findings", methods=["GET"])
def api_findings_get():
    """List findings with optional severity and status filters."""
    severity = request.args.get("severity")
    status = request.args.get("status")
    findings = get_all_findings(severity_filter=severity, status_filter=status)
    return jsonify({"success": True, "findings": findings, "count": len(findings)})

@app.route("/api/findings", methods=["POST"])
def api_findings_create():
    """Manually record a new security finding."""
    data = request.get_json() or {}
    title = data.get("title", "").strip()
    severity = data.get("severity", "Medium").strip()
    category = data.get("category", "General").strip()
    target = data.get("target", "127.0.0.1").strip()
    description = data.get("description", "").strip()
    evidence = data.get("evidence", "").strip()
    remediation = data.get("remediation", "").strip()
    status = data.get("status", "Open").strip()

    if not title:
        return jsonify({"success": False, "error": "Finding title is required."}), 400

    finding_id = save_finding(
        title=title,
        severity=severity,
        category=category,
        target=target,
        description=description,
        evidence=evidence,
        remediation=remediation,
        status=status
    )

    return jsonify({"success": True, "finding_id": finding_id, "message": "Finding saved successfully."})

@app.route("/api/findings/<int:finding_id>", methods=["PUT"])
def api_findings_update(finding_id: int):
    """Update finding fields or status."""
    data = request.get_json() or {}
    success = update_finding(finding_id, data)
    if not success:
        return jsonify({"success": False, "error": "Finding not found or no valid fields to update."}), 404
    return jsonify({"success": True, "message": "Finding updated."})

@app.route("/api/findings/<int:finding_id>", methods=["DELETE"])
def api_findings_delete(finding_id: int):
    """Delete finding by ID."""
    success = delete_finding(finding_id)
    if not success:
        return jsonify({"success": False, "error": "Finding not found."}), 404
    return jsonify({"success": True, "message": "Finding deleted."})

# --- Scan History API ---
@app.route("/api/scans", methods=["GET"])
def api_scans_get():
    """List recent scans."""
    scans = get_all_scans(limit=50)
    return jsonify({"success": True, "scans": scans})

@app.route("/api/scans/<int:scan_id>", methods=["GET"])
def api_scans_detail(scan_id: int):
    """Retrieve full scan details."""
    scan = get_scan_by_id(scan_id)
    if not scan:
        return jsonify({"success": False, "error": "Scan not found."}), 404
    return jsonify({"success": True, "scan": scan})

@app.route("/api/scans/<int:scan_id>", methods=["DELETE"])
def api_scans_delete(scan_id: int):
    """Delete scan record."""
    success = delete_scan_by_id(scan_id)
    if not success:
        return jsonify({"success": False, "error": "Scan not found."}), 404
    return jsonify({"success": True, "message": "Scan record deleted."})

# --- PDF Assessment Report API ---
@app.route("/api/reports/generate", methods=["POST"])
def api_reports_generate():
    """Generate professional PDF assessment report."""
    data = request.get_json() or {}
    target = data.get("target", "127.0.0.1").strip()
    title = data.get("title", f"Security Assessment: {target}").strip()

    # Fetch findings for target or all findings
    findings = get_all_findings()
    target_findings = [f for f in findings if target in f.get("target", "") or target == "all"]
    if not target_findings:
        target_findings = findings  # fallback to all findings if target not specific

    # Retrieve latest Nmap scan ports for this target
    scans = get_all_scans()
    nmap_scan = next((s for s in scans if s["scan_type"] == "nmap" and s["target"] == target), None)
    ports_summary = {"ports": nmap_scan.get("parsed_json", {}).get("ports", [])} if nmap_scan else {"ports": []}

    # Retrieve sample or latest PCAP summary
    pcap_scan = next((s for s in scans if s["scan_type"] == "pcap"), None)
    pcap_summary = pcap_scan.get("parsed_json", None) if pcap_scan else None

    try:
        pdf_filepath = generate_security_report(
            target=target,
            findings=target_findings,
            scans_summary=ports_summary,
            pcap_summary=pcap_summary
        )
        pdf_filename = Path(pdf_filepath).name
        report_id = save_report_meta(title, pdf_filename, target, len(target_findings))

        return jsonify({
            "success": True,
            "report_id": report_id,
            "filename": pdf_filename,
            "download_url": f"/api/reports/download/{pdf_filename}",
            "findings_count": len(target_findings)
        })
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to generate PDF report: {str(e)}"}), 500

@app.route("/api/reports", methods=["GET"])
def api_reports_list():
    """List generated PDF reports."""
    reports = get_all_reports()
    return jsonify({"success": True, "reports": reports})

@app.route("/api/reports/download/<filename>", methods=["GET"])
def api_reports_download(filename: str):
    """Download generated PDF report."""
    safe_name = secure_filename(filename)
    file_path = REPORTS_DIR / safe_name
    if not file_path.exists():
        abort(404, description="Report file not found.")
    return send_from_directory(str(REPORTS_DIR), safe_name, as_attachment=True)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] Starting Controlled Reconnaissance Lab on http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=False)
