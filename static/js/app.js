/**
 * Controlled Reconnaissance Lab - Frontend Application Logic
 * Cyber dashboard interactivity, AJAX handlers, tool execution, and reporting.
 */

document.addEventListener("DOMContentLoaded", () => {
    initNavigation();
    initOverview();
    initLinuxFundamentals();
    initDnsRecon();
    initNmapScanner();
    initNetEnum();
    initPcapAnalysis();
    initWebSecurity();
    initFindings();
    initScanHistory();
    initReports();
});

// --- Toast / Notification Helper ---
function showToast(message, type = "info") {
    let container = document.getElementById("toast-container");
    if (!container) {
        container = document.createElement("div");
        container.id = "toast-container";
        container.style.cssText = "position:fixed;bottom:20px;right:20px;z-index:9999;display:flex;flex-direction:column;gap:10px;";
        document.body.appendChild(container);
    }
    const toast = document.createElement("div");
    const colors = {
        info: "background:#0284c7;color:#fff",
        success: "background:#059669;color:#fff",
        error: "background:#dc2626;color:#fff",
        warning: "background:#d97706;color:#fff"
    };
    toast.style.cssText = `padding:10px 16px;border-radius:6px;font-size:12px;font-weight:600;box-shadow:0 4px 12px rgba(0,0,0,0.4);${colors[type] || colors.info};transition:all 0.3s ease;opacity:0;transform:translateY(10px);`;
    toast.innerText = message;
    container.appendChild(toast);

    requestAnimationFrame(() => {
        toast.style.opacity = "1";
        toast.style.transform = "translateY(0)";
    });

    setTimeout(() => {
        toast.style.opacity = "0";
        setTimeout(() => toast.remove(), 300);
    }, 3500);
}

// --- Navigation Controller ---
function initNavigation() {
    const navItems = document.querySelectorAll(".nav-item");
    const tabPanels = document.querySelectorAll(".tab-panel");
    const titleElem = document.getElementById("current-view-title");

    navItems.forEach(item => {
        item.addEventListener("click", (e) => {
            e.preventDefault();
            const targetTab = item.getAttribute("data-tab");

            navItems.forEach(n => n.classList.remove("active"));
            tabPanels.forEach(p => p.classList.remove("active"));

            item.classList.add("active");
            const activePanel = document.getElementById(`panel-${targetTab}`);
            if (activePanel) {
                activePanel.classList.add("active");
            }

            if (titleElem) {
                titleElem.innerHTML = `<i class="${item.querySelector('i').className}"></i> ${item.querySelector('span').innerText}`;
            }

            // Refresh tab-specific data on visit
            if (targetTab === "overview") loadOverviewData();
            if (targetTab === "findings") loadFindingsData();
            if (targetTab === "scans") loadScansData();
            if (targetTab === "reports") loadReportsData();
        });
    });
}

// --- Overview Dashboard ---
function initOverview() {
    loadOverviewData();
}

async function loadOverviewData() {
    try {
        const res = await fetch("/api/overview");
        const data = await res.json();
        if (!data.success) return;

        // Metrics
        document.getElementById("stat-total-scans").innerText = data.metrics.total_scans;
        document.getElementById("stat-total-findings").innerText = data.metrics.total_findings;
        
        const critCount = data.metrics.severity_counts.Critical || 0;
        const highCount = data.metrics.severity_counts.High || 0;
        document.getElementById("stat-crit-high").innerText = `${critCount} / ${highCount}`;

        // Tool Badges
        const nmapBadge = document.getElementById("overview-nmap-badge");
        if (nmapBadge) {
            nmapBadge.className = data.tools.nmap.installed ? "badge badge-low" : "badge badge-medium";
            nmapBadge.innerText = data.tools.nmap.installed ? "Active: " + data.tools.nmap.version : "Fallback: Python Socket Engine";
        }

        const tsharkBadge = document.getElementById("overview-tshark-badge");
        if (tsharkBadge) {
            tsharkBadge.className = "badge badge-low";
            tsharkBadge.innerText = "Native Python Decoder Active";
        }

        const burpBadge = document.getElementById("overview-burp-badge");
        if (burpBadge) {
            burpBadge.className = data.tools.burp.is_active ? "badge badge-low" : "badge badge-medium";
            burpBadge.innerText = data.tools.burp.is_active ? "Port 8080 Active" : "Port 8080 Offline";
        }

        const zapBadge = document.getElementById("overview-zap-badge");
        if (zapBadge) {
            zapBadge.className = data.tools.zap.is_active ? "badge badge-low" : "badge badge-medium";
            zapBadge.innerText = data.tools.zap.is_active ? "Port 8090 Active" : "Port 8090 Offline";
        }

        // Recent Scans Table
        const recentScansTbody = document.getElementById("overview-recent-scans");
        if (recentScansTbody) {
            if (!data.recent_scans || data.recent_scans.length === 0) {
                recentScansTbody.innerHTML = `<tr><td colspan="5" class="text-muted" style="text-align:center;">No scan records found. Run your first reconnaissance scan above.</td></tr>`;
            } else {
                recentScansTbody.innerHTML = data.recent_scans.map(s => `
                    <tr>
                        <td><span class="badge badge-info">${s.scan_type.toUpperCase()}</span></td>
                        <td><code>${s.target}</code></td>
                        <td><span class="badge ${s.status === 'Completed' ? 'badge-low' : 'badge-critical'}">${s.status}</span></td>
                        <td>${s.duration}s</td>
                        <td>${s.start_time.split('T')[0]}</td>
                    </tr>
                `).join("");
            }
        }

        // Recent Findings Table
        const recentFindingsTbody = document.getElementById("overview-recent-findings");
        if (recentFindingsTbody) {
            if (!data.recent_findings || data.recent_findings.length === 0) {
                recentFindingsTbody.innerHTML = `<tr><td colspan="4" class="text-muted" style="text-align:center;">No vulnerabilities recorded.</td></tr>`;
            } else {
                recentFindingsTbody.innerHTML = data.recent_findings.map(f => `
                    <tr>
                        <td><span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span></td>
                        <td><b>${f.title}</b></td>
                        <td><code>${f.target}</code></td>
                        <td><span class="status-${f.status.toLowerCase().replace(' ', '')}">● ${f.status}</span></td>
                    </tr>
                `).join("");
            }
        }

    } catch (err) {
        console.error("Failed to load overview data", err);
    }
}

// --- Linux Fundamentals ---
function initLinuxFundamentals() {
    // Subtab switching
    const subtabs = document.querySelectorAll("#panel-linux .subtab-btn");
    subtabs.forEach(btn => {
        btn.addEventListener("click", () => {
            subtabs.forEach(b => b.classList.remove("active"));
            document.querySelectorAll("#panel-linux .linux-subview").forEach(v => v.style.display = "none");
            btn.classList.add("active");
            const viewId = btn.getAttribute("data-subview");
            const targetView = document.getElementById(viewId);
            if (targetView) targetView.style.display = "block";
        });
    });

    // Permission Calculator Checkboxes
    const permInputs = document.querySelectorAll(".perm-calc-input");
    permInputs.forEach(input => {
        input.addEventListener("change", updatePermissionCalculator);
    });
    updatePermissionCalculator();

    // Command Sandbox
    const cmdInput = document.getElementById("linux-cmd-input");
    const cmdSubmit = document.getElementById("linux-cmd-submit");
    if (cmdSubmit && cmdInput) {
        cmdSubmit.addEventListener("click", () => runSimulatedCommand(cmdInput.value));
        cmdInput.addEventListener("keypress", (e) => {
            if (e.key === "Enter") runSimulatedCommand(cmdInput.value);
        });
    }

    // Quick Command Pills
    document.querySelectorAll(".cmd-pill").forEach(pill => {
        pill.addEventListener("click", () => {
            const cmd = pill.getAttribute("data-cmd");
            if (cmdInput) cmdInput.value = cmd;
            runSimulatedCommand(cmd);
        });
    });

    // Load Quiz Questions
    loadLinuxQuiz();
}

async function updatePermissionCalculator() {
    const payload = {
        user_r: document.getElementById("p_ur")?.checked || false,
        user_w: document.getElementById("p_uw")?.checked || false,
        user_x: document.getElementById("p_ux")?.checked || false,
        group_r: document.getElementById("p_gr")?.checked || false,
        group_w: document.getElementById("p_gw")?.checked || false,
        group_x: document.getElementById("p_gx")?.checked || false,
        other_r: document.getElementById("p_or")?.checked || false,
        other_w: document.getElementById("p_ow")?.checked || false,
        other_x: document.getElementById("p_ox")?.checked || false,
        suid: document.getElementById("p_suid")?.checked || false,
        sgid: document.getElementById("p_sgid")?.checked || false,
        sticky: document.getElementById("p_sticky")?.checked || false
    };

    try {
        const res = await fetch("/api/linux/calc-perms", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (data.success) {
            document.getElementById("calc-octal").innerText = data.result.octal;
            document.getElementById("calc-symbolic").innerText = data.result.symbolic;
            document.getElementById("calc-cmd").innerText = data.result.chmod_cmd;
            
            const riskBadge = document.getElementById("calc-risk-level");
            riskBadge.innerText = data.result.risk_level;
            riskBadge.className = `badge badge-${data.result.risk_level.toLowerCase().replace(' ', '')}`;

            const assessDiv = document.getElementById("calc-assessments");
            assessDiv.innerHTML = data.result.assessment.map(a => `<p style="margin-bottom:4px;font-size:12px;">• ${a}</p>`).join("");
        }
    } catch (e) {
        console.error("Perm calc error", e);
    }
}

async function runSimulatedCommand(cmd) {
    if (!cmd.trim()) return;
    const termBody = document.getElementById("linux-term-output");
    termBody.innerHTML += `\n<span style="color:#38bdf8;">$ ${cmd}</span>\n[Executing in Linux sandbox...]\n`;
    termBody.scrollTop = termBody.scrollHeight;

    try {
        const res = await fetch("/api/linux/cmd", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ command: cmd })
        });
        const data = await res.json();
        if (data.success) {
            termBody.innerHTML += `<span style="color:#a7f3d0;">${data.result.output}</span>\n`;
        } else {
            termBody.innerHTML += `<span style="color:#f87171;">Command execution failed.</span>\n`;
        }
        termBody.scrollTop = termBody.scrollHeight;
    } catch (err) {
        termBody.innerHTML += `<span style="color:#f87171;">Error connecting to simulator.</span>\n`;
    }
}

async function loadLinuxQuiz() {
    const quizContainer = document.getElementById("linux-quiz-container");
    if (!quizContainer) return;

    try {
        const res = await fetch("/api/linux/quiz");
        const data = await res.json();
        if (!data.success) return;

        quizContainer.innerHTML = data.questions.map((q, idx) => `
            <div class="card" style="margin-bottom:14px;background:#0d1527;">
                <p style="font-weight:600;margin-bottom:10px;color:#fff;">${idx + 1}. ${q.question}</p>
                <div style="display:flex;flex-direction:column;gap:8px;">
                    ${q.options.map((opt, oIdx) => `
                        <label style="display:flex;align-items:center;gap:8px;font-size:12.5px;color:#94a3b8;cursor:pointer;">
                            <input type="radio" name="quiz_q_${q.id}" value="${oIdx}">
                            <span>${opt}</span>
                        </label>
                    `).join("")}
                </div>
            </div>
        `).join("");

        const submitBtn = document.getElementById("linux-quiz-submit");
        if (submitBtn) {
            submitBtn.onclick = submitLinuxQuiz;
        }
    } catch (e) {
        console.error("Failed to load quiz", e);
    }
}

async function submitLinuxQuiz() {
    const answers = {};
    for (let i = 1; i <= 5; i++) {
        const selected = document.querySelector(`input[name="quiz_q_${i}"]:checked`);
        if (selected) {
            answers[i.toString()] = parseInt(selected.value);
        }
    }

    try {
        const res = await fetch("/api/linux/quiz/submit", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ answers })
        });
        const data = await res.json();
        if (data.success) {
            const resultBox = document.getElementById("linux-quiz-result");
            resultBox.style.display = "block";
            resultBox.innerHTML = `
                <div class="alert-box ${data.evaluation.passed ? 'alert-success' : 'alert-warning'}">
                    <div>
                        <h4 style="font-weight:700;">Score: ${data.evaluation.score} / ${data.evaluation.total} (${data.evaluation.percentage}%)</h4>
                        <p>${data.evaluation.feedback}</p>
                    </div>
                </div>
                <div style="margin-top:12px;">
                    ${data.evaluation.results.map(r => `
                        <p style="font-size:12px;margin-bottom:6px;">
                            ${r.is_correct ? '<span style="color:#10b981;">✓ Correct</span>' : '<span style="color:#ef4444;">✗ Incorrect</span>'}: 
                            <b>${r.question}</b><br/>
                            <span style="color:#94a3b8;">Explanation: ${r.explanation}</span>
                        </p>
                    `).join("")}
                </div>
            `;
            showToast(`Quiz completed! Score: ${data.evaluation.percentage}%`, data.evaluation.passed ? "success" : "info");
        }
    } catch (e) {
        showToast("Error submitting quiz", "error");
    }
}

// --- DNS Reconnaissance ---
function initDnsRecon() {
    const runBtn = document.getElementById("btn-run-dns");
    const domainInput = document.getElementById("dns-domain-input");
    if (!runBtn || !domainInput) return;

    runBtn.addEventListener("click", async () => {
        const domain = domainInput.value.trim();
        if (!domain) {
            showToast("Please enter an authorized lab domain.", "warning");
            return;
        }

        runBtn.disabled = true;
        runBtn.innerHTML = `<i class="fa fa-spinner fa-spin"></i> Resolving...`;

        try {
            const res = await fetch("/api/scan/dns", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ domain })
            });
            const data = await res.json();

            if (!data.success) {
                showToast(data.error || "DNS query rejected.", "error");
                runBtn.disabled = false;
                runBtn.innerHTML = `<i class="fa fa-search"></i> Run DNS Recon`;
                return;
            }

            // Populate Records Table
            const recTbody = document.getElementById("dns-records-tbody");
            const recRows = [];
            for (let [rtype, vals] of Object.entries(data.records)) {
                if (vals && vals.length > 0) {
                    recRows.push(`
                        <tr>
                            <td><span class="badge badge-info">${rtype}</span></td>
                            <td><code>${vals.join(", ")}</code></td>
                        </tr>
                    `);
                }
            }
            recTbody.innerHTML = recRows.length ? recRows.join("") : `<tr><td colspan="2" class="text-muted">No records found.</td></tr>`;

            // Populate Subdomains Table
            const subTbody = document.getElementById("dns-subdomains-tbody");
            if (data.subdomains && data.subdomains.length > 0) {
                subTbody.innerHTML = data.subdomains.map(s => `
                    <tr>
                        <td><b>${s.subdomain}</b></td>
                        <td><code>${s.ip}</code></td>
                        <td><span class="badge badge-low">${s.status}</span></td>
                    </tr>
                `).join("");
            } else {
                subTbody.innerHTML = `<tr><td colspan="3" class="text-muted">No active subdomains discovered.</td></tr>`;
            }

            // Raw Output
            document.getElementById("dns-raw-output").innerText = data.raw_output;

            // Security Findings
            const findDiv = document.getElementById("dns-findings-list");
            if (data.findings && data.findings.length > 0) {
                findDiv.innerHTML = data.findings.map(f => `
                    <div class="alert-box alert-warning">
                        <div>
                            <span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span> 
                            <b>${f.title}</b>
                            <p style="margin-top:4px;">${f.description}</p>
                            <p style="margin-top:4px;color:#a7f3d0;"><b>Fix:</b> ${f.remediation}</p>
                        </div>
                    </div>
                `).join("");
            } else {
                findDiv.innerHTML = `<p class="text-muted" style="font-size:12px;">No immediate DNS security anomalies detected.</p>`;
            }

            showToast(`DNS reconnaissance complete on ${domain}`, "success");
        } catch (e) {
            showToast("Failed to execute DNS recon.", "error");
        } finally {
            runBtn.disabled = false;
            runBtn.innerHTML = `<i class="fa fa-search"></i> Run DNS Recon`;
        }
    });
}

// --- Nmap Scanner ---
function initNmapScanner() {
    const scanBtn = document.getElementById("btn-run-nmap");
    const targetInput = document.getElementById("nmap-target-input");
    const profileSelect = document.getElementById("nmap-profile-select");
    const customPortsInput = document.getElementById("nmap-custom-ports");

    if (profileSelect && customPortsInput) {
        profileSelect.addEventListener("change", () => {
            customPortsInput.disabled = (profileSelect.value !== "custom");
        });
    }

    if (!scanBtn) return;

    scanBtn.addEventListener("click", async () => {
        const target = targetInput.value.trim();
        const profile = profileSelect.value;
        const custom_ports = customPortsInput.value.trim();

        if (!target) {
            showToast("Target address is required.", "warning");
            return;
        }

        scanBtn.disabled = true;
        scanBtn.innerHTML = `<i class="fa fa-spinner fa-spin"></i> Scanning (${profile})...`;

        try {
            const res = await fetch("/api/scan/nmap", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ target, profile, custom_ports })
            });
            const data = await res.json();

            if (!data.success) {
                showToast(data.error || "Nmap scan failed.", "error");
                scanBtn.disabled = false;
                scanBtn.innerHTML = `<i class="fa fa-play"></i> Start Scan`;
                return;
            }

            // Engine badge
            const engineBadge = document.getElementById("nmap-active-engine");
            if (engineBadge) {
                engineBadge.innerText = data.engine_version || "Nmap";
            }

            // Populate Ports Table
            const portsTbody = document.getElementById("nmap-ports-tbody");
            if (data.ports && data.ports.length > 0) {
                portsTbody.innerHTML = data.ports.map(p => `
                    <tr>
                        <td><b>${p.port}</b> / ${p.protocol}</td>
                        <td><span class="badge badge-low">${p.state}</span></td>
                        <td><b>${p.service}</b></td>
                        <td><code>${p.version || '-'}</code></td>
                    </tr>
                `).join("");
            } else {
                portsTbody.innerHTML = `<tr><td colspan="4" class="text-muted" style="text-align:center;">No open ports identified on target.</td></tr>`;
            }

            // Raw Output
            document.getElementById("nmap-raw-output").innerText = data.raw_output;

            // Findings list
            const nmapFindDiv = document.getElementById("nmap-findings-list");
            if (data.findings && data.findings.length > 0) {
                nmapFindDiv.innerHTML = data.findings.map(f => `
                    <div class="alert-box alert-warning">
                        <div>
                            <span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span> 
                            <b>${f.title}</b>
                            <p style="margin-top:4px;">${f.description}</p>
                            <p style="margin-top:4px;color:#a7f3d0;"><b>Remediation:</b> ${f.remediation}</p>
                        </div>
                    </div>
                `).join("");
            } else {
                nmapFindDiv.innerHTML = `<p class="text-muted" style="font-size:12px;">No direct high-risk exposures flagged on scanned ports.</p>`;
            }

            showToast(`Scan complete in ${data.duration}s! ${data.open_count} open ports found.`, "success");
        } catch (err) {
            showToast("Network scan execution error.", "error");
        } finally {
            scanBtn.disabled = false;
            scanBtn.innerHTML = `<i class="fa fa-play"></i> Start Scan`;
        }
    });
}

// --- Network Enumeration ---
function initNetEnum() {
    // Subtab switching
    const subtabs = document.querySelectorAll("#panel-net_enum .subtab-btn");
    subtabs.forEach(btn => {
        btn.addEventListener("click", () => {
            subtabs.forEach(b => b.classList.remove("active"));
            document.querySelectorAll("#panel-net_enum .net-subview").forEach(v => v.style.display = "none");
            btn.classList.add("active");
            const viewId = btn.getAttribute("data-subview");
            const targetView = document.getElementById(viewId);
            if (targetView) targetView.style.display = "block";
        });
    });

    // Refresh Interfaces
    const loadInterfaces = async () => {
        try {
            const res = await fetch("/api/scan/net-enum", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ action: "interfaces" })
            });
            const data = await res.json();
            if (data.success) {
                const ifaceGrid = document.getElementById("net-interfaces-grid");
                ifaceGrid.innerHTML = data.interfaces.map(i => `
                    <div class="card" style="background:#0d1527;">
                        <h4 style="font-size:13px;font-weight:700;color:#38bdf8;margin-bottom:8px;">${i.interface}</h4>
                        <p style="font-size:12px;color:#94a3b8;"><b>Host:</b> ${i.hostname}</p>
                        <p style="font-size:12px;color:#94a3b8;"><b>IPv4:</b> <code>${i.ipv4}</code></p>
                        <p style="font-size:12px;color:#94a3b8;"><b>MAC:</b> <code>${i.mac}</code></p>
                        <span class="badge badge-info" style="margin-top:6px;">${i.scope}</span>
                    </div>
                `).join("");
            }
        } catch (e) {
            console.error("Interface load failed", e);
        }
    };
    loadInterfaces();

    // Subnet Sweep
    const sweepBtn = document.getElementById("btn-run-sweep");
    if (sweepBtn) {
        sweepBtn.addEventListener("click", async () => {
            const cidr = document.getElementById("net-sweep-cidr").value.trim();
            sweepBtn.disabled = true;
            sweepBtn.innerHTML = `<i class="fa fa-spinner fa-spin"></i> Sweeping...`;

            try {
                const res = await fetch("/api/scan/net-enum", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ action: "sweep", cidr })
                });
                const data = await res.json();

                if (!data.success) {
                    showToast(data.error || "Sweep failed", "error");
                    sweepBtn.disabled = false;
                    sweepBtn.innerHTML = `<i class="fa fa-radar"></i> Sweep Subnet`;
                    return;
                }

                const tbody = document.getElementById("net-sweep-tbody");
                if (data.hosts && data.hosts.length > 0) {
                    tbody.innerHTML = data.hosts.map(h => `
                        <tr>
                            <td><code>${h.ip}</code></td>
                            <td><span class="badge badge-low">${h.status}</span></td>
                            <td>Port ${h.active_port}</td>
                            <td>${h.latency_ms} ms</td>
                        </tr>
                    `).join("");
                } else {
                    tbody.innerHTML = `<tr><td colspan="4" class="text-muted" style="text-align:center;">No responsive hosts located in subnet range.</td></tr>`;
                }

                showToast(`Sweep finished: ${data.live_count} live hosts found`, "success");
            } catch (e) {
                showToast("Sweep network error", "error");
            } finally {
                sweepBtn.disabled = false;
                sweepBtn.innerHTML = `<i class="fa fa-radar"></i> Sweep Subnet`;
            }
        });
    }

    // Banner Grabber
    const bannerBtn = document.getElementById("btn-grab-banner");
    if (bannerBtn) {
        bannerBtn.addEventListener("click", async () => {
            const target = document.getElementById("banner-target").value.trim();
            const port = document.getElementById("banner-port").value.trim();

            bannerBtn.disabled = true;
            bannerBtn.innerHTML = `<i class="fa fa-spinner fa-spin"></i> Probing...`;

            try {
                const res = await fetch("/api/scan/net-enum", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ action: "banner", target, port })
                });
                const data = await res.json();

                if (!data.success) {
                    showToast(data.error || "Banner probe failed", "error");
                } else {
                    document.getElementById("banner-output").innerText = 
                        `[Probe on ${data.target}:${data.port}]\nStatus: ${data.status}\nDuration: ${data.duration}s\n\n${data.banner}`;
                }
            } catch (e) {
                showToast("Banner probe network error", "error");
            } finally {
                bannerBtn.disabled = false;
                bannerBtn.innerHTML = `<i class="fa fa-terminal"></i> Grab Banner`;
            }
        });
    }
}

// --- PCAP Packet Analysis ---
function initPcapAnalysis() {
    // 1-Click Sample PCAP Test
    const sampleBtn = document.getElementById("btn-analyze-sample-pcap");
    if (sampleBtn) {
        sampleBtn.addEventListener("click", async () => {
            sampleBtn.disabled = true;
            sampleBtn.innerHTML = `<i class="fa fa-spinner fa-spin"></i> Decoding Sample PCAP...`;

            try {
                const res = await fetch("/api/pcap/sample");
                const data = await res.json();
                if (data.success && data.analysis) {
                    renderPcapResults(data.analysis);
                    showToast(`Sample PCAP analyzed: ${data.analysis.total_packets} packets loaded!`, "success");
                } else {
                    showToast(data.error || "Failed to load sample PCAP", "error");
                }
            } catch (e) {
                console.error("Error processing sample PCAP:", e);
                showToast("Error processing sample PCAP: " + (e.message || "Unknown error"), "error");
            } finally {
                sampleBtn.disabled = false;
                sampleBtn.innerHTML = `<i class="fa fa-play-circle"></i> Analyze Pre-loaded Lab Sample PCAP`;
            }
        });
    }

    // File Upload via Dropzone
    const fileInput = document.getElementById("pcap-file-input");
    const dropzone = document.getElementById("pcap-dropzone");
    if (dropzone && fileInput) {
        dropzone.addEventListener("click", () => fileInput.click());
        fileInput.addEventListener("change", () => {
            if (fileInput.files.length > 0) {
                uploadPcapFile(fileInput.files[0]);
            }
        });

        dropzone.addEventListener("dragover", (e) => {
            e.preventDefault();
            dropzone.classList.add("dragover");
        });
        dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));
        dropzone.addEventListener("drop", (e) => {
            e.preventDefault();
            dropzone.classList.remove("dragover");
            if (e.dataTransfer.files.length > 0) {
                uploadPcapFile(e.dataTransfer.files[0]);
            }
        });
    }

    // Load Wireshark Filters Cheatsheet
    loadWiresharkFilters();
}

async function uploadPcapFile(file) {
    const formData = new FormData();
    formData.append("file", file);

    showToast(`Uploading ${file.name}...`, "info");
    try {
        const res = await fetch("/api/pcap/upload", {
            method: "POST",
            body: formData
        });
        const data = await res.json();
        if (data.success && data.analysis) {
            renderPcapResults(data.analysis);
            showToast(`Parsed ${data.analysis.total_packets} packets from ${file.name}!`, "success");
        } else {
            showToast(data.error || "PCAP analysis failed.", "error");
        }
    } catch (e) {
        console.error("PCAP upload error:", e);
        showToast("Error uploading PCAP file: " + (e.message || "Unknown error"), "error");
    }
}

function renderPcapResults(analysis) {
    if (!analysis) return;

    // Cache packets for inspector modal
    window.currentPcapPackets = analysis.packets || [];

    // Safe helper to set element innerText without throwing if element is absent
    const setElemText = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.innerText = val;
    };

    // Protocol Counters
    setElemText("pcap-stat-total", analysis.total_packets || 0);
    setElemText("pcap-stat-tcp", (analysis.protocols && analysis.protocols.TCP) || 0);
    setElemText("pcap-stat-udp", (analysis.protocols && analysis.protocols.UDP) || 0);
    setElemText("pcap-stat-dns", (analysis.protocols && analysis.protocols.DNS) || 0);
    setElemText("pcap-stat-http", (analysis.protocols && analysis.protocols.HTTP) || 0);
    setElemText("pcap-stat-arp", (analysis.protocols && analysis.protocols.ARP) || 0);

    // Security Alerts
    const alertDiv = document.getElementById("pcap-alerts-container");
    if (alertDiv) {
        if (analysis.security_alerts && analysis.security_alerts.length > 0) {
            alertDiv.innerHTML = analysis.security_alerts.map(a => `
                <div class="alert-box alert-warning" style="margin-bottom:10px;">
                    <div>
                        <span class="badge badge-${(a.severity || 'medium').toLowerCase()}">${a.severity}</span> 
                        <b>${escapeHtml(a.title)}</b>
                        <p style="margin-top:4px;">${escapeHtml(a.details)}</p>
                        <p style="margin-top:4px;color:#a7f3d0;"><b>Recommendation:</b> ${escapeHtml(a.recommendation || '')}</p>
                    </div>
                </div>
            `).join("");
        } else {
            alertDiv.innerHTML = `<p class="text-muted" style="font-size:12px;">No malicious or cleartext credential exposures flagged in capture.</p>`;
        }
    }

    // Top Talkers
    const talkersList = document.getElementById("pcap-top-talkers");
    if (talkersList) {
        if (analysis.top_talkers && analysis.top_talkers.length > 0) {
            talkersList.innerHTML = analysis.top_talkers.map(t => `
                <li style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid rgba(255,255,255,0.05);font-size:12px;">
                    <code>${escapeHtml(t.ip)}</code>
                    <span class="badge badge-info">${t.count} pkts</span>
                </li>
            `).join("");
        } else {
            talkersList.innerHTML = `<li class="text-muted" style="font-size:12px;">No traffic conversation data loaded.</li>`;
        }
    }

    // Packet Table
    const pTbody = document.getElementById("pcap-packets-tbody");
    if (pTbody) {
        if (analysis.packets && analysis.packets.length > 0) {
            pTbody.innerHTML = analysis.packets.map((p, idx) => `
                <tr style="cursor:pointer;" onclick="inspectPacketByIndex(${idx})">
                    <td><b>${p.no}</b></td>
                    <td><code>${escapeHtml(p.src)}</code></td>
                    <td><code>${escapeHtml(p.dst)}</code></td>
                    <td><span class="badge badge-${getPcapProtocolBadgeClass(p.protocol)}">${escapeHtml(p.protocol)}</span></td>
                    <td>${p.length} B</td>
                    <td>${escapeHtml(p.info)}</td>
                </tr>
            `).join("");
        } else {
            pTbody.innerHTML = `<tr><td colspan="6" class="text-muted" style="text-align:center;">No packet streams available in capture.</td></tr>`;
        }
    }
}

function getPcapProtocolBadgeClass(proto) {
    if (!proto) return "info";
    const p = proto.toUpperCase();
    if (p === "TCP") return "info";
    if (p === "HTTP") return "medium";
    if (p === "DNS") return "low";
    if (p === "ARP") return "purple";
    if (p === "ICMP") return "high";
    return "info";
}

function escapeHtml(str) {
    if (!str) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

window.inspectPacketByIndex = function(idx) {
    if (!window.currentPcapPackets || !window.currentPcapPackets[idx]) return;
    const p = window.currentPcapPackets[idx];
    const modal = document.getElementById("modal-packet-inspect");
    if (modal) {
        const payloadText = p.payload_preview ? p.payload_preview : (p.info || "No application layer payload.");
        let headerDetails = `=== Frame #${p.no} Details ===\n` +
            `Timestamp: ${p.timestamp}\n` +
            `Protocol: ${p.protocol}\n` +
            `Source: ${p.src}${p.src_port ? ':' + p.src_port : ''}\n` +
            `Destination: ${p.dst}${p.dst_port ? ':' + p.dst_port : ''}\n` +
            `Length: ${p.length} bytes\n` +
            `Info: ${p.info}\n\n` +
            `=== Payload Content / Application Stream ===\n` +
            `${payloadText}`;

        document.getElementById("modal-packet-payload").innerText = headerDetails;
        modal.classList.add("active");
    }
};

function inspectPacketPayload(encodedText) {
    const text = decodeURIComponent(encodedText);
    const modal = document.getElementById("modal-packet-inspect");
    if (modal) {
        document.getElementById("modal-packet-payload").innerText = text;
        modal.classList.add("active");
    }
}

async function loadWiresharkFilters() {
    try {
        const res = await fetch("/api/pcap/filters");
        const data = await res.json();
        if (data.success) {
            const container = document.getElementById("wireshark-filters-grid");
            container.innerHTML = data.filters.map(f => `
                <div class="card" style="background:#090f1d;margin-bottom:10px;padding:12px;">
                    <div style="display:flex;justify-content:space-between;align-items:center;">
                        <span class="badge badge-info">${f.category}</span>
                        <button class="btn btn-secondary btn-sm" onclick="navigator.clipboard.writeText('${f.filter}'); showToast('Filter copied to clipboard!', 'success');">
                            <i class="fa fa-copy"></i> Copy
                        </button>
                    </div>
                    <p style="font-weight:600;margin:6px 0;font-size:13px;color:#fff;">${f.name}</p>
                    <code style="display:block;background:#030712;padding:6px 8px;border-radius:4px;color:#38bdf8;font-size:11.5px;margin-bottom:6px;">${f.filter}</code>
                    <p style="font-size:11.5px;color:#94a3b8;">${f.description}</p>
                </div>
            `).join("");
        }
    } catch (e) {
        console.error("Filters load failed", e);
    }
}

// --- Web Security (Burp & ZAP) ---
function initWebSecurity() {
    // Subtab switching
    const subtabs = document.querySelectorAll("#panel-web_sec .subtab-btn");
    subtabs.forEach(btn => {
        btn.addEventListener("click", () => {
            subtabs.forEach(b => b.classList.remove("active"));
            document.querySelectorAll("#panel-web_sec .web-subview").forEach(v => v.style.display = "none");
            btn.classList.add("active");
            const viewId = btn.getAttribute("data-subview");
            const targetView = document.getElementById(viewId);
            if (targetView) targetView.style.display = "block";
        });
    });

    // Load Guides & Status
    loadWebSecurityStatus();

    // Security Headers Analyzer
    const auditBtn = document.getElementById("btn-audit-headers");
    if (auditBtn) {
        auditBtn.addEventListener("click", async () => {
            const url = document.getElementById("web-audit-url").value.trim();
            auditBtn.disabled = true;
            auditBtn.innerHTML = `<i class="fa fa-spinner fa-spin"></i> Auditing Headers...`;

            try {
                const res = await fetch("/api/web-security/headers", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ url })
                });
                const data = await res.json();

                if (!data.success) {
                    showToast(data.error || "Web audit failed.", "error");
                    auditBtn.disabled = false;
                    auditBtn.innerHTML = `<i class="fa fa-shield-alt"></i> Audit Headers`;
                    return;
                }

                // Render Header Table
                const tbody = document.getElementById("web-headers-tbody");
                tbody.innerHTML = data.audit_results.map(h => `
                    <tr>
                        <td><b>${h.header}</b></td>
                        <td>${h.present ? '<span class="badge badge-low">Present</span>' : '<span class="badge badge-critical">Missing</span>'}</td>
                        <td><code>${h.value}</code></td>
                        <td><span class="badge badge-${h.severity.toLowerCase()}">${h.severity}</span></td>
                    </tr>
                `).join("");

                // Render Leaks / Findings
                const leaksDiv = document.getElementById("web-audit-findings");
                if (data.findings && data.findings.length > 0) {
                    leaksDiv.innerHTML = data.findings.map(f => `
                        <div class="alert-box alert-warning">
                            <div>
                                <span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span> 
                                <b>${f.title}</b>
                                <p style="margin-top:4px;">${f.description}</p>
                                <p style="margin-top:4px;color:#a7f3d0;"><b>Fix:</b> ${f.remediation}</p>
                            </div>
                        </div>
                    `).join("");
                } else {
                    leaksDiv.innerHTML = `<p class="text-muted" style="font-size:12px;">All essential defense-in-depth headers configured properly.</p>`;
                }

                showToast(`Header analysis complete for ${data.url}`, "success");
            } catch (e) {
                showToast("Network error during web audit.", "error");
            } finally {
                auditBtn.disabled = false;
                auditBtn.innerHTML = `<i class="fa fa-shield-alt"></i> Audit Headers`;
            }
        });
    }
}

async function loadWebSecurityStatus() {
    try {
        const res = await fetch("/api/web-security/status");
        const data = await res.json();
        if (data.success) {
            // Burp
            document.getElementById("web-burp-status-badge").className = data.burp.is_active ? "badge badge-low" : "badge badge-medium";
            document.getElementById("web-burp-status-badge").innerText = data.burp.is_active ? "LISTENING (Active)" : "NOT RUNNING";
            document.getElementById("web-burp-details").innerText = `${data.burp.status} - ${data.burp.service_detected}`;

            // ZAP
            document.getElementById("web-zap-status-badge").className = data.zap.is_active ? "badge badge-low" : "badge badge-medium";
            document.getElementById("web-zap-status-badge").innerText = data.zap.is_active ? "LISTENING (Active)" : "NOT RUNNING";
            document.getElementById("web-zap-details").innerText = `${data.zap.status} - ${data.zap.service_detected}`;
        }
    } catch (e) {
        console.error("Failed to check proxy status", e);
    }
}

// --- Findings Tracker ---
function initFindings() {
    loadFindingsData();

    // Filters
    document.getElementById("findings-filter-severity")?.addEventListener("change", loadFindingsData);
    document.getElementById("findings-filter-status")?.addEventListener("change", loadFindingsData);

    // Add Modal open
    const addBtn = document.getElementById("btn-add-finding-modal");
    const modal = document.getElementById("modal-add-finding");
    if (addBtn && modal) {
        addBtn.addEventListener("click", () => modal.classList.add("active"));
    }

    // Modal Form Submit
    const form = document.getElementById("form-add-finding");
    if (form) {
        form.addEventListener("submit", async (e) => {
            e.preventDefault();
            const payload = {
                title: document.getElementById("finding-title").value.trim(),
                severity: document.getElementById("finding-severity").value,
                category: document.getElementById("finding-category").value.trim(),
                target: document.getElementById("finding-target").value.trim(),
                description: document.getElementById("finding-description").value.trim(),
                evidence: document.getElementById("finding-evidence").value.trim(),
                remediation: document.getElementById("finding-remediation").value.trim(),
                status: document.getElementById("finding-status").value
            };

            try {
                const res = await fetch("/api/findings", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (data.success) {
                    showToast("Security finding recorded!", "success");
                    modal.classList.remove("active");
                    form.reset();
                    loadFindingsData();
                } else {
                    showToast(data.error || "Failed to save finding", "error");
                }
            } catch (err) {
                showToast("Network error saving finding", "error");
            }
        });
    }
}

async function loadFindingsData() {
    const sev = document.getElementById("findings-filter-severity")?.value || "all";
    const status = document.getElementById("findings-filter-status")?.value || "all";

    try {
        const res = await fetch(`/api/findings?severity=${sev}&status=${status}`);
        const data = await res.json();
        if (!data.success) return;

        const tbody = document.getElementById("findings-table-tbody");
        if (!tbody) return;

        if (data.findings.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" class="text-muted" style="text-align:center;">No security findings match current filter criteria.</td></tr>`;
            return;
        }

        tbody.innerHTML = data.findings.map(f => `
            <tr>
                <td><span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span></td>
                <td><b>${f.title}</b></td>
                <td><span class="badge badge-info">${f.category}</span></td>
                <td><code>${f.target}</code></td>
                <td>
                    <select class="form-select" style="padding:2px 6px;font-size:11px;width:auto;" onchange="updateFindingStatus(${f.id}, this.value)">
                        <option value="Open" ${f.status === 'Open' ? 'selected' : ''}>Open</option>
                        <option value="In Progress" ${f.status === 'In Progress' ? 'selected' : ''}>In Progress</option>
                        <option value="Remediated" ${f.status === 'Remediated' ? 'selected' : ''}>Remediated</option>
                        <option value="False Positive" ${f.status === 'False Positive' ? 'selected' : ''}>False Positive</option>
                    </select>
                </td>
                <td>${f.created_at.split('T')[0]}</td>
                <td>
                    <button class="btn btn-secondary btn-sm" onclick="viewFindingDetail(${encodeURIComponent(JSON.stringify(f))})"><i class="fa fa-eye"></i></button>
                    <button class="btn btn-danger btn-sm" onclick="deleteFindingItem(${f.id})"><i class="fa fa-trash"></i></button>
                </td>
            </tr>
        `).join("");
    } catch (e) {
        console.error("Failed to load findings", e);
    }
}

async function updateFindingStatus(id, newStatus) {
    try {
        const res = await fetch(`/api/findings/${id}`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ status: newStatus })
        });
        const data = await res.json();
        if (data.success) {
            showToast(`Finding #${id} status updated to ${newStatus}`, "success");
        }
    } catch (e) {
        showToast("Error updating finding status", "error");
    }
}

async function deleteFindingItem(id) {
    if (!confirm(`Are you sure you want to delete finding #${id}?`)) return;
    try {
        const res = await fetch(`/api/findings/${id}`, { method: "DELETE" });
        const data = await res.json();
        if (data.success) {
            showToast("Finding deleted", "success");
            loadFindingsData();
        }
    } catch (e) {
        showToast("Error deleting finding", "error");
    }
}

function viewFindingDetail(encodedJson) {
    const f = JSON.parse(decodeURIComponent(encodedJson));
    const modal = document.getElementById("modal-finding-detail");
    if (!modal) return;

    document.getElementById("modal-detail-title").innerText = f.title;
    document.getElementById("modal-detail-severity").innerText = f.severity;
    document.getElementById("modal-detail-severity").className = `badge badge-${f.severity.toLowerCase()}`;
    document.getElementById("modal-detail-target").innerText = f.target;
    document.getElementById("modal-detail-category").innerText = f.category;
    document.getElementById("modal-detail-desc").innerText = f.description || "N/A";
    document.getElementById("modal-detail-evidence").innerText = f.evidence || "N/A";
    document.getElementById("modal-detail-remediation").innerText = f.remediation || "N/A";

    modal.classList.add("active");
}

// --- Scan History ---
function initScanHistory() {
    loadScansData();
}

async function loadScansData() {
    try {
        const res = await fetch("/api/scans");
        const data = await res.json();
        if (!data.success) return;

        const tbody = document.getElementById("scans-table-tbody");
        if (!tbody) return;

        if (data.scans.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" class="text-muted" style="text-align:center;">No past scan executions recorded.</td></tr>`;
            return;
        }

        tbody.innerHTML = data.scans.map(s => `
            <tr>
                <td>#${s.id}</td>
                <td><span class="badge badge-info">${s.scan_type.toUpperCase()}</span></td>
                <td><code>${s.target}</code></td>
                <td>${s.profile}</td>
                <td><span class="badge ${s.status === 'Completed' ? 'badge-low' : 'badge-critical'}">${s.status}</span></td>
                <td>${s.duration}s</td>
                <td>
                    <button class="btn btn-secondary btn-sm" onclick="viewScanRaw(${s.id})"><i class="fa fa-terminal"></i> Output</button>
                    <button class="btn btn-danger btn-sm" onclick="deleteScanItem(${s.id})"><i class="fa fa-trash"></i></button>
                </td>
            </tr>
        `).join("");
    } catch (e) {
        console.error("Failed to load scans", e);
    }
}

async function viewScanRaw(scanId) {
    try {
        const res = await fetch(`/api/scans/${scanId}`);
        const data = await res.json();
        if (data.success) {
            const modal = document.getElementById("modal-scan-raw");
            if (modal) {
                document.getElementById("modal-scan-target").innerText = `${data.scan.scan_type.toUpperCase()} - ${data.scan.target}`;
                document.getElementById("modal-scan-raw-body").innerText = data.scan.raw_output || "(No output captured)";
                modal.classList.add("active");
            }
        }
    } catch (e) {
        showToast("Error retrieving scan details", "error");
    }
}

async function deleteScanItem(id) {
    if (!confirm(`Delete scan record #${id}?`)) return;
    try {
        const res = await fetch(`/api/scans/${id}`, { method: "DELETE" });
        const data = await res.json();
        if (data.success) {
            showToast("Scan record deleted", "success");
            loadScansData();
        }
    } catch (e) {
        showToast("Error deleting scan record", "error");
    }
}

// --- Reports Generator ---
function initReports() {
    loadReportsData();

    const genBtn = document.getElementById("btn-generate-report");
    if (genBtn) {
        genBtn.addEventListener("click", async () => {
            const target = document.getElementById("report-target-input").value.trim() || "127.0.0.1";
            const title = document.getElementById("report-title-input").value.trim() || `Security Assessment: ${target}`;

            genBtn.disabled = true;
            genBtn.innerHTML = `<i class="fa fa-spinner fa-spin"></i> Compiling PDF Report...`;

            try {
                const res = await fetch("/api/reports/generate", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ target, title })
                });
                const data = await res.json();

                if (data.success) {
                    showToast(`Report compiled with ${data.findings_count} findings!`, "success");
                    loadReportsData();

                    // Trigger direct download
                    const dlLink = document.createElement("a");
                    dlLink.href = data.download_url;
                    dlLink.download = data.filename;
                    document.body.appendChild(dlLink);
                    dlLink.click();
                    dlLink.remove();
                } else {
                    showToast(data.error || "Failed to generate report", "error");
                }
            } catch (e) {
                showToast("Report generation network error", "error");
            } finally {
                genBtn.disabled = false;
                genBtn.innerHTML = `<i class="fa fa-file-pdf"></i> Generate & Download Security Report (PDF)`;
            }
        });
    }
}

async function loadReportsData() {
    try {
        const res = await fetch("/api/reports");
        const data = await res.json();
        if (!data.success) return;

        const tbody = document.getElementById("reports-table-tbody");
        if (!tbody) return;

        if (data.reports.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" class="text-muted" style="text-align:center;">No assessment reports generated yet. Click above to compile your first report.</td></tr>`;
            return;
        }

        tbody.innerHTML = data.reports.map(r => `
            <tr>
                <td><b>${r.title}</b></td>
                <td><code>${r.target}</code></td>
                <td><span class="badge badge-info">${r.findings_count} findings</span></td>
                <td>${r.generated_at.split('T')[0]}</td>
                <td>
                    <a href="/api/reports/download/${r.report_filename}" class="btn btn-primary btn-sm" download>
                        <i class="fa fa-download"></i> Download PDF
                    </a>
                </td>
            </tr>
        `).join("");
    } catch (e) {
        console.error("Failed to load reports", e);
    }
}

// Close Modals on click outside or close button
document.addEventListener("click", (e) => {
    if (e.target.classList.contains("modal-overlay") || e.target.closest(".close-btn")) {
        document.querySelectorAll(".modal-overlay").forEach(m => m.classList.remove("active"));
    }
});
