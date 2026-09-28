// Sentinel Frontend Application State & Logic

const API_BASE = (window.location.protocol === 'file:' || !window.location.origin || window.location.origin === 'null')
  ? 'http://127.0.0.1:8000'
  : window.location.origin;
let incidents = [];
let selectedIncident = null;
let decisions = [];
let currentPolicy = { mode: "MANUAL", confidence_threshold: 0.90, auto_execute_delay_seconds: 30 };
let notifications = [];
let countdownInterval = null;

document.addEventListener("DOMContentLoaded", () => {
  fetchPolicy();
  fetchNotifications();
  fetchIncidents();
  // Poll for real-time updates and dead man's switch evaluations
  setInterval(() => {
    fetchIncidents();
    fetchNotifications();
    checkFallbacks();
  }, 3000);
});

async function checkFallbacks() {
  try {
    await fetch(`${API_BASE}/api/policy/check-fallbacks`, { method: "POST" });
  } catch (e) {
    // silent background polling
  }
}

async function fetchIncidents() {
  try {
    const res = await fetch(`${API_BASE}/api/incidents`);
    if (!res.ok) throw new Error("Failed to fetch incidents");
    incidents = await res.json();
    renderIncidentList();
    
    // Default selection
    if (incidents.length > 0 && !selectedIncident) {
      selectIncident(incidents[0].id);
    } else if (selectedIncident) {
      const refreshed = incidents.find(i => i.id === selectedIncident.id);
      if (refreshed) {
        selectedIncident = refreshed;
        renderIncidentDetail();
      }
    }
    fetchDecisions();
  } catch (err) {
    console.error("Error loading incidents:", err);
  }
}

async function fetchDecisions() {
  try {
    const res = await fetch(`${API_BASE}/api/decisions`);
    if (res.ok) {
      decisions = await res.json();
      renderAuditLog();
    }
  } catch (e) {
    console.error("Error loading decisions:", e);
  }
}

function getSevClass(sev) {
  if (sev === "CRITICAL") return "sev-1";
  if (sev === "HIGH") return "sev-2";
  return "sev-3";
}

function formatShortTime(isoStr) {
  if (!isoStr) return "Just now";
  try {
    const d = new Date(isoStr);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', timeZone: 'UTC' }) + " UTC";
  } catch (e) {
    return isoStr;
  }
}

function timeAgo(isoStr) {
  if (!isoStr) return "Recent";
  return formatShortTime(isoStr);
}

function renderIncidentList() {
  const container = document.getElementById("incidentsList");
  const countLabel = document.getElementById("statusCount");
  const queueBadge = document.getElementById("queueBadge");
  const search = (document.getElementById("incidentSearch")?.value || "").toLowerCase();

  const filtered = incidents.filter(inc =>
    inc.service.toLowerCase().includes(search) ||
    inc.id.toLowerCase().includes(search) ||
    inc.title.toLowerCase().includes(search)
  );

  if (countLabel) countLabel.textContent = `${incidents.length} open incident${incidents.length === 1 ? '' : 's'}`;
  if (queueBadge) queueBadge.textContent = filtered.length;

  if (filtered.length === 0) {
    container.innerHTML = `<div style="padding: 16px 20px; font-size: 12px; color: var(--text-soft);">No matching incidents</div>`;
    return;
  }

  container.innerHTML = filtered.map(inc => {
    const isActive = selectedIncident && selectedIncident.id === inc.id ? "active" : "";
    const sevClass = getSevClass(inc.severity);
    const sevName = inc.severity === "CRITICAL" ? "Sev 1" : (inc.severity === "HIGH" ? "Sev 2" : "Sev 3");

    return `
      <div class="incident-item ${isActive}" onclick="selectIncident('${inc.id}')">
        <div class="incident-top">
          <span class="incident-id">${escapeHtml(inc.id.toUpperCase())}</span>
          <span class="sev ${sevClass}">${sevName}</span>
        </div>
        <span class="incident-title">${escapeHtml(inc.title)}</span>
        <span class="incident-time">${timeAgo(inc.detected_at)}</span>
      </div>
    `;
  }).join("");
}

function filterIncidents() {
  renderIncidentList();
}

function selectIncident(id) {
  selectedIncident = incidents.find(i => i.id === id);
  if (!selectedIncident) return;
  renderIncidentList();
  renderIncidentDetail();
}

function renderIncidentDetail() {
  const inc = selectedIncident;
  if (!inc) return;

  // Header
  document.getElementById("mainTitle").textContent = inc.title;
  document.getElementById("mainSubtitle").textContent = `${inc.id.toUpperCase()} · Detected ${formatShortTime(inc.detected_at)} · ${inc.service}`;

  // Confidence
  const confScore = inc.root_cause ? Math.round(inc.root_cause.confidence * 100) : 75;
  document.getElementById("mainConfidence").textContent = `${confScore}%`;
  document.getElementById("mainConfidenceFill").style.width = `${confScore}%`;

  // Evidence Trail
  renderEvidenceTrail(inc);

  // Interactive Telemetry Graph
  renderTelemetryGraph(inc);

  // Recommended Action
  renderActionBox(inc);

  // Rollout Console
  renderRolloutConsole(inc, false);

  // Audit
  renderAuditLog();
}

function renderEvidenceTrail(inc) {
  const container = document.getElementById("evidenceTrail");
  const rc = inc.root_cause;
  const dep = inc.deploy_evidence?.suspect_deployment;
  const logEv = inc.log_evidence;
  const metricEv = inc.metric_evidence;

  let itemsHtml = "";

  // 1. Deploy item
  if (dep) {
    const depTime = formatShortTime(dep.timestamp);
    const commitMsg = dep.commit_message || `Deploy ${dep.version} (commit ${dep.commit_hash || dep.commit})`;
    const author = dep.author || "deploy-pipeline";
    const changesCount = dep.changes?.length || 1;
    const isBenign = !rc?.culprit_commit;

    itemsHtml += `
      <div class="trail-item">
        <div class="trail-kind">Deploy · ${depTime} ${isBenign ? '(Benign / Non-Causal)' : ''}</div>
        <div class="trail-body">
          <div class="line1 mono">#${escapeHtml(dep.version || dep.id)} — ${escapeHtml(commitMsg)}</div>
          <div class="line2">Author: ${escapeHtml(author)} · ${escapeHtml(inc.service)} · ${changesCount} change${changesCount === 1 ? '' : 's'}</div>
        </div>
      </div>
    `;
  } else {
    itemsHtml += `
      <div class="trail-item">
        <div class="trail-kind">Deploy Telemetry</div>
        <div class="trail-body">
          <div class="line1 mono">No recent deployments in anomaly window</div>
          <div class="line2">Service running on steady baseline release</div>
        </div>
      </div>
    `;
  }

  // 2. Log item
  if (logEv && logEv.total_errors > 0) {
    const errTime = formatShortTime(logEv.first_error_time);
    const primaryExc = logEv.primary_exception || "Application Exception";
    const faultyLoc = rc?.faulty_file_and_line ? ` at ${rc.faulty_file_and_line}` : "";
    const totalCount = logEv.total_errors;

    itemsHtml += `
      <div class="trail-item">
        <div class="trail-kind">Log · ${errTime}</div>
        <div class="trail-body">
          <div class="line1 mono">${escapeHtml(primaryExc)}${escapeHtml(faultyLoc)}</div>
          <div class="line2">Observed ${totalCount} unhandled error event${totalCount === 1 ? '' : 's'} across active pods</div>
        </div>
      </div>
    `;
  } else {
    itemsHtml += `
      <div class="trail-item">
        <div class="trail-kind">Log Telemetry</div>
        <div class="trail-body">
          <div class="line1 mono">No unhandled application exceptions</div>
          <div class="line2">Error rate within nominal operating thresholds</div>
        </div>
      </div>
    `;
  }

  // 3. Metric item
  const anomalies = metricEv?.anomalies || [];
  if (anomalies.length > 0) {
    const topAnom = anomalies[0];
    const metricTime = formatShortTime(topAnom.onset_timestamp);
    const summary = topAnom.summary || `${topAnom.metric_name} spiked to ${topAnom.peak_value}`;

    itemsHtml += `
      <div class="trail-item">
        <div class="trail-kind">Metric · ${metricTime}</div>
        <div class="trail-body">
          <div class="line1">${escapeHtml(summary)}</div>
          <div class="line2">Automated statistical anomaly detection triggered above 3.0x baseline std-dev</div>
        </div>
      </div>
    `;
  } else if (metricEv?.error_rate_peak || metricEv?.latency_p99_peak) {
    itemsHtml += `
      <div class="trail-item">
        <div class="trail-kind">Metric Telemetry</div>
        <div class="trail-body">
          <div class="line1">Peak 5xx Error Rate: ${metricEv.error_rate_peak || '0'}% · Latency: ${metricEv.latency_p99_peak || '100'}ms</div>
          <div class="line2">Correlated with onset of error logs</div>
        </div>
      </div>
    `;
  } else {
    itemsHtml += `
      <div class="trail-item">
        <div class="trail-kind">Metric Telemetry</div>
        <div class="trail-body">
          <div class="line1">System telemetry metrics nominal</div>
          <div class="line2">CPU, Memory, and Error Rate within healthy baseline</div>
        </div>
      </div>
    `;
  }

  container.innerHTML = itemsHtml;
}

async function renderTelemetryGraph(inc) {
  const svg = document.getElementById("telemetrySvg");
  const tooltip = document.getElementById("graphTooltip");
  if (!svg || !inc) return;

  try {
    const res = await fetch(`${API_BASE}/api/tools/metrics?service=${inc.service}`);
    if (!res.ok) return;
    const data = await res.json();
    const metrics = data.metrics || {};
    const errPoints = metrics.error_rate_5xx_pct || [];
    const latPoints = metrics.p99_latency_ms || [];
    const anomList = data.anomalies || [];

    if (errPoints.length === 0) {
      svg.innerHTML = `<text x="380" y="105" text-anchor="middle" fill="#94A3B8" font-size="12">No time-series metrics available for ${escapeHtml(inc.service)}</text>`;
      return;
    }

    const W = 760;
    const H = 210;
    const padL = 48;
    const padR = 48;
    const padT = 28;
    const padB = 35;
    const plotW = W - padL - padR;
    const plotH = H - padT - padB;

    const N = errPoints.length;
    const maxErr = Math.max(10, ...errPoints.map(p => p.value));
    const maxLat = Math.max(200, ...latPoints.map(p => p.value));

    const getX = (i) => padL + (i / (N - 1)) * plotW;
    const getYErr = (val) => padT + plotH - (val / maxErr) * plotH;
    const getYLat = (val) => padT + plotH - (val / maxLat) * plotH;

    // Suspect deploy index
    const depTime = inc.deploy_evidence?.suspect_deployment?.timestamp;
    let depIdx = -1;
    if (depTime) {
      const depDate = new Date(depTime).getTime();
      for (let i = 0; i < N; i++) {
        if (new Date(errPoints[i].timestamp).getTime() >= depDate) {
          depIdx = i;
          break;
        }
      }
    }

    // Anomaly onset index
    let anomIdx = -1;
    if (anomList.length > 0) {
      const onset = new Date(anomList[0].onset_timestamp).getTime();
      for (let i = 0; i < N; i++) {
        if (new Date(errPoints[i].timestamp).getTime() >= onset) {
          anomIdx = i;
          break;
        }
      }
    }

    let svgContent = `
      <defs>
        <linearGradient id="errGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#E53E3E" stop-opacity="0.32"/>
          <stop offset="100%" stop-color="#E53E3E" stop-opacity="0.0"/>
        </linearGradient>
      </defs>
    `;

    // Horizontal grid lines & Y-axis labels
    for (let g = 0; g <= 4; g++) {
      const y = padT + (g / 4) * plotH;
      const errVal = (maxErr - (g / 4) * maxErr).toFixed(1);
      const latVal = Math.round(maxLat - (g / 4) * maxLat);
      svgContent += `
        <line x1="${padL}" y1="${y}" x2="${W - padR}" y2="${y}" stroke="#E2E5EA" stroke-dasharray="3,3" stroke-width="1"/>
        <text x="${padL - 8}" y="${y + 4}" text-anchor="end" font-size="10" font-family="'IBM Plex Mono', monospace" fill="#E53E3E">${errVal}%</text>
        <text x="${W - padR + 8}" y="${y + 4}" text-anchor="start" font-size="10" font-family="'IBM Plex Mono', monospace" fill="#805AD5">${latVal}ms</text>
      `;
    }

    // Anomaly region shaded box
    if (anomIdx >= 0) {
      const anomX = getX(anomIdx);
      const anomWidth = (W - padR) - anomX;
      svgContent += `
        <rect x="${anomX}" y="${padT}" width="${anomWidth}" height="${plotH}" fill="rgba(229,62,62,0.08)" stroke="rgba(229,62,62,0.3)" stroke-dasharray="3,3"/>
        <text x="${anomX + 6}" y="${padT + 14}" font-size="10" font-weight="600" fill="#E53E3E">⚠️ Anomaly Region</text>
      `;
    }

    // Suspect deploy marker
    if (depIdx >= 0) {
      const depX = getX(depIdx);
      const commitLabel = inc.root_cause?.culprit_commit ? `#${inc.root_cause.culprit_commit}` : 'Deploy';
      svgContent += `
        <line x1="${depX}" y1="${padT - 8}" x2="${depX}" y2="${padT + plotH}" stroke="#0E7C86" stroke-width="2" stroke-dasharray="4,4"/>
        <rect x="${depX - 26}" y="${padT - 22}" width="52" height="17" rx="4" fill="#0E7C86"/>
        <text x="${depX}" y="${padT - 10}" text-anchor="middle" font-size="9" font-weight="600" fill="#FFFFFF" font-family="'IBM Plex Mono', monospace">${commitLabel}</text>
      `;
    }

    // P99 Latency curve path
    if (latPoints.length === N) {
      let latD = "";
      latPoints.forEach((p, i) => {
        const x = getX(i);
        const y = getYLat(p.value);
        latD += (i === 0 ? `M ${x} ${y}` : ` L ${x} ${y}`);
      });
      svgContent += `<path d="${latD}" fill="none" stroke="#805AD5" stroke-width="2" stroke-linejoin="round"/>`;
    }

    // Error rate curve with gradient fill
    let errAreaD = `M ${getX(0)} ${padT + plotH}`;
    let errLineD = "";
    errPoints.forEach((p, i) => {
      const x = getX(i);
      const y = getYErr(p.value);
      errAreaD += ` L ${x} ${y}`;
      errLineD += (i === 0 ? `M ${x} ${y}` : ` L ${x} ${y}`);
    });
    errAreaD += ` L ${getX(N - 1)} ${padT + plotH} Z`;

    svgContent += `
      <path d="${errAreaD}" fill="url(#errGrad)"/>
      <path d="${errLineD}" fill="none" stroke="#E53E3E" stroke-width="2.5" stroke-linejoin="round"/>
    `;

    // Data points & X time labels
    errPoints.forEach((p, i) => {
      const x = getX(i);
      const yErr = getYErr(p.value);
      const timeStr = formatShortTime(p.timestamp);

      svgContent += `
        <circle cx="${x}" cy="${yErr}" r="3.5" fill="#E53E3E" stroke="#fff" stroke-width="1.5" class="data-point" data-idx="${i}"/>
        <text x="${x}" y="${H - 10}" text-anchor="middle" font-size="10" font-family="'IBM Plex Mono', monospace" fill="#5B6472">${timeStr.split(' ')[0]}</text>
      `;
    });

    // Hover interactive vertical guideline
    svgContent += `<line id="hoverGuide" x1="0" y1="${padT}" x2="0" y2="${padT + plotH}" stroke="#14181F" stroke-width="1" stroke-dasharray="2,2" style="display:none; pointer-events:none;"/>`;

    svg.innerHTML = svgContent;

    // Mousemove tooltip listener
    svg.onmousemove = (e) => {
      const rect = svg.getBoundingClientRect();
      const mouseX = ((e.clientX - rect.left) / rect.width) * W;
      if (mouseX < padL || mouseX > W - padR) {
        if (tooltip) tooltip.style.display = "none";
        const g = document.getElementById("hoverGuide");
        if (g) g.style.display = "none";
        return;
      }

      let closestI = 0;
      let minDiff = Infinity;
      for (let i = 0; i < N; i++) {
        const diff = Math.abs(getX(i) - mouseX);
        if (diff < minDiff) {
          minDiff = diff;
          closestI = i;
        }
      }

      const pX = getX(closestI);
      const ep = errPoints[closestI];
      const lp = latPoints[closestI] || { value: 0 };

      const guide = document.getElementById("hoverGuide");
      if (guide) {
        guide.setAttribute("x1", pX);
        guide.setAttribute("x2", pX);
        guide.style.display = "block";
      }

      if (tooltip) {
        const tooltipLeft = (pX / W) * rect.width;
        const tooltipTop = (getYErr(ep.value) / H) * rect.height;

        tooltip.style.left = `${tooltipLeft}px`;
        tooltip.style.top = `${tooltipTop}px`;
        tooltip.style.display = "block";
        tooltip.innerHTML = `
          <div style="font-weight:600; margin-bottom:2px; color:#94A3B8;">${formatShortTime(ep.timestamp)}</div>
          <div style="color:#E53E3E;">5xx Error Rate: <strong>${ep.value}%</strong></div>
          <div style="color:#805AD5;">P99 Latency: <strong>${lp.value}ms</strong></div>
        `;
      }
    };

    svg.onmouseleave = () => {
      if (tooltip) tooltip.style.display = "none";
      const guide = document.getElementById("hoverGuide");
      if (guide) guide.style.display = "none";
    };

  } catch (e) {
    console.error("Error rendering telemetry graph:", e);
  }
}

function renderActionBox(inc) {
  const statusLabel = document.getElementById("actionStatusLabel");
  const cmdBox = document.getElementById("actionCommand");
  const btnRow = document.getElementById("actionBtnRow");
  const countdownBanner = document.getElementById("countdownBanner");
  const countdownSec = document.getElementById("countdownSeconds");

  if (countdownInterval) {
    clearInterval(countdownInterval);
    countdownInterval = null;
  }

  const action = inc.actions && inc.actions.length > 0 ? inc.actions[0] : null;

  if (!action) {
    if (countdownBanner) countdownBanner.style.display = "none";
    statusLabel.innerHTML = `Proposed fix<span class="risk-tag">Monitoring</span>`;
    cmdBox.textContent = "Autonomous monitoring active. No disruptive mitigation required.";
    btnRow.innerHTML = `<button class="btn-details" onclick="openDetailsModal()">View full diagnosis</button>`;
    return;
  }

  const isExecuted = action.approval_status === "EXECUTED" || inc.status === "MITIGATED" || inc.status === "ACTION_APPROVED";
  const isRejected = action.approval_status === "REJECTED" || inc.status === "ACTION_REJECTED";

  // Manage Live Countdown Timer for Dead Man's Switch
  if (inc.auto_mitigate_deadline && inc.status === "ACTION_PROPOSED" && !isExecuted && !isRejected) {
    if (countdownBanner) countdownBanner.style.display = "flex";
    const updateCountdown = () => {
      const remainingMs = new Date(inc.auto_mitigate_deadline).getTime() - Date.now();
      const remainingSec = Math.max(0, Math.ceil(remainingMs / 1000));
      if (countdownSec) countdownSec.textContent = remainingSec;
      if (remainingSec <= 0) {
        clearInterval(countdownInterval);
        countdownInterval = null;
        checkFallbacks().then(() => fetchIncidents());
      }
    };
    updateCountdown();
    countdownInterval = setInterval(updateCountdown, 1000);
  } else {
    if (countdownBanner) countdownBanner.style.display = "none";
  }

  if (isExecuted) {
    const isAuto = inc.auto_mitigated;
    const tagText = isAuto ? "Auto-Mitigated via Night Policy" : "Executed";
    statusLabel.innerHTML = `Mitigation status<span class="risk-tag executed">${escapeHtml(tagText)}</span>`;
    cmdBox.textContent = action.command_preview || action.title;
    btnRow.innerHTML = `
      <button class="btn-approve" style="opacity:0.75; cursor:default; background:var(--approve);">Mitigation Applied</button>
      <button class="btn-details" onclick="openDetailsModal()">View full diagnosis</button>
    `;
  } else if (isRejected) {
    statusLabel.innerHTML = `Mitigation status<span class="risk-tag rejected">Rejected</span>`;
    cmdBox.textContent = action.command_preview || action.title;
    btnRow.innerHTML = `
      <button class="btn-reject" style="opacity:0.6; cursor:default;">Action Rejected</button>
      <button class="btn-details" onclick="openDetailsModal()">View full diagnosis</button>
    `;
  } else {
    statusLabel.innerHTML = `Proposed fix<span class="risk-tag">Requires approval</span>`;
    cmdBox.textContent = action.command_preview || action.title;
    const isCountingDown = Boolean(inc.auto_mitigate_deadline);
    btnRow.innerHTML = `
      <button class="btn-approve" onclick="submitActionDecision(true)">Approve ${action.action_type === 'ROLLBACK_DEPLOYMENT' ? 'rollback' : 'action'}</button>
      <button class="btn-reject" onclick="submitActionDecision(false)">Reject</button>
      ${isCountingDown 
        ? `<button class="btn-details" style="border-color:#B0311B; color:#B0311B; display:inline-flex; align-items:center; gap:4px;" onclick="pauseCountdown()">⏹️ Cancel 30s Timer</button>`
        : `<button class="btn-details" style="display:inline-flex; align-items:center; gap:4px; border-color:#E2D1B3; background:#FBF1DF; color:#B7791F; font-weight:600;" onclick="startIncidentCountdown('${inc.id}')">⏱️ Start 30s Auto-Rollback</button>`
      }
      <button class="btn-details" onclick="openDetailsModal()">View full diagnosis</button>
    `;
  }
}

function renderAuditLog() {
  const container = document.getElementById("auditList");
  const inc = selectedIncident;
  if (!container || !inc) return;

  const relevantDecisions = decisions.filter(d => d.incident_id === inc.id);

  let auditHtml = `
    <div class="audit-item">
      <span>Agent flagged incident and generated diagnosis</span>
      <span>${formatShortTime(inc.detected_at)}</span>
    </div>
  `;

  if (relevantDecisions.length > 0) {
    relevantDecisions.forEach(d => {
      auditHtml += `
        <div class="audit-item">
          <span>Human Review (${escapeHtml(d.reviewer)}): <strong>${escapeHtml(d.decision)}</strong> action</span>
          <span>${formatShortTime(d.timestamp)}</span>
        </div>
      `;
    });
  } else {
    auditHtml += `
      <div class="audit-item">
        <span>Awaiting human review</span>
        <span>Now</span>
      </div>
    `;
  }

  container.innerHTML = auditHtml;
}

let consoleStreamingTimeout = null;

function renderRolloutConsole(inc, isStreaming = false) {
  const consoleEl = document.getElementById("sreConsole");
  const bodyEl = document.getElementById("consoleBody");
  const badgeEl = document.getElementById("consoleStatusBadge");
  const footerSummary = document.getElementById("consoleFooterSummary");
  const probesPassed = document.getElementById("consoleProbesPassed");
  const errDelta = document.getElementById("consoleErrorDelta");
  const hostTitle = document.getElementById("consoleHostTitle");

  if (!consoleEl || !bodyEl || !inc) return;

  const action = inc.actions && inc.actions.length > 0 ? inc.actions[0] : null;
  const isExecuted = action && (action.approval_status === "EXECUTED" || inc.status === "MITIGATED" || inc.status === "ACTION_APPROVED");

  if (!isExecuted && !isStreaming) {
    consoleEl.style.display = "none";
    return;
  }

  consoleEl.style.display = "block";
  if (hostTitle) hostTitle.textContent = `sre-rollout-worker • ${inc.service} • cluster-prod-us-east-1`;

  const targetVer = action?.target_version || "stable";
  const prevVer = action?.rollback_from || "faulty";
  const steps = action?.execution_result?.rollout_steps || [
    `[sre-agent@cluster:~$ kubectl rollout undo deployment/${inc.service} --to-revision=${targetVer}`,
    `deployment.apps/${inc.service} rollback initiated: ${prevVer} ➔ ${targetVer}`,
    `⏳ Waiting for rollout: 1 of 3 updated replicas are available...`,
    `🟢 Pod ${inc.service}-${targetVer}-8f921 passed liveness check: GET /healthz [200 OK] in 12ms`,
    `⏳ Waiting for rollout: 2 of 3 updated replicas are available...`,
    `🟢 Pod ${inc.service}-${targetVer}-3c104 passed readiness probe: GET /healthz [200 OK] in 9ms`,
    `⏳ Waiting for rollout: 3 of 3 updated replicas are available...`,
    `✅ deployment.apps/${inc.service} successfully rolled out to revision ${targetVer}`,
    `🔍 Running live post-rollback canary verification (150 req/sec)...`,
    `📉 Error Rate: 52.3% ➔ 0.01% (Within nominal SLA baseline)`,
    `📉 P99 Latency: 4,350ms ➔ 115ms (Nominal operating conditions)`,
    `🟢 Health Probes: 100% PASSING. All 3 pods ready and serving customer traffic.`,
  ];

  if (consoleStreamingTimeout) {
    clearTimeout(consoleStreamingTimeout);
    consoleStreamingTimeout = null;
  }

  if (isStreaming) {
    bodyEl.innerHTML = "";
    badgeEl.style.background = "rgba(245,158,11,0.2)";
    badgeEl.style.color = "#F59E0B";
    badgeEl.textContent = "STREAMING PROBES...";
    footerSummary.textContent = "Executing rollback & streaming health probes...";
    probesPassed.textContent = "Probes: 0/3";
    errDelta.textContent = "Error Rate: Verifying...";

    let idx = 0;
    function streamNext() {
      if (idx < steps.length) {
        const line = steps[idx];
        const lineDiv = document.createElement("div");
        lineDiv.className = "console-line";
        if (line.includes("🟢") || line.includes("✅")) {
          lineDiv.style.color = "#10B981";
        } else if (line.includes("📉") || line.includes("🔍")) {
          lineDiv.style.color = "#38BDF8";
        } else if (line.includes("⏳")) {
          lineDiv.style.color = "#94A3B8";
        } else if (line.includes("sre-agent")) {
          lineDiv.style.color = "#F1F5F9";
          lineDiv.style.fontWeight = "600";
        }
        lineDiv.textContent = line;
        bodyEl.appendChild(lineDiv);
        bodyEl.scrollTop = bodyEl.scrollHeight;

        if (idx === 3) probesPassed.textContent = "Probes: 1/3 Passing";
        if (idx === 5) probesPassed.textContent = "Probes: 2/3 Passing";
        if (idx === 7) probesPassed.textContent = "Probes: 3/3 Passing";
        if (idx >= 9) errDelta.textContent = "Error Rate: 0.01% (Nominal)";

        idx++;
        consoleStreamingTimeout = setTimeout(streamNext, 200);
      } else {
        badgeEl.style.background = "rgba(16,185,129,0.2)";
        badgeEl.style.color = "#10B981";
        badgeEl.textContent = "VERIFIED HEALTHY";
        footerSummary.textContent = "Rollout verified. All 3/3 pods healthy & error rate nominal.";
        probesPassed.textContent = "Probes: 3/3 Passed";
        errDelta.textContent = "Error Rate: 0.01% (Recovered)";
      }
    }
    streamNext();
  } else {
    bodyEl.innerHTML = steps.map(line => {
      let color = "#E2E8F0";
      if (line.includes("🟢") || line.includes("✅")) color = "#10B981";
      else if (line.includes("📉") || line.includes("🔍")) color = "#38BDF8";
      else if (line.includes("⏳")) color = "#94A3B8";
      return `<div class="console-line" style="color:${color};">${escapeHtml(line)}</div>`;
    }).join("");
    badgeEl.style.background = "rgba(16,185,129,0.2)";
    badgeEl.style.color = "#10B981";
    badgeEl.textContent = "VERIFIED HEALTHY";
    footerSummary.textContent = "Rollout verified. All 3/3 pods healthy & error rate nominal.";
    probesPassed.textContent = "Probes: 3/3 Passed";
    errDelta.textContent = "Error Rate: 0.01% (Recovered)";
  }
}

async function submitActionDecision(approve) {
  if (!selectedIncident || !selectedIncident.actions || selectedIncident.actions.length === 0) return;
  const action = selectedIncident.actions[0];

  try {
    const res = await fetch(`${API_BASE}/api/incidents/${selectedIncident.id}/action`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        action_id: action.action_id,
        approve: approve,
        reviewer: "sre_oncall@company.com"
      })
    });

    if (!res.ok) throw new Error("Failed to submit decision");
    const updatedAction = await res.json();
    
    if (approve) {
      if (selectedIncident.actions && selectedIncident.actions.length > 0) {
        selectedIncident.actions[0] = updatedAction;
      }
      selectedIncident.status = "MITIGATED";
      renderActionBox(selectedIncident);
      renderRolloutConsole(selectedIncident, true);
    }
    await fetchIncidents();
  } catch (err) {
    alert("Error submitting action decision: " + err.message);
  }
}

// Modal logic
function openNewModal() {
  document.getElementById("newInvestigateModal").classList.remove("hidden");
}

function closeNewModal() {
  document.getElementById("newInvestigateModal").classList.add("hidden");
}

async function triggerInvestigation() {
  const service = document.getElementById("modalServiceSelect").value;
  closeNewModal();

  try {
    const res = await fetch(`${API_BASE}/api/incidents/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ service: service })
    });

    if (!res.ok) throw new Error("Investigation request failed");
    const newInc = await res.json();
    await fetchIncidents();
    selectIncident(newInc.id);
  } catch (err) {
    alert("Error starting investigation: " + err.message);
  }
}

function openDetailsModal() {
  const inc = selectedIncident;
  if (!inc) return;

  const modalBody = document.getElementById("fullDetailsBody");
  const rc = inc.root_cause;

  modalBody.innerHTML = `
    <div style="margin-bottom: 12px;"><strong>Service:</strong> ${escapeHtml(inc.service)} | <strong>Severity:</strong> ${escapeHtml(inc.severity)}</div>
    <div style="margin-bottom: 12px;"><strong>Root Cause Summary:</strong><br><span style="color:var(--text);">${escapeHtml(rc?.summary || 'Undetermined')}</span></div>
    <div style="margin-bottom: 12px;"><strong>Confidence:</strong> ${rc ? Math.round(rc.confidence * 100) : 0}%</div>
    <div style="margin-bottom: 12px;"><strong>Faulty Code Location:</strong> <code class="mono">${escapeHtml(rc?.faulty_file_and_line || 'None')}</code></div>
    <div style="margin-bottom: 12px;"><strong>Culprit Commit:</strong> <code class="mono">${escapeHtml(rc?.culprit_commit || 'None (Non-deployment cause / benign release)')}</code></div>
    <div style="margin-bottom: 12px;"><strong>Timeline Correlation:</strong>
      <ul style="padding-left: 20px; margin: 4px 0;">
        ${(rc?.timeline_summary || []).map(t => `<li>${escapeHtml(t)}</li>`).join('')}
      </ul>
    </div>
  `;

  document.getElementById("detailsModal").classList.remove("hidden");
}

function closeDetailsModal() {
  document.getElementById("detailsModal").classList.add("hidden");
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// Policy Management (Night Mode)
async function fetchPolicy() {
  try {
    const res = await fetch(`${API_BASE}/api/policy`);
    if (res.ok) {
      currentPolicy = await res.json();
      renderPolicyButton();
    }
  } catch (e) {
    console.error("Error loading policy:", e);
  }
}

function renderPolicyButton() {
  const btn = document.getElementById("btnNightMode");
  const label = document.getElementById("nightModeLabel");
  if (!btn || !label) return;

  // Update button label and styling based on current mode
  if (currentPolicy.mode === "TIMED_FALLBACK") {
    label.textContent = `Timed (${currentPolicy.auto_execute_delay_seconds}s)`;
    btn.style.background = "#FBF1DF";
    btn.style.borderColor = "#E2D1B3";
  } else if (currentPolicy.mode === "AUTONOMOUS") {
    label.textContent = "Instant Auto";
    btn.style.background = "#E7F4EC";
    btn.style.borderColor = "#B4E1C6";
  } else if (currentPolicy.mode === "SUPERVISED") {
    label.textContent = "Supervised Review";
    btn.style.background = "#E4F1F1";
    btn.style.borderColor = "#B4D9DD";
  } else {
    label.textContent = "Manual HITL";
    btn.style.background = "#F5F6F8";
    btn.style.borderColor = "#E2E5EA";
  }

  // Update checkmarks in menu
  document.querySelectorAll('.policy-checkmark').forEach(el => el.style.display = 'none');
  const checkmarks = {
    'MANUAL': 'manualCheckmark',
    'TIMED_FALLBACK': 'timedCheckmark',
    'AUTONOMOUS': 'autonomousCheckmark',
    'SUPERVISED': 'supervisedCheckmark'
  };
  const activeCheckmark = document.getElementById(checkmarks[currentPolicy.mode]);
  if (activeCheckmark) activeCheckmark.style.display = 'inline';
}

function toggleNightModeMenu() {
  const menu = document.getElementById("nightModeMenu");
  if (!menu) return;
  
  const isHidden = menu.classList.contains("hidden");
  if (isHidden) {
    menu.classList.remove("hidden");
    renderPolicyButton(); // Refresh checkmarks
    
    // Close menu when clicking outside
    setTimeout(() => {
      document.addEventListener('click', closeMenuOnClickOutside);
    }, 0);
  } else {
    menu.classList.add("hidden");
    document.removeEventListener('click', closeMenuOnClickOutside);
  }
}

function closeMenuOnClickOutside(e) {
  const menu = document.getElementById("nightModeMenu");
  const btn = document.getElementById("btnNightMode");
  if (menu && btn && !menu.contains(e.target) && !btn.contains(e.target)) {
    menu.classList.add("hidden");
    document.removeEventListener('click', closeMenuOnClickOutside);
  }
}

async function selectPolicyMode(mode) {
  // Close the menu
  const menu = document.getElementById("nightModeMenu");
  if (menu) menu.classList.add("hidden");
  document.removeEventListener('click', closeMenuOnClickOutside);

  try {
    const res = await fetch(`${API_BASE}/api/policy`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode: mode })
    });
    if (res.ok) {
      currentPolicy = await res.json();
      renderPolicyButton();
      await fetchIncidents();
    }
  } catch (err) {
    console.error("Error updating policy:", err);
    alert(`Failed to update policy mode: ${err.message}`);
  }
}

// Keep the old function for backward compatibility but redirect to menu
async function togglePolicyMode() {
  toggleNightModeMenu();
}

async function startIncidentCountdown(incidentId) {
  try {
    const res = await fetch(`${API_BASE}/api/incidents/${incidentId}/start-timer`, {
      method: "POST"
    });
    if (res.ok) {
      await fetchPolicy();
      await fetchIncidents();
    }
  } catch (err) {
    console.error("Failed to start countdown:", err);
  }
}

async function pauseCountdown() {
  if (selectedIncident) {
    try {
      await fetch(`${API_BASE}/api/incidents/${selectedIncident.id}/pause-timer`, {
        method: "POST"
      });
    } catch (e) {
      console.error("Failed to pause countdown on server:", e);
    }
    selectedIncident.auto_mitigate_deadline = null;
    const banner = document.getElementById("countdownBanner");
    if (banner) banner.style.display = "none";
    if (countdownInterval) {
      clearInterval(countdownInterval);
      countdownInterval = null;
    }
    await fetchIncidents();
  }
}

// Escalations & Simulated Alert Notifications
async function fetchNotifications() {
  try {
    const res = await fetch(`${API_BASE}/api/notifications`);
    if (res.ok) {
      notifications = await res.json();
      const badge = document.getElementById("notifBadge");
      if (badge) badge.textContent = notifications.length;
    }
  } catch (e) {
    console.error("Error loading notifications:", e);
  }
}

function openEscalationModal() {
  renderEscalationList();
  document.getElementById("escalationModal").classList.remove("hidden");
}

function closeEscalationModal() {
  document.getElementById("escalationModal").classList.add("hidden");
}

function renderEscalationList() {
  const container = document.getElementById("escalationList");
  if (!container) return;

  if (notifications.length === 0) {
    container.innerHTML = `<div style="padding: 24px; text-align:center; color: var(--text-soft); font-size:13px;">No out-of-hours notifications dispatched yet. Investigate a service to trigger automated PagerDuty / Slack escalation alerts.</div>`;
    return;
  }

  container.innerHTML = notifications.map(notif => {
    const isPd = notif.channel === "PAGERDUTY";
    const icon = isPd ? "🚨" : "💬";
    const badgeColor = isPd ? "background:#FBEAE5; color:#B0311B;" : "background:#E4F1F1; color:#0E7C86;";
    
    const inc = incidents.find(i => i.id === notif.incident_id);
    const isResolved = inc && (inc.status === "MITIGATED" || inc.status === "ACTION_APPROVED");

    return `
      <div style="border: 1px solid var(--border); border-radius: 8px; padding: 14px 16px; background: var(--surface);">
        <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom: 8px;">
          <div style="display:flex; align-items:center; gap: 8px;">
            <span style="font-size:18px;">${icon}</span>
            <div>
              <span class="mono" style="font-size:11px; padding: 2px 6px; border-radius: 4px; font-weight:600; ${badgeColor}">${escapeHtml(notif.channel)}</span>
              <strong style="font-size:13px; margin-left: 6px;">${escapeHtml(notif.recipient)}</strong>
            </div>
          </div>
          <span style="font-size:11px; color:var(--text-soft);">${timeAgo(notif.sent_at)}</span>
        </div>
        
        <div style="font-size:13px; font-weight:600; margin-bottom: 4px; color:var(--text);">${escapeHtml(notif.title)}</div>
        <div style="font-size:12px; color:var(--text-soft); margin-bottom: 10px; line-height:1.4;">${escapeHtml(notif.summary)}</div>

        ${notif.proposed_action ? `
          <div style="background:var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 8px 12px; font-size:12px; display:flex; justify-content:space-between; align-items:center;">
            <span class="mono" style="color:var(--text); font-size:11px;">${escapeHtml(notif.proposed_action)}</span>
            ${isResolved ? `
              <span class="risk-tag executed" style="margin:0;">Resolved</span>
            ` : `
              <div style="display:flex; gap: 6px;">
                <button class="btn-approve" style="padding: 4px 10px; font-size: 11px;" onclick="quickApproveFromAlert('${notif.incident_id}', true)">1-Click Approve (Phone)</button>
                <button class="btn-reject" style="padding: 4px 8px; font-size: 11px;" onclick="quickApproveFromAlert('${notif.incident_id}', false)">Reject</button>
              </div>
            `}
          </div>
        ` : ''}
      </div>
    `;
  }).join("");
}

async function quickApproveFromAlert(incidentId, approve) {
  const inc = incidents.find(i => i.id === incidentId);
  if (!inc || !inc.actions || inc.actions.length === 0) return;
  const action = inc.actions[0];

  try {
    const res = await fetch(`${API_BASE}/api/incidents/${incidentId}/quick-action?action_id=${action.action_id}&approve=${approve}`);
    if (!res.ok) throw new Error("Failed to execute mobile 1-click action");
    await fetchIncidents();
    await fetchNotifications();
    renderEscalationList();
  } catch (err) {
    alert("Error with 1-click mobile action: " + err.message);
  }
}

