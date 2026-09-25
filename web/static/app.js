/**
 * KernelGuard Frontend Controller v2.0
 * Features:
 * 1. Force-Directed Behavioral Graph with GNN Saliency Heatmap
 * 2. Causal Provenance Slicing (Backward Root-Cause & Forward Blast-Radius)
 * 3. Autonomous In-Kernel Mitigation Trigger
 * 4. Real Host OS Sniffer Toggle
 * 5. Interactive Shell Simulator & Sandbox Terminal
 * 6. Publication LaTeX Table Exporter
 */

// Canvas & Graph Engine State
let canvas, ctx;
let nodes = [];
let edges = [];
let nodeMap = new Map();
let simulationRunning = true;
let transform = { x: 0, y: 0, k: 1 };
let isDragging = false;
let dragNode = null;
let lastMouse = { x: 0, y: 0 };
let selectedNode = null;
let pulseTimer = 0;

// Feature State
let saliencyHeatmapEnabled = false;
let hostSnifferActive = false;
let activeSlicedNodes = new Set();
let activeSlicedEdges = new Set();
let currentAssessment = null;
let totalEventsCaptured = 0;

// Color Palette
const COLORS = {
  process: "#00f0ff",
  file: "#00ff88",
  socket: "#a855f7",
  memory: "#ffaa00",
  threat: "#ff0055",
  edge: "rgba(100, 140, 180, 0.35)",
  edgeThreat: "rgba(255, 0, 85, 0.75)",
  sliceHighlight: "#00f0ff",
  sliceEdge: "#ff0055"
};

// Initialize Application
window.addEventListener("DOMContentLoaded", () => {
  initCanvas();
  initWebSocket();
  startRenderLoop();
  fetchInitialState();
});

function initCanvas() {
  canvas = document.getElementById("graphCanvas");
  ctx = canvas.getContext("2d");

  function resize() {
    canvas.width = canvas.parentElement.clientWidth;
    canvas.height = canvas.parentElement.clientHeight;
    transform.x = canvas.width / 2;
    transform.y = canvas.height / 2;
  }
  window.addEventListener("resize", resize);
  resize();

  // Mouse Interactions: Dragging, Panning, Zooming
  canvas.addEventListener("mousedown", (e) => {
    const rect = canvas.getBoundingClientRect();
    const mx = (e.clientX - rect.left - transform.x) / transform.k;
    const my = (e.clientY - rect.top - transform.y) / transform.k;

    // Find clicked node
    let clicked = null;
    for (let i = nodes.length - 1; i >= 0; i--) {
      const n = nodes[i];
      const dx = n.x - mx;
      const dy = n.y - my;
      if (Math.hypot(dx, dy) < n.radius + 6) {
        clicked = n;
        break;
      }
    }

    if (clicked) {
      dragNode = clicked;
      selectedNode = clicked;
      showProvenanceBar(clicked);
      if (clicked.properties && clicked.properties.pid) {
        fetchProcessAssessment(clicked.properties.pid);
      }
    } else {
      isDragging = true;
      lastMouse = { x: e.clientX, y: e.clientY };
    }
  });

  window.addEventListener("mousemove", (e) => {
    if (dragNode) {
      const rect = canvas.getBoundingClientRect();
      dragNode.x = (e.clientX - rect.left - transform.x) / transform.k;
      dragNode.y = (e.clientY - rect.top - transform.y) / transform.k;
      dragNode.vx = 0;
      dragNode.vy = 0;
    } else if (isDragging) {
      transform.x += e.clientX - lastMouse.x;
      transform.y += e.clientY - lastMouse.y;
      lastMouse = { x: e.clientX, y: e.clientY };
    }
  });

  window.addEventListener("mouseup", () => {
    dragNode = null;
    isDragging = false;
  });

  canvas.addEventListener("wheel", (e) => {
    e.preventDefault();
    const factor = e.deltaY < 0 ? 1.1 : 0.9;
    transform.k = Math.max(0.2, Math.min(transform.k * factor, 3.5));
  });
}

// Simple Physics Simulation for Force-Directed Graph
function updatePhysics() {
  const repulsion = 1100;
  const linkDist = 70;
  const linkStrength = 0.05;
  const centerGravity = 0.008;

  for (let i = 0; i < nodes.length; i++) {
    const n1 = nodes[i];
    for (let j = i + 1; j < nodes.length; j++) {
      const n2 = nodes[j];
      const dx = n2.x - n1.x;
      const dy = n2.y - n1.y;
      const dist = Math.hypot(dx, dy) || 1;
      if (dist < 280) {
        const force = repulsion / (dist * dist);
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        n1.vx -= fx;
        n1.vy -= fy;
        n2.vx += fx;
        n2.vy += fy;
      }
    }

    n1.vx -= n1.x * centerGravity;
    n1.vy -= n1.y * centerGravity;
  }

  for (const edge of edges) {
    const s = nodeMap.get(edge.source);
    const t = nodeMap.get(edge.target);
    if (s && t) {
      const dx = t.x - s.x;
      const dy = t.y - s.y;
      const dist = Math.hypot(dx, dy) || 1;
      const force = (dist - linkDist) * linkStrength;
      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;
      s.vx += fx;
      s.vy += fy;
      t.vx -= fx;
      t.vy -= fy;
    }
  }

  const damping = 0.82;
  for (const n of nodes) {
    if (n === dragNode) continue;
    n.vx *= damping;
    n.vy *= damping;
    n.x += n.vx;
    n.y += n.vy;
  }
}

// Canvas Render Loop
function startRenderLoop() {
  function render() {
    pulseTimer += 0.05;
    updatePhysics();

    ctx.save();
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    ctx.translate(transform.x, transform.y);
    ctx.scale(transform.k, transform.k);

    drawGrid();

    // Draw Edges
    for (let i = 0; i < edges.length; i++) {
      const edge = edges[i];
      const s = nodeMap.get(edge.source);
      const t = nodeMap.get(edge.target);
      if (!s || !t) continue;

      const edgeKey = `${edge.source}->${edge.target}`;
      const isSliced = activeSlicedEdges.has(edgeKey);
      const isThreatEdge = (s.risk_score > 0.6 || t.risk_score > 0.6 || edge.edge_type === "memfd" || edge.edge_type === "unlink");

      ctx.beginPath();
      ctx.moveTo(s.x, s.y);
      ctx.lineTo(t.x, t.y);

      if (isSliced) {
        ctx.strokeStyle = "#ff0055";
        ctx.lineWidth = 3.0;
        ctx.shadowColor = "#ff0055";
        ctx.shadowBlur = 10;
      } else if (saliencyHeatmapEnabled) {
        // GNN Saliency gradient
        const saliency = edge.saliency_percentage || (isThreatEdge ? 85 : 25);
        ctx.strokeStyle = saliency > 70 ? "#ff0055" : (saliency > 40 ? "#ffaa00" : "#00f0ff");
        ctx.lineWidth = saliency > 70 ? 2.5 : 1.2;
      } else if (isThreatEdge) {
        ctx.strokeStyle = COLORS.edgeThreat;
        ctx.lineWidth = 2.0;
        ctx.shadowColor = COLORS.threat;
        ctx.shadowBlur = 6;
      } else {
        ctx.strokeStyle = COLORS.edge;
        ctx.lineWidth = 1.0;
        ctx.shadowBlur = 0;
      }
      ctx.stroke();
      ctx.shadowBlur = 0;

      // Syscall Label along edge
      if ((isThreatEdge || isSliced || saliencyHeatmapEnabled) && edge.syscall) {
        const midX = (s.x + t.x) / 2;
        const midY = (s.y + t.y) / 2;
        ctx.fillStyle = isSliced ? "#ffffff" : "#ff99bb";
        ctx.font = "9px 'JetBrains Mono', monospace";
        ctx.textAlign = "center";
        const label = edge.syscall.replace("sys_enter_", "") + (saliencyHeatmapEnabled ? ` [${Math.round(edge.saliency_percentage || 75)}%]` : "");
        ctx.fillText(label, midX, midY - 4);
      }
    }

    // Draw Nodes
    for (const n of nodes) {
      const isCritical = n.risk_score >= 0.70;
      const isSliced = activeSlicedNodes.has(n.id);
      const baseColor = isCritical ? COLORS.threat : (COLORS[n.type] || COLORS.process);
      const radius = n.radius || 10;

      if (isCritical || isSliced) {
        const pulse = Math.sin(pulseTimer * 3) * 4 + 6;
        ctx.beginPath();
        ctx.arc(n.x, n.y, radius + pulse, 0, Math.PI * 2);
        ctx.fillStyle = isSliced ? "rgba(0, 240, 255, 0.3)" : "rgba(255, 0, 85, 0.25)";
        ctx.fill();
      }

      ctx.beginPath();
      ctx.arc(n.x, n.y, radius, 0, Math.PI * 2);
      ctx.fillStyle = baseColor;
      ctx.shadowColor = baseColor;
      ctx.shadowBlur = (isCritical || isSliced) ? 16 : 6;
      ctx.fill();
      ctx.shadowBlur = 0;

      ctx.strokeStyle = selectedNode === n ? "#ffffff" : (isSliced ? "#00f0ff" : "rgba(255, 255, 255, 0.4)");
      ctx.lineWidth = (selectedNode === n || isSliced) ? 2.5 : 1;
      ctx.stroke();

      ctx.fillStyle = "#f0f4f8";
      ctx.font = (isCritical || isSliced) ? "bold 11px 'Inter', sans-serif" : "10px 'Inter', sans-serif";
      ctx.textAlign = "center";
      ctx.fillText(n.label, n.x, n.y + radius + 13);
    }

    ctx.restore();
    requestAnimationFrame(render);
  }
  requestAnimationFrame(render);
}

function drawGrid() {
  const size = 60;
  const left = -transform.x / transform.k - 100;
  const top = -transform.y / transform.k - 100;
  const right = (canvas.width - transform.x) / transform.k + 100;
  const bottom = (canvas.height - transform.y) / transform.k + 100;

  ctx.strokeStyle = "rgba(255, 255, 255, 0.02)";
  ctx.lineWidth = 1;
  ctx.beginPath();
  for (let x = Math.floor(left / size) * size; x < right; x += size) {
    ctx.moveTo(x, top);
    ctx.lineTo(x, bottom);
  }
  for (let y = Math.floor(top / size) * size; y < bottom; y += size) {
    ctx.moveTo(left, y);
    ctx.lineTo(right, y);
  }
  ctx.stroke();
}

function updateGraphData(graphData) {
  if (!graphData || !graphData.nodes) return;

  const newMap = new Map();
  for (const n of graphData.nodes) {
    let existing = nodeMap.get(n.id);
    if (!existing) {
      existing = {
        id: n.id,
        label: n.label,
        type: n.type,
        risk_score: n.risk_score || 0,
        properties: n.properties || {},
        x: (Math.random() - 0.5) * 200,
        y: (Math.random() - 0.5) * 200,
        vx: 0,
        vy: 0,
        radius: n.type === "process" ? 12 : 9
      };
      nodes.push(existing);
    } else {
      existing.label = n.label;
      existing.risk_score = n.risk_score || 0;
      existing.properties = n.properties || {};
    }
    newMap.set(n.id, existing);
  }

  const incomingIds = new Set(graphData.nodes.map(n => n.id));
  nodes = nodes.filter(n => incomingIds.has(n.id));
  nodeMap = newMap;
  edges = graphData.edges || [];

  document.getElementById("hudEntityCount").textContent = `${nodes.length} Nodes / ${edges.length} Edges`;
}

// WebSocket Connection
function initWebSocket() {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/ws/telemetry`;
  let ws;

  try {
    ws = new WebSocket(wsUrl);
    ws.onopen = () => {
      console.log("[KernelGuard] WebSocket telemetry connection active.");
    };
    ws.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload.nodes && payload.edges) {
          updateGraphData({ nodes: payload.nodes, edges: payload.edges });
        }
        if (payload.events) {
          updateEventTerminal(payload.events);
        }
        if (payload.latest_assessment) {
          updateThreatHUD(payload.latest_assessment);
        }
        if (payload.host_sniffer_active !== undefined) {
          updateHostSnifferBadge(payload.host_sniffer_active);
        }
      } catch (err) {
        console.error("WS Parse error", err);
      }
    };
    ws.onclose = () => {
      setTimeout(initWebSocket, 2000);
    };
    ws.onerror = () => ws.close();
  } catch (e) {
    setInterval(fetchInitialState, 1500);
  }
}

async function fetchInitialState() {
  try {
    const resGraph = await fetch("/api/graph");
    const graphData = await resGraph.json();
    updateGraphData(graphData);

    const resAssess = await fetch("/api/latest_assessment");
    const assessData = await resAssess.json();
    updateThreatHUD(assessData);

    const resEvents = await fetch("/api/events?limit=20");
    const eventsData = await resEvents.json();
    updateEventTerminal(eventsData);
  } catch (err) {
    console.error("Failed to fetch initial state:", err);
  }
}

function updateEventTerminal(events) {
  const terminal = document.getElementById("eventTerminal");
  if (!events || events.length === 0) return;

  totalEventsCaptured += events.length;
  document.getElementById("eventCountBadge").textContent = `${totalEventsCaptured} events captured`;

  terminal.innerHTML = events.slice(-15).reverse().map(ev => {
    const isThreat = ev.event_type === "EVENT_MEMFD_CREATE" || 
                     ev.event_type === "EVENT_MEM_PROTECT" || 
                     ev.event_type === "EVENT_FILE_UNLINK" || 
                     ev.event_type === "EVENT_PRIV_SETUID" ||
                     (ev.net_dport && [4444, 1337, 8080].includes(ev.net_dport));

    const timeStr = new Date(ev.timestamp_ns / 1e6).toISOString().substring(11, 23);
    const syscallName = (ev.raw_syscall || ev.event_type).replace("sys_enter_", "");
    const target = ev.target_path || (ev.net_daddr ? `${ev.net_daddr}:${ev.net_dport}` : (ev.mem_addr || "-"));

    return `
      <div class="log-entry ${isThreat ? 'flagged' : ''}">
        <span class="time">${timeStr}</span>
        <span class="syscall">${syscallName}</span>
        <span class="pid">${ev.comm}[${ev.pid}]</span>
        <span class="target">${escapeHtml(target)}</span>
      </div>
    `;
  }).join("");
}

function updateThreatHUD(assessment) {
  if (!assessment) return;
  currentAssessment = assessment;

  const scoreVal = document.getElementById("riskScoreVal");
  const threatBadge = document.getElementById("threatBadge");
  const riskCard = document.getElementById("riskCard");
  const graphPanel = document.getElementById("graphPanel");

  const score = assessment.composite_risk_score || 0;
  scoreVal.textContent = score.toFixed(2);

  const comp = assessment.component_scores || {};
  document.getElementById("scoreModelVal").textContent = (comp.gnn_transformer_model || 0).toFixed(2);
  document.getElementById("barModel").style.width = `${Math.min((comp.gnn_transformer_model || 0) * 100, 100)}%`;

  document.getElementById("scoreSemanticVal").textContent = (comp.syscall_semantics || 0).toFixed(2);
  document.getElementById("barSemantic").style.width = `${Math.min((comp.syscall_semantics || 0) * 100, 100)}%`;

  document.getElementById("scoreLineageVal").textContent = (comp.lineage_anomaly || 0).toFixed(2);
  document.getElementById("barLineage").style.width = `${Math.min((comp.lineage_anomaly || 0) * 100, 100)}%`;

  if (assessment.is_malicious) {
    scoreVal.style.color = "var(--red-alert)";
    threatBadge.className = "threat-badge critical";
    threatBadge.textContent = `${assessment.threat_classification} [${assessment.confidence}]`;
    riskCard.className = "risk-hud-card critical-threat";
    graphPanel.className = "panel alert-active";
    document.getElementById("mitigationStatusBadge").textContent = "THREAT ARMED • EXECUTE";
    document.getElementById("mitigationStatusBadge").style.color = "var(--red-alert)";
  } else {
    scoreVal.style.color = "var(--emerald-safe)";
    threatBadge.className = "threat-badge benign";
    threatBadge.textContent = "BENIGN SYSTEM ACTIVITY";
    riskCard.className = "risk-hud-card";
    graphPanel.className = "panel";
    document.getElementById("mitigationStatusBadge").textContent = "ENFORCEMENT READY";
    document.getElementById("mitigationStatusBadge").style.color = "var(--emerald-safe)";
  }

  const mitreContainer = document.getElementById("mitreContainer");
  const mitreTechs = assessment.mitre_attack_techniques || [];
  if (mitreTechs.length > 0) {
    mitreContainer.innerHTML = mitreTechs.map(m => `
      <div class="mitre-tag">
        <span class="id">${m.id}</span>
        <span>${escapeHtml(m.name)}</span>
      </div>
    `).join("");
  } else {
    mitreContainer.innerHTML = `<span style="font-size: 11px; color: var(--text-muted);">No malicious techniques detected. System baseline normal.</span>`;
  }

  const narrative = document.getElementById("explainNarrative");
  const causalList = document.getElementById("causalList");
  const reasons = assessment.causal_anomaly_explanations || [];

  if (assessment.is_malicious) {
    narrative.className = "explain-narrative critical";
    narrative.innerHTML = `<strong>⚠️ Malicious Sequence Detected:</strong> Process PID <code>${assessment.target_pid}</code> triggered high-risk anomaly thresholds across temporal GNN structure and kernel syscall semantics.`;
    causalList.innerHTML = reasons.map(r => `<li>${escapeHtml(r)}</li>`).join("");
  } else {
    narrative.className = "explain-narrative";
    narrative.innerHTML = "System baseline is stable. KernelGuard continuously monitors process lineage, file modifications, memory permissions, and network sockets via kernel tracepoints.";
    causalList.innerHTML = `<li style="color: var(--text-muted);">All syscall patterns in current temporal window match benign operational baselines.</li>`;
  }

  const actionContent = document.getElementById("actionBoxContent");
  const recs = assessment.recommended_actions || [];
  if (recs.length > 0) {
    actionContent.innerHTML = recs.map(r => `<div>• ${escapeHtml(r)}</div>`).join("");
  }
}

// Feature 1: Host OS Sniffer Toggle
async function toggleHostSniffer() {
  try {
    const res = await fetch("/api/host_sniffer/toggle", { method: "POST" });
    const data = await res.json();
    updateHostSnifferBadge(data.host_sniffer_active);
  } catch (e) {
    console.error("Host sniffer toggle error", e);
  }
}

function updateHostSnifferBadge(active) {
  hostSnifferActive = active;
  const btn = document.getElementById("btnHostSnifferToggle");
  const hud = document.getElementById("hudHostSniffer");
  if (active) {
    btn.innerHTML = `<span>🖥️ Host OS Sniffer: LIVE</span>`;
    btn.classList.add("active-toggle");
    hud.textContent = "LIVE HOST (psutil)";
    hud.style.color = "var(--emerald-safe)";
  } else {
    btn.innerHTML = `<span>🖥️ Host OS Sniffer: OFF</span>`;
    btn.classList.remove("active-toggle");
    hud.textContent = "DISABLED";
    hud.style.color = "var(--text-muted)";
  }
}

// Feature 2: In-Kernel Active Mitigation Execution
async function executeActiveMitigation() {
  if (!currentAssessment || !currentAssessment.target_pid) {
    alert("No active threat to mitigate.");
    return;
  }

  const pid = currentAssessment.target_pid;
  const threatClass = currentAssessment.threat_classification || "Detected Malware";
  const btn = document.getElementById("btnMitigateAction");
  btn.disabled = true;
  btn.innerHTML = `<span>⏳ Emitting In-Kernel bpf_send_signal(SIGKILL)...</span>`;

  try {
    const res = await fetch("/api/mitigate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pid: pid, threat_class: threatClass })
    });
    const result = await res.json();
    console.log("[KernelGuard Mitigation]", result);

    document.getElementById("actionBoxContent").innerHTML = `
      <div style="color: var(--emerald-safe); font-weight: bold;">
        ✓ Autonomous Mitigation Enforced (${result.mitigation_latency_ms} ms)
      </div>
      ${result.actions_executed.map(a => `<div>• ${escapeHtml(a)}</div>`).join("")}
    `;

    setTimeout(() => {
      btn.disabled = false;
      btn.innerHTML = `<span>⚡ Execute Autonomous In-Kernel Mitigation (bpf_send_signal)</span>`;
      document.getElementById("mitigationStatusBadge").textContent = "THREAT NEUTRALIZED";
      document.getElementById("mitigationStatusBadge").style.color = "var(--emerald-safe)";
    }, 1500);
  } catch (err) {
    console.error("Mitigation failed", err);
    btn.disabled = false;
  }
}

// Feature 3: Provenance Slicing
function showProvenanceBar(node) {
  const bar = document.getElementById("graphProvenanceBar");
  bar.style.display = "flex";
  document.getElementById("provenanceNodeDesc").textContent = `Selected: ${node.label} [${node.type.toUpperCase()}]`;
}

async function triggerBackwardSlice() {
  if (!selectedNode) return;
  try {
    const res = await fetch(`/api/provenance/backward/${encodeURIComponent(selectedNode.id)}`);
    const data = await res.json();
    applySliceHighlight(data);
    alert(`Backward Slicing: ${data.narrative}`);
  } catch (e) {
    console.error("Backward slice error", e);
  }
}

async function triggerForwardSlice() {
  if (!selectedNode) return;
  try {
    const res = await fetch(`/api/provenance/forward/${encodeURIComponent(selectedNode.id)}`);
    const data = await res.json();
    applySliceHighlight(data);
    alert(`Forward Blast Radius: ${data.narrative}`);
  } catch (e) {
    console.error("Forward slice error", e);
  }
}

function applySliceHighlight(sliceData) {
  activeSlicedNodes.clear();
  activeSlicedEdges.clear();

  if (sliceData.slice_nodes) {
    for (const n of sliceData.slice_nodes) {
      activeSlicedNodes.add(n.id);
    }
  }
  if (sliceData.slice_edges) {
    for (const e of sliceData.slice_edges) {
      activeSlicedEdges.add(`${e.source}->${e.target}`);
    }
  }
}

function clearProvenanceSlice() {
  activeSlicedNodes.clear();
  activeSlicedEdges.clear();
  document.getElementById("graphProvenanceBar").style.display = "none";
  selectedNode = null;
}

// Feature 4: GNN Saliency Heatmap Toggle
async function toggleSaliencyHeatmap() {
  saliencyHeatmapEnabled = !saliencyHeatmapEnabled;
  const btn = document.getElementById("btnSaliencyToggle");
  if (saliencyHeatmapEnabled) {
    btn.innerHTML = `<span>🧠 GNN Saliency: ON</span>`;
    btn.classList.add("active-toggle");

    // Fetch saliency for active highlighted pid
    const pid = currentAssessment ? currentAssessment.target_pid : 1102;
    try {
      const res = await fetch(`/api/explainer/${pid}`);
      const expl = await res.json();
      if (expl.edge_saliency) {
        for (const item of expl.edge_saliency) {
          for (const edge of edges) {
            if (edge.source === item.source && edge.target === item.target) {
              edge.saliency_percentage = item.saliency_percentage;
            }
          }
        }
      }
    } catch (e) {
      console.error("GNN Explainer fetch error", e);
    }
  } else {
    btn.innerHTML = `<span>🧠 GNN Saliency: OFF</span>`;
    btn.classList.remove("active-toggle");
  }
}

// Feature 6: Interactive Terminal Simulator Drawer
function toggleTerminalDrawer() {
  const drawer = document.getElementById("terminalDrawer");
  drawer.classList.toggle("expanded");
  if (drawer.classList.contains("expanded")) {
    document.getElementById("terminalCmdInput").focus();
  }
}

function handleTerminalKey(event) {
  if (event.key === "Enter") {
    const input = document.getElementById("terminalCmdInput");
    const cmd = input.value.trim();
    if (!cmd) return;
    input.value = "";
    executeTerminal(cmd);
  }
}

async function executeTerminal(cmd) {
  const view = document.getElementById("terminalOutput");
  view.innerHTML += `\n\n<span style="color: var(--cyan-accent);">> ${escapeHtml(cmd)}</span>`;
  view.scrollTop = view.scrollHeight;

  try {
    const res = await fetch("/api/terminal/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ command: cmd })
    });
    const data = await res.json();
    view.innerHTML += `\n<span style="color: #c9d8ea;">${escapeHtml(data.output)}</span>`;
    view.scrollTop = view.scrollHeight;
  } catch (err) {
    view.innerHTML += `\n<span style="color: var(--red-alert);">Execution error: ${err}</span>`;
  }
}

// Feature 7: LaTeX Exporter
async function openLatexModal() {
  const modal = document.getElementById("latexModal");
  const box = document.getElementById("latexSnippetBox");
  modal.style.display = "flex";
  try {
    const res = await fetch("/api/export/latex");
    const text = await res.text();
    box.textContent = text;
  } catch (err) {
    box.textContent = `Error loading LaTeX: ${err}`;
  }
}

function closeLatexModal() {
  document.getElementById("latexModal").style.display = "none";
}

function copyLatexSnippet() {
  const text = document.getElementById("latexSnippetBox").textContent;
  navigator.clipboard.writeText(text);
  alert("LaTeX snippets successfully copied to clipboard!");
}

function downloadLatexFile() {
  const text = document.getElementById("latexSnippetBox").textContent;
  const blob = new Blob([text], { type: "text/plain" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "kernelguard_publication_tables.tex";
  a.click();
}

// Scenarios & Reset
async function runScenario(name) {
  document.querySelectorAll(".btn-scenario").forEach(b => b.classList.remove("active-attack"));
  const btn = document.getElementById(`btn${name.charAt(0).toUpperCase() + name.slice(1)}`);
  if (btn && name !== "benign") btn.classList.add("active-attack");

  try {
    const res = await fetch(`/api/scenario/${name}`, { method: "POST" });
    const data = await res.json();
    setTimeout(async () => {
      const resAssess = await fetch("/api/latest_assessment");
      const assessData = await resAssess.json();
      updateThreatHUD(assessData);
    }, 400);
  } catch (err) {
    console.error("Failed to run scenario:", err);
  }
}

async function resetGraph() {
  document.querySelectorAll(".btn-scenario").forEach(b => b.classList.remove("active-attack"));
  clearProvenanceSlice();
  try {
    await fetch("/api/reset", { method: "POST" });
    nodes = [];
    edges = [];
    nodeMap.clear();
    fetchInitialState();
  } catch (err) {
    console.error("Failed to reset graph:", err);
  }
}

async function fetchProcessAssessment(pid) {
  try {
    const res = await fetch(`/api/assessment/${pid}`);
    const data = await res.json();
    updateThreatHUD(data);
  } catch (e) {
    console.error("Assessment fetch error", e);
  }
}

function openBenchmarkModal() {
  document.getElementById("benchmarkModal").style.display = "flex";
}

function closeBenchmarkModal() {
  document.getElementById("benchmarkModal").style.display = "none";
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
