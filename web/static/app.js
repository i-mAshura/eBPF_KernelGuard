/**
 * KernelGuard Frontend Controller & Force-Directed Graph Visualizer
 * High-performance canvas-based graph engine with dynamic particle physics,
 * WebSocket real-time telemetry streaming, and MITRE ATT&CK explainability HUD.
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

// Application State
let activeScenario = null;
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
  edgeThreat: "rgba(255, 0, 85, 0.75)"
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
  const repulsion = 1200;
  const linkDist = 70;
  const linkStrength = 0.05;
  const centerGravity = 0.008;

  // Repulsion between nodes
  for (let i = 0; i < nodes.length; i++) {
    const n1 = nodes[i];
    for (let j = i + 1; j < nodes.length; j++) {
      const n2 = nodes[j];
      const dx = n2.x - n1.x;
      const dy = n2.y - n1.y;
      const dist = Math.hypot(dx, dy) || 1;
      if (dist < 300) {
        const force = repulsion / (dist * dist);
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        n1.vx -= fx;
        n1.vy -= fy;
        n2.vx += fx;
        n2.vy += fy;
      }
    }

    // Centering force
    n1.vx -= n1.x * centerGravity;
    n1.vy -= n1.y * centerGravity;
  }

  // Edge link attraction
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

  // Update positions with damping
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

    // Apply viewport transform
    ctx.translate(transform.x, transform.y);
    ctx.scale(transform.k, transform.k);

    // Draw Subtle Grid
    drawGrid();

    // Draw Edges
    for (const edge of edges) {
      const s = nodeMap.get(edge.source);
      const t = nodeMap.get(edge.target);
      if (!s || !t) continue;

      const isThreatEdge = (s.risk_score > 0.6 || t.risk_score > 0.6 || edge.edge_type === "memfd" || edge.edge_type === "unlink");
      ctx.beginPath();
      ctx.moveTo(s.x, s.y);
      ctx.lineTo(t.x, t.y);

      if (isThreatEdge) {
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

      // Syscall Label along the edge if threat or highlighted
      if (isThreatEdge && edge.syscall) {
        const midX = (s.x + t.x) / 2;
        const midY = (s.y + t.y) / 2;
        ctx.fillStyle = "#ff99bb";
        ctx.font = "9px 'JetBrains Mono', monospace";
        ctx.textAlign = "center";
        ctx.fillText(edge.syscall.replace("sys_enter_", ""), midX, midY - 4);
      }
    }

    // Draw Nodes
    for (const n of nodes) {
      const isCritical = n.risk_score >= 0.70;
      const baseColor = isCritical ? COLORS.threat : (COLORS[n.type] || COLORS.process);
      const radius = n.radius || 10;

      // Pulsing outer glow for threats
      if (isCritical) {
        const pulse = Math.sin(pulseTimer * 3) * 4 + 6;
        ctx.beginPath();
        ctx.arc(n.x, n.y, radius + pulse, 0, Math.PI * 2);
        ctx.fillStyle = "rgba(255, 0, 85, 0.25)";
        ctx.fill();
      }

      // Main Node Circle
      ctx.beginPath();
      ctx.arc(n.x, n.y, radius, 0, Math.PI * 2);
      ctx.fillStyle = baseColor;
      ctx.shadowColor = baseColor;
      ctx.shadowBlur = isCritical ? 15 : 6;
      ctx.fill();
      ctx.shadowBlur = 0;

      // Border ring
      ctx.strokeStyle = selectedNode === n ? "#ffffff" : "rgba(255, 255, 255, 0.4)";
      ctx.lineWidth = selectedNode === n ? 2.5 : 1;
      ctx.stroke();

      // Node Label
      ctx.fillStyle = "#f0f4f8";
      ctx.font = isCritical ? "bold 11px 'Inter', sans-serif" : "10px 'Inter', sans-serif";
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

// Ingest Graph Data
function updateGraphData(graphData) {
  if (!graphData || !graphData.nodes) return;

  const currentIds = new Set(nodes.map(n => n.id));
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

  // Filter out removed nodes
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
      console.log("[KernelGuard] WebSocket connected to telemetry stream.");
      document.getElementById("hudEbpfMode").textContent = "eBPF RingBuffer (Active)";
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
      } catch (err) {
        console.error("WS Parse error", err);
      }
    };
    ws.onclose = () => {
      console.warn("[KernelGuard] WebSocket disconnected. Retrying in 2s...");
      setTimeout(initWebSocket, 2000);
    };
    ws.onerror = () => {
      ws.close();
    };
  } catch (e) {
    console.error("WS init exception, falling back to polling", e);
    setInterval(fetchInitialState, 1500);
  }
}

// Fallback REST fetch
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

// Update Event Terminal
function updateEventTerminal(events) {
  const terminal = document.getElementById("eventTerminal");
  if (!events || events.length === 0) return;

  totalEventsCaptured += events.length;
  document.getElementById("eventCountBadge").textContent = `${totalEventsCaptured} events captured`;

  // Render recent 15 entries
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

// Update Threat Intelligence HUD
function updateThreatHUD(assessment) {
  if (!assessment) return;
  currentAssessment = assessment;

  const scoreVal = document.getElementById("riskScoreVal");
  const threatBadge = document.getElementById("threatBadge");
  const riskCard = document.getElementById("riskCard");
  const graphPanel = document.getElementById("graphPanel");

  const score = assessment.composite_risk_score || 0;
  scoreVal.textContent = score.toFixed(2);

  // Component breakdown
  const comp = assessment.component_scores || {};
  const mScore = comp.gnn_transformer_model || 0;
  const sScore = comp.syscall_semantics || 0;
  const lScore = comp.lineage_anomaly || 0;

  document.getElementById("scoreModelVal").textContent = mScore.toFixed(2);
  document.getElementById("barModel").style.width = `${Math.min(mScore * 100, 100)}%`;

  document.getElementById("scoreSemanticVal").textContent = sScore.toFixed(2);
  document.getElementById("barSemantic").style.width = `${Math.min(sScore * 100, 100)}%`;

  document.getElementById("scoreLineageVal").textContent = lScore.toFixed(2);
  document.getElementById("barLineage").style.width = `${Math.min(lScore * 100, 100)}%`;

  // Status Styling
  if (assessment.is_malicious) {
    scoreVal.style.color = "var(--red-alert)";
    threatBadge.className = "threat-badge critical";
    threatBadge.textContent = `${assessment.threat_classification} [${assessment.confidence}]`;
    riskCard.className = "risk-hud-card critical-threat";
    graphPanel.className = "panel alert-active";
  } else {
    scoreVal.style.color = "var(--emerald-safe)";
    threatBadge.className = "threat-badge benign";
    threatBadge.textContent = "BENIGN SYSTEM ACTIVITY";
    riskCard.className = "risk-hud-card";
    graphPanel.className = "panel";
  }

  // MITRE ATT&CK Badges
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

  // Causal Explanations
  const narrative = document.getElementById("explainNarrative");
  const causalList = document.getElementById("causalList");
  const reasons = assessment.causal_anomaly_explanations || [];

  if (assessment.is_malicious) {
    narrative.className = "explain-narrative critical";
    narrative.innerHTML = `<strong>⚠️ Malicious Sequence Detected:</strong> Process tree for PID <code>${assessment.target_pid}</code> triggered high-risk anomaly thresholds across temporal GNN structure and kernel syscall semantics.`;
    
    causalList.innerHTML = reasons.map(r => `<li>${escapeHtml(r)}</li>`).join("");
  } else {
    narrative.className = "explain-narrative";
    narrative.innerHTML = "System baseline is stable. KernelGuard continuously monitors process lineage, file modifications, memory permissions, and network sockets via kernel tracepoints.";
    causalList.innerHTML = `<li style="color: var(--text-muted);">All syscall patterns in current temporal window match benign operational baselines.</li>`;
  }

  // Recommendations
  const actionContent = document.getElementById("actionBoxContent");
  const recs = assessment.recommended_actions || [];
  if (recs.length > 0) {
    actionContent.innerHTML = recs.map(r => `<div>• ${escapeHtml(r)}</div>`).join("");
  }
}

// Scenario Trigger
async function runScenario(name) {
  // Highlight active button
  document.querySelectorAll(".btn-scenario").forEach(b => b.classList.remove("active-attack"));
  const btn = document.getElementById(`btn${name.charAt(0).toUpperCase() + name.slice(1)}`);
  if (btn && name !== "benign") btn.classList.add("active-attack");

  try {
    const res = await fetch(`/api/scenario/${name}`, { method: "POST" });
    const data = await res.json();
    console.log(`[KernelGuard] Executed scenario: ${name}`, data);

    // Immediately fetch updated assessment
    setTimeout(async () => {
      const resAssess = await fetch("/api/latest_assessment");
      const assessData = await resAssess.json();
      updateThreatHUD(assessData);
    }, 400);
  } catch (err) {
    console.error("Failed to run scenario:", err);
  }
}

// Reset Graph
async function resetGraph() {
  document.querySelectorAll(".btn-scenario").forEach(b => b.classList.remove("active-attack"));
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

// Specific process assessment
async function fetchProcessAssessment(pid) {
  try {
    const res = await fetch(`/api/assessment/${pid}`);
    const data = await res.json();
    updateThreatHUD(data);
  } catch (e) {
    console.error("Assessment fetch error", e);
  }
}

// Modal Controls
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
