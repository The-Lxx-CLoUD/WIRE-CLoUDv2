(() => {
  "use strict";

  const socket = io();
  const filterEngine = window.WireCloudFilters;

  
  const btnCaptureSettings = document.getElementById("btnCaptureSettings");
  const settingsLabel = document.getElementById("settingsLabel");
  const btnStart = document.getElementById("btnStart");
  const btnStop = document.getElementById("btnStop");
  const btnClear = document.getElementById("btnClear");
  const btnExport = document.getElementById("btnExport");
  const btnTheme = document.getElementById("btnTheme");
  const btnStats = document.getElementById("btnStats");
  const themeIcon = document.getElementById("themeIcon");
  const statusDot = document.getElementById("statusDot");
  const packetBody = document.getElementById("packetBody");
  const emptyState = document.getElementById("emptyState");
  const liveSearch = document.getElementById("liveSearch");
  const filterStatus = document.getElementById("filterStatus");
  const protoChips = document.getElementById("protoChips");
  const btnAutoscroll = document.getElementById("btnAutoscroll");
  const statTotal = document.getElementById("statTotal");
  const statBytes = document.getElementById("statBytes");
  const statPps = document.getElementById("statPps");
  const detailTree = document.getElementById("detailTree");
  const hexDump = document.getElementById("hexDump");
  const footInterface = document.getElementById("footInterface");
  const footFilter = document.getElementById("footFilter");
  const pulseCanvas = document.getElementById("pulse");
  const btnFollowStream = document.getElementById("btnFollowStream");

  const setupModal = document.getElementById("setupModal");
  const modalIface = document.getElementById("modalIface");
  const modalFilter = document.getElementById("modalFilter");
  const modalStart = document.getElementById("modalStart");
  const modalSkip = document.getElementById("modalSkip");
  const modalPresets = document.querySelectorAll(".preset-chip");

  const statsModal = document.getElementById("statsModal");
  const btnStatsClose = document.getElementById("btnStatsClose");
  const hierarchyTree = document.getElementById("hierarchyTree");
  const conversationsBody = document.getElementById("conversationsBody");
  const statsTabs = document.querySelectorAll(".stats-tab");

  const streamModal = document.getElementById("streamModal");
  const btnStreamClose = document.getElementById("btnStreamClose");
  const streamTitle = document.getElementById("streamTitle");
  const streamBody = document.getElementById("streamBody");

  const MAX_ROWS = 4000;
  const RENDER_INTERVAL_MS = 120;

  let packets = [];
  let pendingQueue = [];
  let selectedId = null;
  let selectedProtocol = null;
  let activeProto = null;
  let running = false;
  let autoScroll = true;
  let lastPacketCount = 0;
  let ppsHistory = new Array(60).fill(0);
  let protoCounts = {};
  let selectedInterface = "";
  let selectedFilter = "";
  let displayPredicate = () => true;

  const PROTOS = ["TCP", "UDP", "DNS", "HTTP", "TLS", "ICMP", "ARP", "IPv6",
    "DHCP", "NTP", "SSH", "FTP", "SMTP", "SNMP", "MDNS", "QUIC"];
  const TCP_BASED_PROTOS = new Set([
    "TCP", "HTTP", "TLS", "FTP", "SSH", "TELNET", "SMTP", "POP3", "IMAP", "SMB",
  ]);

  function initTheme() {
    const saved = localStorage.getItem("wc-theme") ||
      document.documentElement.getAttribute("data-theme") || "dark";
    applyTheme(saved);
    btnTheme.addEventListener("click", () => {
      const current = document.documentElement.getAttribute("data-theme");
      applyTheme(current === "dark" ? "light" : "dark");
    });
  }
  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("wc-theme", theme);
    themeIcon.textContent = theme === "dark" ? "☀" : "☾";
  }

  function init() {
    initTheme();
    buildProtoChips();
    bindEvents();
    loadInterfacesInto(modalIface);
    drawPulse();
    setInterval(pollStats, 1000);
    setInterval(flushPendingRows, RENDER_INTERVAL_MS);
    openSetupModal(); 
  }

  function buildProtoChips() {
    protoChips.innerHTML = "";
    PROTOS.forEach((p) => {
      protoCounts[p] = 0;
      const el = document.createElement("span");
      el.className = "proto-chip";
      el.dataset.proto = p;
      el.innerHTML = `${p} <span class="n" data-count="${p}">0</span>`;
      el.addEventListener("click", () => toggleProto(p, el));
      protoChips.appendChild(el);
    });
  }

  function toggleProto(p, el) {
    const wasActive = el.classList.contains("active");
    [...protoChips.children].forEach((c) => c.classList.remove("active"));
    activeProto = wasActive ? null : p;
    if (!wasActive) el.classList.add("active");
    renderTable();
  }

  async function loadInterfacesInto(selectEl) {
    try {
      const res = await fetch("/api/interfaces");
      const data = await res.json();
      selectEl.innerHTML = "";
      if (data.ok && data.interfaces.length) {
        data.interfaces.forEach((i) => {
          const opt = document.createElement("option");
          opt.value = i.id;
          opt.textContent = i.name;
          selectEl.appendChild(opt);
        });
        selectedInterface = selectEl.value;
      } else {
        selectEl.innerHTML = "<option value=''>No interfaces found</option>";
      }
    } catch (e) {
      selectEl.innerHTML = "<option value=''>Error loading interfaces</option>";
    }
  }

  function bindEvents() {
    btnStart.addEventListener("click", startCapture);
    btnStop.addEventListener("click", stopCapture);
    btnClear.addEventListener("click", clearCapture);
    btnExport.addEventListener("click", () => { window.location = "/api/export"; });
    document.getElementById("btnSaveSession").addEventListener("click", saveSession);
    liveSearch.addEventListener("input", debounce(applyDisplayFilter, 150));
    btnAutoscroll.addEventListener("click", () => {
      autoScroll = !autoScroll;
      btnAutoscroll.classList.toggle("active", autoScroll);
    });
    btnCaptureSettings.addEventListener("click", () => {
      if (running) {
        alert("Stop the current capture before changing interface/filter.\nقبل از تغییر تنظیمات، ابتدا ضبط جاری را متوقف کنید.");
        return;
      }
      openSetupModal();
    });

    
    modalStart.addEventListener("click", () => {
      selectedInterface = modalIface.value;
      selectedFilter = modalFilter.value.trim();
      closeSetupModal();
      updateSettingsLabel();
      startCapture();
    });
    modalSkip.addEventListener("click", () => {
      selectedInterface = modalIface.value;
      selectedFilter = modalFilter.value.trim();
      closeSetupModal();
      updateSettingsLabel();
    });
    modalPresets.forEach((chip) => {
      chip.addEventListener("click", () => {
        modalPresets.forEach((c) => c.classList.remove("active"));
        chip.classList.add("active");
        modalFilter.value = chip.dataset.filter;
      });
    });

    
    btnStats.addEventListener("click", openStatsModal);
    btnStatsClose.addEventListener("click", () => statsModal.classList.add("hidden"));
    statsTabs.forEach((tab) => {
      tab.addEventListener("click", () => {
        statsTabs.forEach((t) => t.classList.remove("active"));
        tab.classList.add("active");
        document.querySelectorAll(".stats-pane").forEach((p) => p.classList.add("is-hidden"));
        document.getElementById(tab.dataset.pane).classList.remove("is-hidden");
      });
    });

    
    btnFollowStream.addEventListener("click", followStream);
    btnStreamClose.addEventListener("click", () => streamModal.classList.add("hidden"));

    initSplitters();
  }

  function openSetupModal() {
    modalFilter.value = selectedFilter;
    setupModal.classList.remove("hidden");
  }
  function closeSetupModal() {
    setupModal.classList.add("hidden");
  }

  function updateSettingsLabel() {
    const ifaceName = selectedInterface || "(default)";
    settingsLabel.textContent = ifaceName + (selectedFilter ? "  ·  " + selectedFilter : "");
  }

  async function startCapture() {
    const res = await fetch("/api/capture/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ interface: selectedInterface, filter: selectedFilter }),
    });
    const data = await res.json();
    if (data.ok) {
      running = true;
      statusDot.classList.add("live");
      btnStart.disabled = true;
      btnStop.disabled = false;
      footInterface.textContent = "Interface: " + (selectedInterface || "default");
      footFilter.textContent = "Filter: " + (selectedFilter || "none");
      updateSettingsLabel();
    } else {
      alert(data.message || "Could not start capture");
    }
  }

  async function stopCapture() {
    const res = await fetch("/api/capture/stop", { method: "POST" });
    const data = await res.json();
    if (data.ok) {
      running = false;
      statusDot.classList.remove("live");
      btnStart.disabled = false;
      btnStop.disabled = true;
    }
  }

  async function clearCapture() {
    await fetch("/api/capture/clear", { method: "POST" });
    packets = [];
    pendingQueue = [];
    selectedId = null;
    selectedProtocol = null;
    Object.keys(protoCounts).forEach((k) => protoCounts[k] = 0);
    updateChipCounts();
    renderTable();
    detailTree.innerHTML = '<div class="placeholder">Select a packet to inspect its layers.</div>';
    hexDump.innerHTML = '<span class="placeholder">— — —</span>';
    btnFollowStream.classList.add("is-hidden");
  }

  async function saveSession() {
    const res = await fetch("/api/session/save", { method: "POST" });
    const data = await res.json();
    if (data.ok) {
      alert("Session saved: " + data.session + "\nView it in the PHP report dashboard (php/index.php).");
    } else {
      alert(data.error || "Nothing to save yet — capture some packets first.");
    }
  }

  socket.on("packet", (pkt) => {
    packets.push(pkt);
    if (packets.length > MAX_ROWS) packets.shift();
    if (matchesFilters(pkt)) pendingQueue.push(pkt);

    protoCounts[pkt.protocol] = (protoCounts[pkt.protocol] || 0) + 1;
  });

  socket.on("capture_error", (err) => {
    running = false;
    statusDot.classList.remove("live");
    btnStart.disabled = false;
    btnStop.disabled = true;
    alert("Capture error: " + err.message +
      "\n\nRun WIRE-CLOUD as Administrator (Windows) or with sudo (Linux).");
  });

  function applyDisplayFilter() {
    const expr = liveSearch.value.trim();
    displayPredicate = filterEngine.makePredicate(expr);
    filterStatus.textContent = expr ? "filter active" : "";
    renderTable();
  }

  function matchesFilters(pkt) {
    if (activeProto && pkt.protocol !== activeProto) return false;
    return displayPredicate(pkt);
  }

  function rowHTML(pkt) {
    const tip = tooltipFor(pkt);
    return `<tr data-id="${pkt.id}" data-proto="${pkt.protocol}" class="flash" title="${escapeHtml(tip)}">
      <td>${pkt.id}</td>
      <td>${pkt.time.toFixed(6)}</td>
      <td title="${escapeHtml(pkt.src)}">${escapeHtml(pkt.src)}${pkt.sport ? ":" + pkt.sport : ""}</td>
      <td title="${escapeHtml(pkt.dst)}">${escapeHtml(pkt.dst)}${pkt.dport ? ":" + pkt.dport : ""}</td>
      <td><span class="proto-tag">${pkt.protocol}</span></td>
      <td>${pkt.length}</td>
      <td class="col-info" title="${escapeHtml(pkt.info)}">${escapeHtml(pkt.info)}</td>
    </tr>`;
  }

  function tooltipFor(pkt) {
    const bits = [pkt.info];
    if (pkt.http_host) bits.push("Host: " + pkt.http_host);
    if (pkt.dns_qname) bits.push("Query: " + pkt.dns_qname);
    if (pkt.tls_sni) bits.push("SNI: " + pkt.tls_sni);
    return bits.filter(Boolean).join(" · ");
  }

  function flushPendingRows() {
    if (pendingQueue.length === 0) return;
    const shouldStick = autoScroll && isScrolledToBottom();
    const html = pendingQueue.map(rowHTML).join("");
    pendingQueue = [];

    packetBody.insertAdjacentHTML("beforeend", html);
    while (packetBody.children.length > MAX_ROWS) {
      packetBody.removeChild(packetBody.firstChild);
    }
    emptyState.style.display = packetBody.children.length ? "none" : "flex";
    updateChipCounts();

    if (shouldStick) {
      document.getElementById("paneList").scrollTop = 999999999;
    }
  }

  function updateChipCounts() {
    PROTOS.forEach((p) => {
      const el = protoChips.querySelector(`.n[data-count="${p}"]`);
      if (el) el.textContent = protoCounts[p] || 0;
    });
  }

  function renderTable() {
    packetBody.innerHTML = "";
    const filtered = packets.filter(matchesFilters);
    emptyState.style.display = filtered.length ? "none" : "flex";
    packetBody.insertAdjacentHTML("beforeend", filtered.map(rowHTML).join(""));
  }

  packetBody.addEventListener("click", (e) => {
    const tr = e.target.closest("tr");
    if (!tr) return;
    selectPacket(parseInt(tr.dataset.id, 10), tr.dataset.proto);
  });

  async function selectPacket(id, proto) {
    selectedId = id;
    selectedProtocol = proto;
    [...packetBody.children].forEach((tr) => {
      tr.classList.toggle("selected", parseInt(tr.dataset.id, 10) === id);
    });
    btnFollowStream.classList.toggle("is-hidden", !TCP_BASED_PROTOS.has(proto));
    const res = await fetch(`/api/packet/${id}`);
    const data = await res.json();
    if (!data.ok) return;
    renderDetail(data.detail);
  }

  function renderDetail(detail) {
    detailTree.innerHTML = detail.layers.map((layer) => `
      <div class="layer-block">
        <div class="layer-head">▸ ${layer.layer}</div>
        ${layer.fields.map(f => `<div class="layer-field"><b>${escapeHtml(f.name)}</b>: ${escapeHtml(f.value)}</div>`).join("")}
      </div>
    `).join("");

    hexDump.innerHTML = detail.hex.map((line) =>
      `<span class="hex-offset">${line.offset}</span>  <span class="hex-bytes">${line.hex.padEnd(47, " ")}</span>  <span class="hex-ascii">${escapeHtml(line.ascii)}</span>`
    ).join("\n");
  }

  async function followStream() {
    if (selectedId == null) return;
    const res = await fetch(`/api/stream/${selectedId}`);
    const data = await res.json();
    if (!data.ok) {
      alert(data.error || "Could not reassemble this TCP stream.");
      return;
    }
    const s = data.stream;
    streamTitle.textContent = `TCP Stream — client ${s.client} ⇄ server ${s.server}`;
    if (s.empty) {
      streamBody.innerHTML = '<div class="placeholder">No payload data captured for this stream (headers/ACKs only).</div>';
    } else {
      streamBody.innerHTML = s.blocks.map((b) => `
        <div class="stream-block stream-${b.direction}">
          <div class="stream-dir">${b.direction === "client" ? "▶ " + s.client : "◀ " + s.server} <span class="stream-bytes">${b.bytes} B</span></div>
          <pre>${escapeHtml(b.text)}</pre>
        </div>
      `).join("");
    }
    streamModal.classList.remove("hidden");
  }

  async function openStatsModal() {
    statsModal.classList.remove("hidden");
    await refreshStats();
  }

  async function refreshStats() {
    const [hRes, cRes] = await Promise.all([
      fetch("/api/hierarchy"), fetch("/api/conversations"),
    ]);
    const hData = await hRes.json();
    const cData = await cRes.json();
    if (hData.ok) renderHierarchy(hData.hierarchy);
    if (cData.ok) renderConversations(cData.conversations);
  }

  function renderHierarchy(nodes) {
    hierarchyTree.innerHTML = renderHierarchyLevel(nodes, 0);
  }
  function renderHierarchyLevel(nodes, depth) {
    if (!nodes || !nodes.length) {
      return depth === 0 ? '<div class="placeholder">No traffic captured yet.</div>' : "";
    }
    return nodes.map((n) => `
      <div class="hierarchy-row" style="padding-left:${depth * 18}px">
        <span class="hierarchy-name">${escapeHtml(n.name)}</span>
        <span class="hierarchy-count">${n.count} pkt</span>
        <span class="hierarchy-bytes">${formatBytes(n.bytes)}</span>
      </div>
      ${renderHierarchyLevel(n.children, depth + 1)}
    `).join("");
  }

  function renderConversations(convs) {
    if (!convs.length) {
      conversationsBody.innerHTML = '<tr><td colspan="5" class="placeholder">No traffic captured yet.</td></tr>';
      return;
    }
    conversationsBody.innerHTML = convs.map((c) => `
      <tr>
        <td class="mono">${escapeHtml(c.a)}</td>
        <td class="mono">${escapeHtml(c.b)}</td>
        <td>${c.packets}</td>
        <td>${formatBytes(c.bytes)}</td>
        <td>${c.protocols.map(p => `<span class="proto-tag">${escapeHtml(p)}</span>`).join(" ")}</td>
      </tr>
    `).join("");
  }

  async function pollStats() {
    try {
      const res = await fetch("/api/stats");
      const data = await res.json();
      if (!data.ok) return;
      const s = data.stats;
      statTotal.textContent = s.total;
      statBytes.textContent = formatBytes(s.bytes);
      const pps = Math.max(0, s.total - lastPacketCount);
      lastPacketCount = s.total;
      statPps.textContent = pps;
      ppsHistory.push(pps);
      ppsHistory.shift();
      if (!statsModal.classList.contains("hidden")) refreshStats();
    } catch (e) { /* silent */ }
  }

  function drawPulse() {
    const ctx = pulseCanvas.getContext("2d");
    const w = pulseCanvas.width, h = pulseCanvas.height;
    function frame() {
      const styles = getComputedStyle(document.documentElement);
      ctx.clearRect(0, 0, w, h);
      ctx.strokeStyle = styles.getPropertyValue("--signal").trim() || "#3ddc97";
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      const max = Math.max(5, ...ppsHistory);
      ppsHistory.forEach((v, i) => {
        const x = (i / (ppsHistory.length - 1)) * w;
        const y = h - (v / max) * (h - 6) - 3;
        i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
      });
      ctx.stroke();
      requestAnimationFrame(frame);
    }
    frame();
  }

  function initSplitters() {
    const paneList = document.getElementById("paneList");
    const splitterH = document.getElementById("splitterH");
    const workspace = document.querySelector(".workspace");

    let draggingH = false;
    splitterH.addEventListener("mousedown", () => draggingH = true);
    window.addEventListener("mousemove", (e) => {
      if (!draggingH) return;
      const rect = workspace.getBoundingClientRect();
      const newHeight = e.clientY - rect.top;
      paneList.style.flex = "none";
      paneList.style.height = Math.max(80, newHeight) + "px";
    });
    window.addEventListener("mouseup", () => draggingH = false);

    const paneDetail = document.querySelector(".pane-detail");
    const splitterV = document.getElementById("splitterV");
    const paneBottom = document.getElementById("paneBottom");

    let draggingV = false;
    splitterV.addEventListener("mousedown", () => draggingV = true);
    window.addEventListener("mousemove", (e) => {
      if (!draggingV) return;
      const rect = paneBottom.getBoundingClientRect();
      const newWidth = e.clientX - rect.left;
      paneDetail.style.flex = "none";
      paneDetail.style.width = Math.max(120, newWidth) + "px";
    });
    window.addEventListener("mouseup", () => draggingV = false);
  }

  function isScrolledToBottom() {
    const el = document.getElementById("paneList");
    return el.scrollHeight - el.scrollTop - el.clientHeight < 60;
  }
  function formatBytes(b) {
    if (b < 1024) return b + " B";
    if (b < 1024 * 1024) return (b / 1024).toFixed(1) + " KB";
    return (b / (1024 * 1024)).toFixed(2) + " MB";
  }
  function escapeHtml(str) {
    return String(str ?? "").replace(/[&<>"']/g, (m) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    }[m]));
  }
  function debounce(fn, ms) {
    let t;
    return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
  }

  document.addEventListener("DOMContentLoaded", init);
})();
