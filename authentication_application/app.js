const brokerListEl = document.getElementById("broker-list");
const logPanelEl = document.getElementById("log-panel");
const logListEl = document.getElementById("log-list");

const authOverlay = document.getElementById("auth-overlay");
const authModalTitle = document.getElementById("auth-modal-title");
const authModalStatus = document.getElementById("auth-modal-status");
const vncContainer = document.getElementById("vnc-container");
const cancelBtn = document.getElementById("auth-cancel-btn");

const STATUS_TEXT = {
  starting_browser: "Starting secure browser…",
  waiting_for_otp: "Complete the broker login (and OTP, if asked) in the browser below.",
  authenticating: "Login detected — exchanging tokens…",
  success: "Authenticated successfully.",
  failed: "Authentication failed.",
  cancelled: "Cancelled.",
};

const TERMINAL_STATUSES = new Set(["success", "failed", "cancelled"]);
const POLL_INTERVAL_MS = 1500;

let active = null; // { sessionId, broker, pollTimer, rfb }

function logEvent(message, kind) {
  logPanelEl.hidden = false;
  const li = document.createElement("li");
  li.className = kind || "";
  const time = document.createElement("span");
  time.className = "log-time";
  time.textContent = new Date().toLocaleTimeString();
  li.appendChild(time);
  li.appendChild(document.createTextNode(message));
  logListEl.prepend(li);
}

function setBrokerButtonsDisabled(disabled) {
  brokerListEl.querySelectorAll(".auth-btn").forEach((btn) => {
    btn.disabled = disabled;
  });
}

function renderBrokers(brokers) {
  brokerListEl.innerHTML = "";

  if (!brokers.length) {
    brokerListEl.innerHTML = '<p class="status-line">No brokers registered.</p>';
    return;
  }

  brokers.forEach((broker) => {
    const card = document.createElement("div");
    card.className = "broker-card";
    card.id = `card-${broker}`;

    card.innerHTML = `
      <div class="broker-info">
        <h3>${broker}</h3>
        <p class="broker-status">Not authenticated</p>
      </div>
      <button class="auth-btn" data-broker="${broker}">Authenticate</button>
    `;

    brokerListEl.appendChild(card);
  });

  brokerListEl.querySelectorAll(".auth-btn").forEach((btn) => {
    btn.addEventListener("click", () => startAuth(btn.dataset.broker));
  });
}

async function loadBrokers() {
  try {
    const res = await fetch("/brokers");
    if (!res.ok) throw new Error(`Failed to load brokers (${res.status})`);
    const data = await res.json();
    renderBrokers(data.brokers || []);
  } catch (err) {
    brokerListEl.innerHTML = `<p class="status-line error">${err.message}</p>`;
  }
}

function vncWebSocketUrl(vncToken) {
  const protocol = location.protocol === "https:" ? "wss:" : "ws:";
  return `${protocol}//${location.host}/vnc/websockify?token=${encodeURIComponent(vncToken)}`;
}

async function connectVnc(vncToken) {
  vncContainer.innerHTML = "";
  try {
    const { default: RFB } = await import("/novnc/core/rfb.js");
    const rfb = new RFB(vncContainer, vncWebSocketUrl(vncToken));
    rfb.scaleViewport = true;
    rfb.addEventListener("disconnect", () => {
      // Expected once the session ends and we tear it down ourselves; a
      // disconnect while still "active" means the viewer dropped unexpectedly.
      if (active) vncContainer.innerHTML = '<p class="vnc-error">Viewer disconnected.</p>';
    });
    return rfb;
  } catch (err) {
    vncContainer.innerHTML = '<p class="vnc-error">Could not load the embedded browser viewer.</p>';
    return null;
  }
}

function disconnectVnc() {
  if (active && active.rfb) {
    try {
      active.rfb.disconnect();
    } catch (err) {
      // already gone
    }
  }
  vncContainer.innerHTML = "";
}

function openModal(broker) {
  authModalTitle.textContent = `${broker} authentication`;
  authModalStatus.textContent = STATUS_TEXT.starting_browser;
  authOverlay.hidden = false;
}

function closeModal() {
  authOverlay.hidden = true;
}

function updateBrokerCard(broker, text) {
  const card = document.getElementById(`card-${broker}`);
  if (card) card.querySelector(".broker-status").textContent = text;
}

async function startAuth(broker) {
  if (active) return; // one session at a time, matches backend

  setBrokerButtonsDisabled(true);
  updateBrokerCard(broker, "Starting…");
  logEvent(`Starting authentication for "${broker}"…`);
  openModal(broker);

  let res, data;
  try {
    res = await fetch(`/auth/${encodeURIComponent(broker)}/start`, { method: "POST" });
    data = await res.json();
  } catch (err) {
    finishAuth(broker, "failed", err.message);
    return;
  }

  if (!res.ok) {
    finishAuth(broker, "failed", data.detail || `Request failed (${res.status})`);
    return;
  }

  active = { sessionId: data.session_id, broker, rfb: null, pollTimer: null };
  active.rfb = await connectVnc(data.vnc_token);
  active.pollTimer = setInterval(() => pollSession(broker), POLL_INTERVAL_MS);
}

async function pollSession(broker) {
  if (!active) return;
  let res, data;
  try {
    res = await fetch(`/auth/session/${active.sessionId}`);
    data = await res.json();
  } catch (err) {
    return; // transient network hiccup - try again next tick
  }

  if (!res.ok) {
    finishAuth(broker, "failed", data.detail || "Session lookup failed.");
    return;
  }

  authModalStatus.textContent = STATUS_TEXT[data.status] || data.status;

  if (TERMINAL_STATUSES.has(data.status)) {
    finishAuth(broker, data.status, data.error);
  }
}

function finishAuth(broker, status, error) {
  if (active && active.pollTimer) clearInterval(active.pollTimer);
  disconnectVnc();
  active = null;
  setBrokerButtonsDisabled(false);
  closeModal();

  if (status === "success") {
    updateBrokerCard(broker, "Authenticated");
    logEvent(`"${broker}" authenticated successfully.`, "success");
  } else if (status === "cancelled") {
    updateBrokerCard(broker, "Cancelled");
    logEvent(`"${broker}" authentication cancelled.`);
  } else {
    updateBrokerCard(broker, "Authentication failed");
    logEvent(`"${broker}" failed: ${error || "unknown error"}`, "error");
  }
}

cancelBtn.addEventListener("click", async () => {
  if (!active) return;
  const { sessionId, broker } = active;
  try {
    await fetch(`/auth/session/${sessionId}/cancel`, { method: "POST" });
  } catch (err) {
    // fall through - the poll loop (or user retry) will resolve state either way
  }
  finishAuth(broker, "cancelled");
});

loadBrokers();
