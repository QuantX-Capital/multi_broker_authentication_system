const brokerListEl = document.getElementById("broker-list");
const logPanelEl = document.getElementById("log-panel");
const logListEl = document.getElementById("log-list");

const authOverlay = document.getElementById("auth-overlay");
const authModalTitle = document.getElementById("auth-modal-title");
const authModalStatus = document.getElementById("auth-modal-status");
const cancelBtn = document.getElementById("auth-cancel-btn");

const credentialsForm = document.getElementById("credentials-form");
const userIdInput = document.getElementById("input-user-id");
const passwordInput = document.getElementById("input-password");

const otpForm = document.getElementById("otp-form");
const otpInput = document.getElementById("input-otp");

let active = null; // { broker, awaitingOtp }

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
    card.dataset.status = "idle";

    card.innerHTML = `
      <div class="broker-avatar" aria-hidden="true">${broker.charAt(0).toUpperCase()}</div>
      <div class="broker-info">
        <h3>${broker}</h3>
        <p class="broker-status"><span class="status-dot"></span>Not authenticated</p>
      </div>
      <button class="auth-btn" data-broker="${broker}">Authenticate</button>
    `;

    brokerListEl.appendChild(card);
  });

  brokerListEl.querySelectorAll(".auth-btn").forEach((btn) => {
    btn.addEventListener("click", () => openModal(btn.dataset.broker));
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

function updateBrokerCard(broker, text, status) {
  const card = document.getElementById(`card-${broker}`);
  if (!card) return;
  if (status) card.dataset.status = status;
  const statusEl = card.querySelector(".broker-status");
  statusEl.innerHTML = "";
  statusEl.appendChild(Object.assign(document.createElement("span"), { className: "status-dot" }));
  statusEl.appendChild(document.createTextNode(text));
}

function showStatus(text, kind) {
  authModalStatus.hidden = !text;
  authModalStatus.textContent = text || "";
  authModalStatus.className = "auth-modal-status" + (kind ? ` ${kind}` : "");
}

function clearCredentialInputs() {
  passwordInput.value = "";
}

function clearOtpInput() {
  otpInput.value = "";
}

function openModal(broker) {
  active = { broker, awaitingOtp: false };
  setBrokerButtonsDisabled(true);
  authModalTitle.textContent = `${broker} authentication`;
  showStatus("");
  userIdInput.value = "";
  passwordInput.value = "";
  otpInput.value = "";
  credentialsForm.hidden = false;
  credentialsForm.querySelectorAll("input, button").forEach((el) => (el.disabled = false));
  otpForm.hidden = true;
  authOverlay.hidden = false;
  userIdInput.focus();
}

function closeModal() {
  authOverlay.hidden = true;
  clearCredentialInputs();
  clearOtpInput();
  active = null;
}

function setFormBusy(form, busy) {
  form.querySelectorAll("input, button").forEach((el) => (el.disabled = busy));
}

credentialsForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!active) return;

  const broker = active.broker;
  const userId = userIdInput.value;
  const password = passwordInput.value;

  setFormBusy(credentialsForm, true);
  showStatus("Starting secure browser…");
  updateBrokerCard(broker, "Starting…", "busy");
  logEvent(`Starting authentication for "${broker}"…`);

  let res, data;
  try {
    res = await fetch(`/auth/${encodeURIComponent(broker)}/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ user_id: userId, password }),
    });
    data = await res.json();
  } catch (err) {
    fail(broker, "Network error while starting authentication.");
    return;
  } finally {
    clearCredentialInputs();
  }

  if (!res.ok) {
    fail(broker, data.detail || `Request failed (${res.status})`);
    return;
  }

  if (data.status === "otp_required") {
    active.awaitingOtp = true;
    credentialsForm.hidden = true;
    otpForm.hidden = false;
    setFormBusy(otpForm, false);
    showStatus("OTP required — check your device and enter it below.");
    updateBrokerCard(broker, "Waiting for OTP…", "busy");
    otpInput.focus();
  } else if (data.status === "authenticated") {
    succeed(broker);
  } else {
    fail(broker, `Unexpected status: ${data.status}`);
  }
});

otpForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!active) return;

  const broker = active.broker;
  const otp = otpInput.value;

  setFormBusy(otpForm, true);
  showStatus("Submitting OTP…");

  let res, data;
  try {
    res = await fetch(`/auth/${encodeURIComponent(broker)}/otp`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ otp }),
    });
    data = await res.json();
  } catch (err) {
    fail(broker, "Network error while submitting OTP.");
    return;
  } finally {
    clearOtpInput();
  }

  if (!res.ok) {
    fail(broker, data.detail || `Request failed (${res.status})`);
    return;
  }

  if (data.status === "authenticated") {
    succeed(broker);
  } else {
    fail(broker, `Unexpected status: ${data.status}`);
  }
});

cancelBtn.addEventListener("click", async () => {
  if (!active) return;
  const { broker, awaitingOtp } = active;

  if (awaitingOtp) {
    try {
      await fetch(`/auth/${encodeURIComponent(broker)}/cancel`, { method: "POST" });
    } catch (err) {
      // fall through - the session will expire on its own either way
    }
  }

  updateBrokerCard(broker, "Cancelled", "idle");
  logEvent(`"${broker}" authentication cancelled.`);
  setBrokerButtonsDisabled(false);
  closeModal();
});

function succeed(broker) {
  updateBrokerCard(broker, "Authenticated", "success");
  logEvent(`"${broker}" authenticated successfully.`, "success");
  setBrokerButtonsDisabled(false);
  closeModal();
}

function fail(broker, error) {
  updateBrokerCard(broker, "Authentication failed", "failed");
  logEvent(`"${broker}" failed: ${error || "unknown error"}`, "error");
  setBrokerButtonsDisabled(false);
  closeModal();
}

loadBrokers();
