const brokerListEl = document.getElementById("broker-list");
const logPanelEl = document.getElementById("log-panel");
const logListEl = document.getElementById("log-list");

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
    btn.addEventListener("click", () => runAuth(btn.dataset.broker));
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

async function runAuth(broker) {
  const card = document.getElementById(`card-${broker}`);
  const btn = card.querySelector(".auth-btn");
  const statusEl = card.querySelector(".broker-status");

  btn.disabled = true;
  btn.textContent = "Authenticating…";
  statusEl.textContent = "A browser window is opening on the server — complete login/OTP there. This can take up to 3 minutes.";
  logEvent(`Starting authentication for "${broker}"…`);

  try {
    const res = await fetch(`/authenticate/${encodeURIComponent(broker)}`, {
      method: "POST",
    });
    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.detail || `Request failed (${res.status})`);
    }

    statusEl.textContent = "Authenticated";
    const existingToken = card.querySelector(".broker-token");
    if (existingToken) existingToken.remove();
    const tokenEl = document.createElement("p");
    tokenEl.className = "broker-token";
    tokenEl.textContent = data.access_token;
    card.querySelector(".broker-info").appendChild(tokenEl);

    logEvent(`"${broker}" authenticated successfully.`, "success");
  } catch (err) {
    statusEl.textContent = "Authentication failed";
    logEvent(`"${broker}" failed: ${err.message}`, "error");
  } finally {
    btn.disabled = false;
    btn.textContent = "Re-authenticate";
  }
}

loadBrokers();
