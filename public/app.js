const backendStatus = document.querySelector("#backend-status");
const eventLog = document.querySelector("#event-log");
const webAddress = document.querySelector("#web-address");
const chatAddress = document.querySelector("#chat-address");
const protocolVersion = document.querySelector("#protocol-version");

function appendEvent(message, severity = "info") {
  const item = document.createElement("li");
  item.className = `event event--${severity}`;

  const time = document.createElement("time");
  time.dateTime = new Date().toISOString();
  time.textContent = new Date().toLocaleTimeString();

  const text = document.createElement("span");
  text.textContent = message;

  item.append(time, text);
  eventLog.prepend(item);
}

async function loadHealth() {
  try {
    const response = await fetch("/health", { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`Health endpoint returned ${response.status}.`);
    }

    const health = await response.json();
    webAddress.textContent = window.location.origin;
    chatAddress.textContent = `${health.chatBindAddress}:${health.chatPort} (Phase 2)`;
    protocolVersion.textContent = String(health.protocolVersion);
    appendEvent("Health check passed.", "success");
  } catch (error) {
    appendEvent(error instanceof Error ? error.message : "Health check failed.", "error");
  }
}

function connectControlSocket() {
  const scheme = window.location.protocol === "https:" ? "wss" : "ws";
  const socket = new WebSocket(`${scheme}://${window.location.host}/control`);

  socket.addEventListener("open", () => {
    backendStatus.textContent = "Local backend connected";
    backendStatus.className = "status status--connected";
  });

  socket.addEventListener("message", (event) => {
    const message = JSON.parse(event.data);
    if (message.type === "security_event") {
      appendEvent(message.message, message.severity);
    }
  });

  socket.addEventListener("close", () => {
    backendStatus.textContent = "Local backend disconnected";
    backendStatus.className = "status status--error";
    appendEvent("Local control channel closed.", "error");
  });

  socket.addEventListener("error", () => {
    appendEvent("Unable to connect to the local control channel.", "error");
  });
}

void loadHealth();
connectControlSocket();
