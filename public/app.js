const backendStatus = document.querySelector("#backend-status");
const phaseBadge = document.querySelector("#phase-badge");
const eventLog = document.querySelector("#event-log");
const webAddress = document.querySelector("#web-address");
const chatAddress = document.querySelector("#chat-address");
const peerAddress = document.querySelector("#peer-address");
const connectionForm = document.querySelector("#connection-form");
const peerIpInput = document.querySelector("#peer-ip");
const connectButton = document.querySelector("#connect-button");
const disconnectButton = document.querySelector("#disconnect-button");
const messageForm = document.querySelector("#message-form");
const messageInput = document.querySelector("#message-input");
const sendButton = document.querySelector("#send-button");
const messageList = document.querySelector("#message-list");
const emptyChat = document.querySelector("#empty-chat");
const stepConnected = document.querySelector("#step-connected");
const stepClear = document.querySelector("#step-clear");

let controlSocket;
let currentState = "DISCONNECTED";
let reconnectTimer;

function appendEvent(message, severity = "info", timestamp = new Date().toISOString()) {
  const item = document.createElement("li");
  item.className = `event event--${severity}`;

  const time = document.createElement("time");
  time.dateTime = timestamp;
  time.textContent = new Date(timestamp).toLocaleTimeString();

  const text = document.createElement("span");
  text.textContent = message;

  item.append(time, text);
  eventLog.prepend(item);
}

function appendMessage(message) {
  emptyChat.hidden = true;

  const item = document.createElement("li");
  item.className = `message message--${message.direction}`;

  const meta = document.createElement("div");
  meta.className = "message__meta";

  const direction = document.createElement("span");
  direction.textContent = message.direction === "outgoing" ? "You" : "Peer";

  const security = document.createElement("span");
  security.className = "message__security";
  security.textContent = message.security;

  const time = document.createElement("time");
  time.dateTime = message.timestamp;
  time.textContent = new Date(message.timestamp).toLocaleTimeString();

  const text = document.createElement("p");
  text.textContent = message.text;

  meta.append(direction, security, time);
  item.append(meta, text);
  messageList.append(item);
  item.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function sendCommand(command) {
  if (!controlSocket || controlSocket.readyState !== WebSocket.OPEN) {
    appendEvent("The local control channel is not connected.", "error");
    return false;
  }
  controlSocket.send(JSON.stringify(command));
  return true;
}

function applyState(message) {
  currentState = message.state;
  phaseBadge.textContent = message.state;
  phaseBadge.className = `phase-badge phase-badge--${message.state.toLowerCase()}`;

  const canConnect = message.permittedActions.includes("connect");
  const canDisconnect = message.permittedActions.includes("disconnect");
  const canSend = message.permittedActions.includes("send_message");

  peerIpInput.disabled = !canConnect;
  connectButton.disabled = !canConnect;
  disconnectButton.disabled = !canDisconnect;
  messageInput.disabled = !canSend;
  sendButton.disabled = !canSend;
  peerAddress.textContent = message.peerIp
    ? `${message.peerIp}:${message.peerPort} (${message.direction})`
    : "None";
  chatAddress.textContent = `${message.chatBindAddress}:${message.chatPort}`;

  const connected = message.state === "CONNECTED_CLEAR" || message.state === "CLEAR_EXCHANGED";
  stepConnected.classList.toggle("is-complete", connected);
  stepClear.classList.toggle("is-complete", message.state === "CLEAR_EXCHANGED");

  if (canSend && document.activeElement !== peerIpInput) {
    messageInput.focus();
  }
}

async function loadHealth() {
  try {
    const response = await fetch("/health", { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`Health endpoint returned ${response.status}.`);
    }

    const health = await response.json();
    webAddress.textContent = window.location.origin;
    chatAddress.textContent = `${health.chatBindAddress}:${health.chatPort}`;
    appendEvent("Health check passed.", "success");
  } catch (error) {
    appendEvent(error instanceof Error ? error.message : "Health check failed.", "error");
  }
}

function connectControlSocket() {
  clearTimeout(reconnectTimer);
  const scheme = window.location.protocol === "https:" ? "wss" : "ws";
  controlSocket = new WebSocket(`${scheme}://${window.location.host}/control`);

  controlSocket.addEventListener("open", () => {
    backendStatus.textContent = "Local backend connected";
    backendStatus.className = "status status--connected";
  });

  controlSocket.addEventListener("message", (event) => {
    let message;
    try {
      message = JSON.parse(event.data);
    } catch {
      appendEvent("Received an invalid local backend event.", "error");
      return;
    }

    switch (message.type) {
      case "state":
        applyState(message);
        break;
      case "chat_message":
        appendMessage(message);
        break;
      case "security_event":
        appendEvent(message.message, message.severity, message.timestamp);
        break;
      case "error":
        appendEvent(message.message, "error");
        break;
    }
  });

  controlSocket.addEventListener("close", () => {
    backendStatus.textContent = "Local backend disconnected";
    backendStatus.className = "status status--error";
    peerIpInput.disabled = true;
    connectButton.disabled = true;
    disconnectButton.disabled = true;
    messageInput.disabled = true;
    sendButton.disabled = true;
    if (currentState !== "DISCONNECTED") {
      appendEvent("Local control channel closed.", "error");
    }
    reconnectTimer = setTimeout(connectControlSocket, 1_500);
  });

  controlSocket.addEventListener("error", () => {
    backendStatus.textContent = "Local backend unavailable";
    backendStatus.className = "status status--error";
  });
}

connectionForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const peerIp = peerIpInput.value.trim();
  if (sendCommand({ type: "connect", peerIp })) {
    appendEvent(`Requested connection to ${peerIp}.`, "info");
  }
});

disconnectButton.addEventListener("click", () => {
  sendCommand({ type: "disconnect" });
});

messageForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const text = messageInput.value.trim();
  if (!text) {
    return;
  }
  if (sendCommand({ type: "send_message", text })) {
    messageInput.value = "";
  }
});

void loadHealth();
connectControlSocket();
