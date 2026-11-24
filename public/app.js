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
const identityAlgorithm = document.querySelector("#identity-algorithm");
const localFingerprint = document.querySelector("#local-fingerprint");
const identityCreated = document.querySelector("#identity-created");
const toggleFingerprint = document.querySelector("#toggle-fingerprint");
const copyFingerprint = document.querySelector("#copy-fingerprint");
const peerFingerprint = document.querySelector("#peer-fingerprint");
const localVerificationStatus = document.querySelector("#local-verification-status");
const peerVerificationStatus = document.querySelector("#peer-verification-status");
const exchangeKeysButton = document.querySelector("#exchange-keys-button");
const confirmFingerprintButton = document.querySelector("#confirm-fingerprint-button");
const rejectFingerprintButton = document.querySelector("#reject-fingerprint-button");
const startSecureSessionButton = document.querySelector("#start-secure-session-button");
const secureSessionStatus = document.querySelector("#secure-session-status");
const stepIdentity = document.querySelector("#step-identity");
const stepSecure = document.querySelector("#step-secure");

let controlSocket;
let currentState = "DISCONNECTED";
let reconnectTimer;
let fingerprintValue = "";

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
  const canExchangeKeys = message.permittedActions.includes("exchange_keys");
  const canVerifyFingerprint = message.permittedActions.includes("verify_fingerprint");
  const canRejectFingerprint = message.permittedActions.includes("reject_fingerprint");
  const canStartSecureSession = message.permittedActions.includes("start_secure_session");

  peerIpInput.disabled = !canConnect;
  connectButton.disabled = !canConnect;
  disconnectButton.disabled = !canDisconnect;
  messageInput.disabled = !canSend;
  sendButton.disabled = !canSend;
  exchangeKeysButton.disabled = !canExchangeKeys;
  confirmFingerprintButton.disabled = !canVerifyFingerprint;
  rejectFingerprintButton.disabled = !canRejectFingerprint;
  startSecureSessionButton.disabled = !canStartSecureSession;
  peerAddress.textContent = message.peerIp
    ? `${message.peerIp}:${message.peerPort} (${message.direction})`
    : "None";
  chatAddress.textContent = `${message.chatBindAddress}:${message.chatPort}`;

  const connected = message.state !== "DISCONNECTED" && message.state !== "CONNECTING";
  const clearComplete = [
    "CLEAR_EXCHANGED",
    "KEYS_UNVERIFIED",
    "IDENTITY_VERIFIED",
    "SECURE_NEGOTIATING",
    "SECURE_ACTIVE",
  ].includes(message.state);
  const identityComplete = [
    "IDENTITY_VERIFIED",
    "SECURE_NEGOTIATING",
    "SECURE_ACTIVE",
  ].includes(message.state);
  stepConnected.classList.toggle("is-complete", connected);
  stepClear.classList.toggle("is-complete", clearComplete);
  stepIdentity.classList.toggle("is-future", !clearComplete);
  stepIdentity.classList.toggle("is-active", message.state === "KEYS_UNVERIFIED");
  stepIdentity.classList.toggle("is-complete", identityComplete);
  stepSecure.classList.toggle("is-future", !identityComplete);
  stepSecure.classList.toggle(
    "is-active",
    message.state === "IDENTITY_VERIFIED" || message.state === "SECURE_NEGOTIATING",
  );
  stepSecure.classList.toggle("is-complete", message.state === "SECURE_ACTIVE");

  secureSessionStatus.textContent =
    message.state === "SECURE_ACTIVE"
      ? "✓ Authenticated AES-256 session key established"
      : message.state === "SECURE_NEGOTIATING"
        ? "Authenticating the AES-256 session key…"
        : message.state === "IDENTITY_VERIFIED"
          ? "Ready to establish an authenticated AES-256 session key."
          : "Secure session not started.";

  messageInput.placeholder =
    message.state === "SECURE_ACTIVE"
      ? "Encrypted chat is enabled in Phase 6…"
      : message.state === "SECURE_NEGOTIATING"
        ? "Secure session negotiation in progress…"
        : "Write a plaintext message…";

  peerFingerprint.textContent = message.peerFingerprint ?? "Public key not received";
  localVerificationStatus.textContent = message.localFingerprintVerified
    ? "✓ You verified the peer fingerprint"
    : message.peerFingerprint
      ? "Awaiting your fingerprint comparison"
      : "Awaiting public-key exchange";
  peerVerificationStatus.textContent = message.peerVerifiedLocalFingerprint
    ? "✓ Peer verified this client's fingerprint"
    : "Awaiting peer confirmation";

  if (message.state === "DISCONNECTED") {
    peerFingerprint.textContent = "Public key not received";
  }

}

function applyIdentity(message) {
  fingerprintValue = message.fingerprint;
  identityAlgorithm.textContent = message.algorithm;
  identityCreated.textContent = `Identity created ${new Date(message.createdAt).toLocaleString()}`;
  localFingerprint.textContent = "Fingerprint hidden";
  localFingerprint.dataset.visible = "false";
  toggleFingerprint.textContent = "Show fingerprint";
  toggleFingerprint.disabled = false;
  copyFingerprint.disabled = false;
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
      case "identity":
        applyIdentity(message);
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
    exchangeKeysButton.disabled = true;
    confirmFingerprintButton.disabled = true;
    rejectFingerprintButton.disabled = true;
    startSecureSessionButton.disabled = true;
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

exchangeKeysButton.addEventListener("click", () => {
  sendCommand({ type: "exchange_keys" });
});

confirmFingerprintButton.addEventListener("click", () => {
  sendCommand({ type: "verify_fingerprint", decision: "accept" });
});

rejectFingerprintButton.addEventListener("click", () => {
  sendCommand({ type: "verify_fingerprint", decision: "reject" });
});

startSecureSessionButton.addEventListener("click", () => {
  sendCommand({ type: "start_secure_session" });
});

toggleFingerprint.addEventListener("click", () => {
  const currentlyVisible = localFingerprint.dataset.visible === "true";
  localFingerprint.dataset.visible = currentlyVisible ? "false" : "true";
  localFingerprint.textContent = currentlyVisible ? "Fingerprint hidden" : fingerprintValue;
  toggleFingerprint.textContent = currentlyVisible ? "Show fingerprint" : "Hide fingerprint";
});

copyFingerprint.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(fingerprintValue);
    appendEvent("Local public-key fingerprint copied to the clipboard.", "success");
  } catch {
    appendEvent("Unable to copy the fingerprint automatically.", "error");
  }
});

void loadHealth();
connectControlSocket();
