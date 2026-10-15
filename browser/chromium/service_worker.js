// LocalPasskey bridge: hands WebAuthn requests from Chrome/Chromium to the
// native host org.localpasskey.bridge, which talks to the LocalPasskey key.
// Never log request or response contents: they carry user IDs and challenges.
"use strict";

const HOST = "org.localpasskey.bridge";
const UVPAA_CACHE_MS = 5000;
const proxy = chrome.webAuthenticationProxy;
const ports = new Map(); // requestId -> native port of a running ceremony
let uvpaaCache = {at: 0, value: false};
let attachFailureLogged = false;

async function attach() {
  let error;
  try {
    error = await proxy.attach();
  } catch (e) {
    error = String(e);
  }
  if (error && !attachFailureLogged) {
    attachFailureLogged = true;
    console.warn("LocalPasskey: not handling passkeys, attach failed:", error);
  }
}

// Send one message to a fresh host process and resolve with its first reply,
// or null if the host is missing, crashes or closes without answering.
function ask(message, requestId) {
  return new Promise((resolve) => {
    let port;
    try {
      port = chrome.runtime.connectNative(HOST);
    } catch (e) {
      resolve(null);
      return;
    }
    const done = (reply) => {
      if (requestId !== undefined) ports.delete(requestId);
      resolve(reply);
    };
    port.onMessage.addListener((reply) => {
      done(reply);
      port.disconnect();
    });
    port.onDisconnect.addListener(() => {
      void chrome.runtime.lastError; // host not installed or exited; already handled as null
      done(null);
    });
    if (requestId !== undefined) ports.set(requestId, port);
    port.postMessage(message);
  });
}

const NOT_ALLOWED = {name: "NotAllowedError", message: "The operation either timed out or was not allowed."};

// Keep only what Chromium expects from the host's reply.
function outcome(reply) {
  if (reply && typeof reply.responseJson === "string") return {responseJson: reply.responseJson};
  if (reply && reply.error && typeof reply.error.name === "string") {
    return {error: {name: reply.error.name, message: String(reply.error.message || "")}};
  }
  return {error: NOT_ALLOWED};
}

async function ceremony(type, request, complete) {
  const {requestId} = request;
  const reply = await ask({type, requestDetailsJson: request.requestDetailsJson}, requestId);
  try {
    await complete({requestId, ...outcome(reply)});
  } catch (e) {
    // The request was canceled or timed out in the meantime.
  }
}

proxy.onCreateRequest.addListener((request) =>
  ceremony("create", request, (r) => proxy.completeCreateRequest(r)));

proxy.onGetRequest.addListener((request) =>
  ceremony("get", request, (r) => proxy.completeGetRequest(r)));

proxy.onRequestCanceled.addListener((requestId) => {
  const port = ports.get(requestId);
  if (port) {
    ports.delete(requestId);
    port.disconnect(); // closes the host's stdin, which cancels the ceremony
  }
});

proxy.onIsUvpaaRequest.addListener(async ({requestId}) => {
  if (Date.now() - uvpaaCache.at > UVPAA_CACHE_MS) {
    const reply = await ask({type: "status"});
    uvpaaCache = {at: Date.now(), value: !!(reply && reply.available === true)};
  }
  try {
    await proxy.completeIsUvpaaRequest({requestId, isUvpaa: uvpaaCache.value});
  } catch (e) {
    // The page went away.
  }
});

chrome.runtime.onStartup.addListener(attach);
chrome.runtime.onInstalled.addListener(attach);
attach();
