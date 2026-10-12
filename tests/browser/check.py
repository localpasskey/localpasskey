"""Verify a running browser against the real LocalPasskey HID device.

Start tests/browser/serve.py on localhost:8765, a visible disposable browser
profile with remote debugging enabled, and an isolated test daemon. This
creates/replaces six test passkeys across Firefox and Chromium; it uses the
browser's real USB transport, never a DevTools virtual authenticator.

    python3 -m tests.browser.check firefox --port 9233
    python3 -m tests.browser.check chromium --port 9234

Requires the installed websocket-client Python module, python-fido2, and an
active browser window. The daemon controls whether approval is real or mocked.
"""

import argparse
import base64
import json
import urllib.request

import websocket

from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestationObject, AuthenticatorData, CollectedClientData,
    PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity,
    PublicKeyCredentialParameters, PublicKeyCredentialType,
)
import fido2.features

fido2.features.webauthn_json_mapping.enabled = False


class Browser:
    def __init__(self, name, port):
        self.name = name
        self.seq = 0
        self.events = []
        if name == "firefox":
            self.socket = websocket.create_connection(
                f"ws://127.0.0.1:{port}/session", timeout=40, suppress_origin=True)
            self.command("session.new", {"capabilities": {}})
            self.context = self.command("browsingContext.getTree", {})["contexts"][0]["context"]
            self.command("browsingContext.navigate", {
                "context": self.context, "url": "http://localhost:8765/", "wait": "complete"})
        else:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/json") as response:
                pages = json.load(response)
            page = next(page for page in pages if page["type"] == "page")
            self.socket = websocket.create_connection(
                page["webSocketDebuggerUrl"], timeout=40, suppress_origin=True)
            self.command("Page.enable", {})
            self.command("Page.navigate", {"url": "http://localhost:8765/"})
            self.command("Page.bringToFront", {})
            while not any(event.get("method") == "Page.loadEventFired" for event in self.events):
                self.events.append(json.loads(self.socket.recv()))

    def command(self, method, params):
        self.seq += 1
        self.socket.send(json.dumps({"id": self.seq, "method": method, "params": params}))
        while True:
            reply = json.loads(self.socket.recv())
            if reply.get("id") == self.seq:
                assert "error" not in reply, reply
                return reply["result"]
            self.events.append(reply)

    def evaluate(self, expression):
        if self.name == "firefox":
            result = self.command("script.evaluate", {
                "expression": expression, "target": {"context": self.context},
                "awaitPromise": True, "userActivation": True,
            })
            assert result["type"] == "success", result
            return result["result"].get("value")
        result = self.command("Runtime.evaluate", {
            "expression": expression, "awaitPromise": True,
            "returnByValue": True, "userGesture": True,
        })
        assert "exceptionDetails" not in result, result
        return result["result"].get("value")

    def close(self):
        if self.name == "firefox":
            self.command("session.end", {})
        self.socket.close()


def encode(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def decode(data):
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def main(name, port):
    browser = Browser(name, port)
    server = Fido2Server(PublicKeyCredentialRpEntity(id="localhost", name="LocalPasskey E2E"))
    try:
        for algorithm in (-7, -8, -257):
            user_name = f"{name}-{algorithm}@localhost"
            server.allowed_algorithms = [PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, algorithm)]
            options, state = server.register_begin(
                PublicKeyCredentialUserEntity(id=user_name.encode(), name=user_name),
                resident_key_requirement="required", user_verification="required")
            challenge = encode(bytes(options["publicKey"]["challenge"]))
            created = json.loads(browser.evaluate("""(async () => {
                const dec = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
                const enc = b => btoa(String.fromCharCode(...new Uint8Array(b)));
                const credential = await navigator.credentials.create({publicKey: {
                    rp: {id: 'localhost', name: 'LocalPasskey E2E'},
                    user: {id: new TextEncoder().encode(%s), name: %s, displayName: %s},
                    challenge: dec(%s), pubKeyCredParams: [{type: 'public-key', alg: %d}],
                    authenticatorSelection: {authenticatorAttachment: 'cross-platform', residentKey: 'required', userVerification: 'required'},
                    timeout: 20000
                }});
                return JSON.stringify({id: enc(credential.rawId), client: enc(credential.response.clientDataJSON), attestation: enc(credential.response.attestationObject)});
            })()""" % (json.dumps(user_name), json.dumps(user_name), json.dumps(user_name), json.dumps(challenge), algorithm)))
            auth = server.register_complete(state, CollectedClientData(decode(created["client"])), AttestationObject(decode(created["attestation"])))
            assert auth.is_user_verified() and auth.is_user_present()
            assert auth.credential_data.public_key[3] == algorithm
            assert bytes(auth.credential_data.aaguid) == bytes(16)
            options, state = server.authenticate_begin([auth.credential_data], user_verification="required")
            challenge = encode(bytes(options["publicKey"]["challenge"]))
            signed = json.loads(browser.evaluate("""(async () => {
                const dec = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
                const enc = b => btoa(String.fromCharCode(...new Uint8Array(b)));
                const credential = await navigator.credentials.get({publicKey: {
                    rpId: 'localhost', challenge: dec(%s),
                    allowCredentials: [{type: 'public-key', id: dec(%s), transports: ['usb']}],
                    userVerification: 'required', timeout: 20000
                }});
                return JSON.stringify({id: enc(credential.rawId), client: enc(credential.response.clientDataJSON), auth: enc(credential.response.authenticatorData), signature: enc(credential.response.signature), user: enc(credential.response.userHandle)});
            })()""" % (json.dumps(challenge), json.dumps(created["id"]))))
            auth_data = AuthenticatorData(decode(signed["auth"]))
            server.authenticate_complete(state, [auth.credential_data], decode(signed["id"]), CollectedClientData(decode(signed["client"])), auth_data, decode(signed["signature"]))
            assert auth_data.is_user_verified() and auth_data.is_user_present() and auth_data.counter == 0
            assert decode(signed["user"]) == user_name.encode()
            print(f"{name} alg={algorithm}: actual HID registration + server-verified assertion OK", flush=True)
    finally:
        browser.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("browser", choices=("firefox", "chromium"))
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    main(args.browser, args.port)
