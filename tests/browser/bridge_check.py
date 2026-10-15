"""Check the Chromium bridge end to end in stock Chromium, offline.

Starts a headless Chromium with a fresh profile, the real extension from
browser/chromium and a native messaging host manifest in the profile's
NativeMessagingHosts directory. The manifest points at this script in --host
mode, which runs localpasskey.bridge over the in-process test authenticator
from tests/helpers.py (approving every prompt) instead of /dev/hidraw*. The
page on http://localhost creates and uses passkeys with "platform" attachment
and every result is verified with python-fido2's Fido2Server.

    python3 -m tests.browser.bridge_check [--chrome PATH]   # or set $CHROME

Requires websocket-client and python-fido2. Not part of make check.
"""

import argparse
import base64
import http.server
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

CHROME = os.environ.get("CHROME") or shutil.which("chromium") or "chromium"
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
EXTENSION = os.path.join(REPO, "browser", "chromium")
EXTENSION_ID = "pocajecgdempcabeopbbdhebigifnkbf"
HOST = "org.localpasskey.bridge"
PAGE = b'<!doctype html><title>bridge check</title><input id="name" autocomplete="username webauthn">'


def host(state_dir):
    """Native messaging host: the real bridge over the test authenticator."""
    import pwd

    from fido2.hid import CtapHidDevice
    from fido2.hid.base import HidDescriptor

    from localpasskey import bridge, session
    from localpasskey.clientpin import PinManager
    from localpasskey.ctap2 import Authenticator, Requester
    from localpasskey.store import CredentialStore
    from tests.helpers import FakeNotifier, FakeResolver, FakeVerifier, LoopbackConnection

    # The name the approval dialog would show for the bridge's parent.
    with open(os.path.join(state_dir, "parents"), "a") as log:
        print(session.application_name(os.getppid()), file=log)
    store = CredentialStore(state_dir)
    requester = Requester(os.getuid(), pwd.getpwuid(os.getuid()).pw_name, os.getpid(), "bridge check")
    authenticator = Authenticator(
        store, FakeResolver(requester), FakeVerifier(), FakeNotifier(), 5.0, pins=PinManager(store)
    )
    descriptor = HidDescriptor("loopback", 0x1209, 0x4C50, 64, 64, "LocalPasskey Virtual FIDO2 Authenticator", None)
    return bridge.serve(
        sys.stdin.buffer, sys.stdout.buffer,
        open_device=lambda: CtapHidDevice(descriptor, LoopbackConnection(authenticator)),
        find_device=lambda: descriptor,
    )


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def serve_page(port):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(PAGE)

        def log_message(self, format, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class Page:
    def __init__(self, url):
        import websocket

        self.socket = websocket.create_connection(url, timeout=60, suppress_origin=True)
        self.seq = 0

    def command(self, method, **params):
        self.seq += 1
        self.socket.send(json.dumps({"id": self.seq, "method": method, "params": params}))
        while True:
            reply = json.loads(self.socket.recv())
            if reply.get("id") == self.seq:
                assert "error" not in reply, reply
                return reply["result"]

    def run(self, body):
        """Run an async function body; returns its value or {"error": name}."""
        result = self.command(
            "Runtime.evaluate", awaitPromise=True, returnByValue=True, userGesture=True,
            expression="(async () => { %s; try { return await (async () => { %s })(); }"
                       " catch (e) { return {error: e.name, message: e.message}; } })()" % (JS, body),
        )
        assert "exceptionDetails" not in result, result
        return result["result"].get("value")


JS = """
const dec = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const enc = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
const out = c => ({id: c.id, rawId: enc(c.rawId), attachment: c.authenticatorAttachment,
  extensions: c.getClientExtensionResults(),
  client: enc(c.response.clientDataJSON),
  attestation: c.response.attestationObject && enc(c.response.attestationObject),
  transports: c.response.getTransports && c.response.getTransports(),
  publicKey: c.response.getPublicKey && c.response.getPublicKey() && enc(c.response.getPublicKey()),
  publicKeyAlgorithm: c.response.getPublicKeyAlgorithm && c.response.getPublicKeyAlgorithm(),
  auth: c.response.authenticatorData && enc(c.response.authenticatorData),
  signature: c.response.signature && enc(c.response.signature),
  user: c.response.userHandle && enc(c.response.userHandle)})
"""


def decode(data):
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def encode(data):
    return base64.urlsafe_b64encode(bytes(data)).decode().rstrip("=")


def check(page, results):
    import fido2.features
    from fido2.server import Fido2Server
    from fido2.webauthn import (
        AttestationObject, AuthenticatorData, CollectedClientData, PublicKeyCredentialParameters,
        PublicKeyCredentialRpEntity, PublicKeyCredentialType, PublicKeyCredentialUserEntity,
    )

    fido2.features.webauthn_json_mapping.enabled = False

    def report(name, ok, detail=""):
        results.append((name, ok))
        print(f"{'OK  ' if ok else 'FAIL'} {name}{': ' + detail if detail else ''}", flush=True)

    uvpaa = page.run("return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()")
    report("isUserVerifyingPlatformAuthenticatorAvailable() is true", uvpaa is True, repr(uvpaa))
    caps = page.run("return await PublicKeyCredential.getClientCapabilities()")
    report("getClientCapabilities() reports a passkey platform authenticator",
           caps.get("userVerifyingPlatformAuthenticator") is True and caps.get("passkeyPlatformAuthenticator") is True,
           json.dumps({k: v for k, v in caps.items() if not k.startswith("extension:")}))

    server = Fido2Server(PublicKeyCredentialRpEntity(id="localhost", name="Bridge check"))
    credentials = []
    for alg in (-7, -8, -257):
        user = f"bridge-{-alg}@localhost"
        server.allowed_algorithms = [PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, alg)]
        options, state = server.register_begin(
            PublicKeyCredentialUserEntity(id=user.encode(), name=user),
            resident_key_requirement="required", user_verification="required")
        created = page.run("""return out(await navigator.credentials.create({publicKey: {
            rp: {id: 'localhost', name: 'Bridge check'},
            user: {id: new TextEncoder().encode(%s), name: %s, displayName: %s},
            challenge: dec(%s), pubKeyCredParams: [{type: 'public-key', alg: %d}],
            authenticatorSelection: {authenticatorAttachment: 'platform', residentKey: 'required', userVerification: 'required'},
            extensions: {credProps: true}, timeout: 20000}}))""" % (
            json.dumps(user), json.dumps(user), json.dumps(user), json.dumps(encode(options["publicKey"]["challenge"])), alg))
        if "error" in created:
            report(f"platform create alg={alg}", False, json.dumps(created))
            continue
        auth = server.register_complete(
            state, CollectedClientData(decode(created["client"])), AttestationObject(decode(created["attestation"])))
        credentials.append(auth.credential_data)
        report(f"platform create alg={alg}, verified by Fido2Server",
               auth.credential_data.public_key[3] == alg and auth.is_user_verified()
               and created["attachment"] == "platform" and created["extensions"] == {"credProps": {"rk": True}}
               and created["publicKeyAlgorithm"] == alg and created["publicKey"] is not None
               and created["transports"] == ["internal", "usb"],
               json.dumps({k: created[k] for k in ("attachment", "extensions", "transports", "publicKeyAlgorithm")}))

        options, state = server.authenticate_begin([auth.credential_data], user_verification="required")
        signed = page.run("""return out(await navigator.credentials.get({publicKey: {
            rpId: 'localhost', challenge: dec(%s), userVerification: 'required', timeout: 20000,
            allowCredentials: [{type: 'public-key', id: dec(%s)}]}}))""" % (
            json.dumps(encode(options["publicKey"]["challenge"])), json.dumps(created["rawId"])))
        report(f"get with allowCredentials alg={alg}, verified by Fido2Server",
               "error" not in signed and verify(server, state, credentials, signed, AuthenticatorData, CollectedClientData)
               and decode(signed["user"]) == user.encode(), json.dumps(signed.get("error")))

    options, state = server.authenticate_begin(user_verification="required")
    signed = page.run("""return out(await navigator.credentials.get({publicKey: {
        rpId: 'localhost', challenge: dec(%s), userVerification: 'required', timeout: 20000}}))""" % (
        json.dumps(encode(options["publicKey"]["challenge"]))))
    report("get without allowCredentials (discoverable), verified by Fido2Server",
           "error" not in signed and verify(server, state, credentials, signed, AuthenticatorData, CollectedClientData),
           "signed in as " + decode(signed["user"]).decode() if "user" in signed else json.dumps(signed))

    if credentials:
        excluded = page.run("""return out(await navigator.credentials.create({publicKey: {
            rp: {id: 'localhost', name: 'Bridge check'},
            user: {id: new TextEncoder().encode('other'), name: 'other', displayName: 'other'},
            challenge: new Uint8Array(32), pubKeyCredParams: [{type: 'public-key', alg: -7}],
            excludeCredentials: [{type: 'public-key', id: dec(%s)}],
            authenticatorSelection: {authenticatorAttachment: 'platform'}, timeout: 20000}}))""" % (
            json.dumps(encode(credentials[0].credential_id))))
        report("create with an excluded credential fails with InvalidStateError",
               excluded.get("error") == "InvalidStateError", json.dumps(excluded.get("error")))

    conditional = page.run("""document.getElementById('name').focus();
        return out(await Promise.race([
          navigator.credentials.get({mediation: 'conditional', publicKey: {rpId: 'localhost', challenge: new Uint8Array(32)}}),
          new Promise((_, reject) => setTimeout(() => reject({name: 'Pending'}), 5000))]))""")
    report("conditional get is refused while the extension is attached (expected limitation)",
           conditional.get("error") == "NotAllowedError", json.dumps(conditional))


def verify(server, state, credentials, signed, AuthenticatorData, CollectedClientData):
    auth_data = AuthenticatorData(decode(signed["auth"]))
    server.authenticate_complete(
        state, credentials, decode(signed["rawId"]), CollectedClientData(decode(signed["client"])),
        auth_data, decode(signed["signature"]))
    return signed["attachment"] == "platform" and auth_data.is_user_verified()


def main(chrome):
    os.makedirs("/tmp/lpk-bridge", exist_ok=True)
    profile = tempfile.mkdtemp(prefix="bridge-check-", dir="/tmp/lpk-bridge")
    state = os.path.join(profile, "localpasskey")
    os.makedirs(state)
    wrapper = os.path.join(profile, "host.sh")
    with open(wrapper, "w") as f:
        # Chromium appends the caller origin and --parent-window; not needed.
        f.write(f"#!/bin/sh\ncd {REPO} && exec {sys.executable} -m tests.browser.bridge_check --host {state}\n")
    os.chmod(wrapper, 0o755)
    os.makedirs(os.path.join(profile, "NativeMessagingHosts"))
    with open(os.path.join(profile, "NativeMessagingHosts", HOST + ".json"), "w") as f:
        json.dump({"name": HOST, "description": "LocalPasskey bridge check", "path": wrapper,
                   "type": "stdio", "allowed_origins": [f"chrome-extension://{EXTENSION_ID}/"]}, f)
    www, cdp = free_port(), free_port()
    page_server = serve_page(www)
    browser = subprocess.Popen([
        chrome, "--headless=new", f"--user-data-dir={profile}", f"--remote-debugging-port={cdp}",
        "--remote-debugging-address=127.0.0.1", f"--load-extension={EXTENSION}",
        f"--disable-extensions-except={EXTENSION}", "--proxy-server=http://127.0.0.1:9",
        "--disable-background-networking", "--disable-component-update", "--disable-sync",
        "--no-first-run", "--no-default-browser-check", "--password-store=basic", "about:blank",
    ], stdout=open(profile + ".log", "w"), stderr=subprocess.STDOUT)
    results = []
    try:
        targets = []
        for _ in range(100):
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{cdp}/json/list", timeout=1) as response:
                    targets = json.load(response)
                if any(t["url"] == f"chrome-extension://{EXTENSION_ID}/service_worker.js" for t in targets):
                    break
            except OSError:
                pass
            time.sleep(0.2)
        assert any(t["url"] == f"chrome-extension://{EXTENSION_ID}/service_worker.js" for t in targets), targets
        time.sleep(1)  # let the service worker attach
        page = Page(next(t for t in targets if t["type"] == "page")["webSocketDebuggerUrl"])
        page.command("Page.enable")
        page.command("Page.navigate", url=f"http://localhost:{www}/")
        time.sleep(1)
        check(page, results)
        with open(os.path.join(state, "parents")) as f:
            parents = sorted(set(f.read().splitlines()))
        print(f"INFO approval dialog would name the host's parent: {parents}", flush=True)
    finally:
        browser.terminate()
        try:
            browser.wait(10)
        except subprocess.TimeoutExpired:
            browser.kill()
        page_server.shutdown()
        with open(profile + ".log", errors="replace") as f:
            crashed = "Fatal Python error" in f.read()
        results.append(("host processes exit cleanly", not crashed))
        print(f"{'FAIL' if crashed else 'OK  '} host processes exit cleanly (see {profile}.log)", flush=True)
        shutil.rmtree(profile, ignore_errors=True)
    failed = [name for name, ok in results if not ok]
    print(f"{len(results) - len(failed)}/{len(results)} checks passed", flush=True)
    return 1 if failed or not results else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--chrome", default=CHROME)
    parser.add_argument("--host", metavar="STATE_DIR", help=argparse.SUPPRESS)
    args, _ = parser.parse_known_args()  # the browser adds its own arguments in --host mode
    sys.exit(host(args.host) if args.host else main(args.chrome))
