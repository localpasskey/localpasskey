"""Test doubles: an in-process CTAPHID host built on python-fido2."""

import os
import pwd
import queue
import tempfile
import threading
import time

import fido2.client
import fido2.features
from fido2.ctap2.pin import ClientPin
from fido2.hid import CtapHidDevice
from fido2.hid.base import CtapHidConnection, HidDescriptor

from localpasskey.clientpin import PinManager
from localpasskey.ctap2 import Authenticator, Requester, Verdict
from localpasskey.ctaphid import CtapHidTransport
from localpasskey.store import CredentialStore


class _BuiltInUvClientPin(ClientPin):
    # python-fido2 1.2 insists on a PIN/UV protocol even when it is about to use
    # built-in UV with uv=true, which needs none; browsers don't.
    def __init__(self, ctap, protocol=None):
        try:
            super().__init__(ctap, protocol)
        except ValueError:
            self.ctap = ctap
            self.protocol = None


fido2.client.ClientPin = _BuiltInUvClientPin
fido2.features.webauthn_json_mapping.enabled = False


class FakeResolver:
    def __init__(self, requester):
        self.requester = requester

    def resolve(self):
        return self.requester


class FakeVerifier:
    """Answers every prompt with ``verdict``, optionally after ``delay``."""

    def __init__(self, verdict=Verdict.APPROVED, delay=0.0):
        self.verdict = verdict
        self.delay = delay
        self.messages = []
        self.saw_cancel = threading.Event()

    def verify(self, requester, message, cancelled, timeout):
        self.messages.append(message)
        if self.delay and cancelled.wait(self.delay):
            self.saw_cancel.set()
            return Verdict.CANCELLED
        return self.verdict


class FakeNotifier:
    def __init__(self):
        self.notes = []

    def notify(self, requester, summary, body, kind="problem"):
        self.notes.append((summary, body, kind))

    def summaries(self):
        return [note[0] for note in self.notes]


class LoopbackConnection(CtapHidConnection):
    """Feeds python-fido2's HID packets straight into our transport."""

    def __init__(self, authenticator):
        self.reports = queue.Queue()
        self.transport = CtapHidTransport(self.reports.put, authenticator, (0, 1, 0))
        self._closed = threading.Event()
        threading.Thread(target=self._tick, daemon=True).start()

    def _tick(self):
        while not self._closed.wait(0.02):
            self.transport.tick()

    def write_packet(self, data):
        self.transport.handle_report(data)

    def read_packet(self):
        return self.reports.get(timeout=10)

    def close(self):
        self._closed.set()


class Harness:
    def __init__(self, verdict=Verdict.APPROVED, delay=0.0, prompt_timeout=5.0):
        self._tmp = tempfile.TemporaryDirectory()
        self.store = CredentialStore(self._tmp.name)
        self.requester = Requester(
            uid=os.getuid(),
            username=pwd.getpwuid(os.getuid()).pw_name,
            pid=os.getpid(),
            app_name="Test Browser",
        )
        self.verifier = FakeVerifier(verdict, delay)
        self.notifier = FakeNotifier()
        self.pins = PinManager(self.store)
        self.authenticator = Authenticator(
            self.store,
            FakeResolver(self.requester),
            self.verifier,
            self.notifier,
            prompt_timeout,
            pins=self.pins,
        )
        self.connection = LoopbackConnection(self.authenticator)
        self.device = self.open_device()

    def open_device(self):
        descriptor = HidDescriptor("loopback", 0x1209, 0x4C50, 64, 64, "LocalPasskey", None)
        return CtapHidDevice(descriptor, self.connection)

    def credentials(self):
        return self.store.credentials(self.requester.uid, self.requester.username)

    def wait_idle(self, timeout=5.0):
        deadline = time.monotonic() + timeout
        while self.connection.transport._busy is not None and time.monotonic() < deadline:
            time.sleep(0.02)

    def close(self):
        self.wait_idle()
        self.connection.close()
        self._tmp.cleanup()
