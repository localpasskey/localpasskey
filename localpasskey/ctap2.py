"""CTAP 2.0 authenticator logic: the part that talks to browsers about passkeys.

The authenticator advertises built-in user verification (the ``uv`` option),
which is how browsers treat a fingerprint security key: they send the request
as-is and let the authenticator verify the user. Here the verification is a
polkit authentication dialog in the requesting user's desktop session (see
``polkit.py``), comparable to the Windows Hello prompt.

Supported commands: authenticatorGetInfo, authenticatorMakeCredential,
authenticatorGetAssertion and authenticatorGetNextAssertion. Credentials are
stored per Linux user, so every account on the machine has its own passkeys.
"""

from __future__ import annotations

import enum
import hashlib
import logging
import secrets
import struct
import threading
import time
from dataclasses import dataclass
from typing import List, Optional

from . import __version__, cbor, cose
from .ctaphid import MAX_MESSAGE
from .notify import ACTIVITY, ERROR, PROBLEM
from .store import Credential, CredentialStore, StoreError, StoreFull

log = logging.getLogger(__name__)

# Firefox passes the AAGUID on to websites; one that only this software uses
# would let sites recognise the same person across sites.
AAGUID = bytes(16)

CMD_MAKE_CREDENTIAL = 0x01
CMD_GET_ASSERTION = 0x02
CMD_GET_INFO = 0x04
CMD_RESET = 0x07
CMD_GET_NEXT_ASSERTION = 0x08

CTAP2_OK = 0x00
CTAP1_ERR_INVALID_COMMAND = 0x01
CTAP1_ERR_INVALID_PARAMETER = 0x02
CTAP1_ERR_INVALID_LENGTH = 0x03
CTAP2_ERR_CBOR_UNEXPECTED_TYPE = 0x11
CTAP2_ERR_INVALID_CBOR = 0x12
CTAP2_ERR_MISSING_PARAMETER = 0x14
CTAP2_ERR_CREDENTIAL_EXCLUDED = 0x19
CTAP2_ERR_UNSUPPORTED_ALGORITHM = 0x26
CTAP2_ERR_OPERATION_DENIED = 0x27
CTAP2_ERR_KEY_STORE_FULL = 0x28
CTAP2_ERR_UNSUPPORTED_OPTION = 0x2B
CTAP2_ERR_INVALID_OPTION = 0x2C
CTAP2_ERR_KEEPALIVE_CANCEL = 0x2D
CTAP2_ERR_NO_CREDENTIALS = 0x2E
CTAP2_ERR_USER_ACTION_TIMEOUT = 0x2F
CTAP2_ERR_NOT_ALLOWED = 0x30
CTAP2_ERR_PIN_AUTH_INVALID = 0x33
CTAP1_ERR_OTHER = 0x7F

STATUS_PROCESSING = 1
STATUS_UPNEEDED = 2

FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_AT = 0x40
FLAG_ED = 0x80

CREDENTIAL_ID_LENGTH = 32
MAX_USER_ID_LENGTH = 64
MAX_CREDENTIALS_IN_LIST = 8
MAX_CREDENTIAL_ID_LENGTH = 512
MAX_LABEL_LENGTH = 255

# Chrome and libfido2 use ".dummy", Firefox uses "make.me.blink" for the fake
# registration that stands in for "touch the security key you want to use".
DUMMY_RP_IDS = frozenset({".dummy", "make.me.blink"})
NO_CREDENTIALS_MEMORY = 30.0
PREVERIFIED_WINDOW = 60.0
NEXT_ASSERTION_TIMEOUT = 30.0
DECLINE_MEMORY = 2.0
# Identical problem notifications to the same user within this time are
# dropped, so that a site retrying in a loop can't flood the history.
NOTIFICATION_MEMORY = 60.0


class CtapError(Exception):
    def __init__(self, code, reason=""):
        super().__init__(f"0x{code:02x} {reason}".strip())
        self.code = code


class Verdict(enum.Enum):
    APPROVED = "approved"
    DENIED = "denied"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed out"
    UNAVAILABLE = "unavailable"


_VERDICT_ERRORS = {
    Verdict.DENIED: CTAP2_ERR_OPERATION_DENIED,
    Verdict.CANCELLED: CTAP2_ERR_KEEPALIVE_CANCEL,
    Verdict.TIMED_OUT: CTAP2_ERR_USER_ACTION_TIMEOUT,
    Verdict.UNAVAILABLE: CTAP2_ERR_OPERATION_DENIED,
}


@dataclass
class Requester:
    """The local user (and, if known, the application) behind a request."""

    uid: int
    username: str
    pid: Optional[int] = None
    app_name: Optional[str] = None


@dataclass
class _PendingAssertions:
    requester: Requester
    rp_id: str
    client_data_hash: bytes
    flags: int
    remaining: List[Credential]
    deadline: float


class ChannelState:
    """What the authenticator remembers per CTAPHID channel between commands."""

    def __init__(self):
        self.pending_assertions: Optional[_PendingAssertions] = None
        self.no_credentials_rp: Optional[str] = None
        self.no_credentials_at = 0.0
        self.preverified_until = 0.0
        self.preverified_requester: Optional[Requester] = None
        self.declined: Optional[tuple] = None

    def just_declined(self, request) -> bool:
        declined, self.declined = self.declined, None
        return (
            declined is not None
            and declined[0] == request
            and time.monotonic() - declined[1] < DECLINE_MEMORY
        )

    def recently_missed(self) -> bool:
        return (
            self.no_credentials_rp is not None
            and time.monotonic() - self.no_credentials_at < NO_CREDENTIALS_MEMORY
        )

    def take_preverification(self, requester) -> bool:
        valid = requester == self.preverified_requester and time.monotonic() < self.preverified_until
        self.preverified_until = 0.0
        self.preverified_requester = None
        return valid


def _param(container, key, kind, default=...):
    if key not in container:
        if default is ...:
            raise CtapError(CTAP2_ERR_MISSING_PARAMETER, f"missing {key!r}")
        return default
    value = container[key]
    if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
        raise CtapError(CTAP2_ERR_CBOR_UNEXPECTED_TYPE, f"bad type for {key!r}")
    return value


def _reject_pin_uv_auth(params, auth_key, protocol_key):
    # Neither clientPin nor pinUvAuthToken is advertised, so platforms have no
    # business sending a pinUvAuthParam.
    if auth_key in params:
        if protocol_key not in params:
            raise CtapError(CTAP2_ERR_MISSING_PARAMETER, "pinUvAuthProtocol missing")
        raise CtapError(CTAP2_ERR_PIN_AUTH_INVALID, "PIN/UV auth tokens are not supported")


def _descriptor_ids(descriptors):
    ids = []
    for descriptor in descriptors:
        if not isinstance(descriptor, dict):
            raise CtapError(CTAP2_ERR_CBOR_UNEXPECTED_TYPE, "credential descriptor")
        cred_type = _param(descriptor, "type", str)
        cred_id = _param(descriptor, "id", bytes)
        if cred_type == "public-key":
            ids.append(cred_id)
    return ids


def _choose_algorithm(cred_params):
    for entry in cred_params:
        if not isinstance(entry, dict):
            raise CtapError(CTAP2_ERR_CBOR_UNEXPECTED_TYPE, "pubKeyCredParams entry")
        cred_type = _param(entry, "type", str)
        alg = _param(entry, "alg", int)
        if cred_type == "public-key" and alg in cose.SUPPORTED_ALGORITHMS:
            return alg
    raise CtapError(CTAP2_ERR_UNSUPPORTED_ALGORITHM)


def _cred_protect_allows(cred, verified, discoverable_flow):
    if cred.cred_protect == 3:  # userVerificationRequired
        return verified
    if cred.cred_protect == 2:  # userVerificationOptionalWithCredentialIDList
        return verified or not discoverable_flow
    return True


def _auth_data(rp_id, flags, attested=None, extensions=None):
    if attested is not None:
        flags |= FLAG_AT
    if extensions:
        flags |= FLAG_ED
    # The signature counter is always 0 ("not supported"). Answering for the
    # account chooser signs for every account on a site, so moving counters
    # would let the site link accounts that live on this authenticator.
    data = hashlib.sha256(rp_id.encode("utf-8")).digest() + struct.pack(">BI", flags, 0)
    if attested is not None:
        cred_id, cose_key = attested
        data += AAGUID + struct.pack(">H", len(cred_id)) + cred_id + cbor.encode(cose_key)
    if extensions:
        data += cbor.encode(extensions)
    return data


def _label(text, limit=64):
    """Make RP-supplied text safe and short enough for a system dialog."""
    text = "".join(ch for ch in text if ch.isprintable()).strip()
    text = text.replace("$(", "$ (")  # polkit expands $(name) in messages
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _account(user_name, display_name):
    return _label(user_name or display_name) or "an unnamed account"


def _version_number():
    major, minor, patch = (int(p) for p in __version__.split(".")[:3])
    return major << 16 | minor << 8 | patch


class Authenticator:
    def __init__(
        self,
        store: CredentialStore,
        resolver,
        verifier,
        notifier=None,
        prompt_timeout: float = 120.0,
    ):
        """``resolver.resolve()`` returns the Requester behind the current
        request (or None); ``verifier.verify(requester, message, cancelled,
        timeout)`` asks that user to approve and returns a Verdict;
        ``notifier.notify(requester, summary, body, kind)`` shows a desktop
        notification of the given ``notify`` kind."""
        self.store = store
        self.resolver = resolver
        self.verifier = verifier
        self.notifier = notifier
        self.prompt_timeout = prompt_timeout
        self._recent_notes = {}
        self._notes_lock = threading.Lock()
        self._handlers = {
            CMD_GET_INFO: self._get_info,
            CMD_MAKE_CREDENTIAL: self._make_credential,
            CMD_GET_ASSERTION: self._get_assertion,
            CMD_GET_NEXT_ASSERTION: self._get_next_assertion,
            CMD_RESET: self._reset,
        }

    def new_channel_state(self) -> ChannelState:
        return ChannelState()

    def process(self, request: bytes, ctx) -> bytes:
        """Handle one authenticatorAPI request (command byte + CBOR map).

        ``ctx`` provides ``channel`` (a ChannelState), ``cancelled`` (a
        threading.Event set when the platform cancels) and ``set_status()``
        (selects the CTAPHID keepalive status).
        """
        if not request:
            return bytes([CTAP1_ERR_INVALID_LENGTH])
        command, payload = request[0], request[1:]
        if command != CMD_GET_NEXT_ASSERTION:
            ctx.channel.pending_assertions = None
        handler = self._handlers.get(command)
        if handler is None:
            log.debug("Unsupported CTAP2 command 0x%02x", command)
            return bytes([CTAP1_ERR_INVALID_COMMAND])
        try:
            response = handler(self._decode_params(payload), ctx)
        except CtapError as e:
            log.debug("CTAP2 command 0x%02x failed: %s", command, e)
            return bytes([e.code])
        except StoreError as e:
            log.error("Credential store error: %s", e)
            self._notify_failure()
            return bytes([CTAP1_ERR_OTHER])
        except Exception:
            log.exception("Unexpected error in CTAP2 command 0x%02x", command)
            self._notify_failure()
            return bytes([CTAP1_ERR_OTHER])
        return bytes([CTAP2_OK]) + cbor.encode(response)

    def _notify_failure(self):
        try:
            requester = self.resolver.resolve()
        except Exception:
            log.exception("Could not tell whom to tell about the failed request")
            return
        self._notify(
            requester,
            "Passkey request failed",
            "Something went wrong while answering a passkey request. Details are in the "
            "system log (journalctl -u localpasskey).",
            ERROR,
        )

    @staticmethod
    def _decode_params(payload):
        if not payload:
            return {}
        try:
            params = cbor.decode(payload)
        except cbor.CBORDecodeError as e:
            raise CtapError(CTAP2_ERR_INVALID_CBOR, str(e)) from None
        if not isinstance(params, dict):
            raise CtapError(CTAP2_ERR_CBOR_UNEXPECTED_TYPE, "parameters are not a map")
        return params

    def _get_info(self, params, ctx):
        return {
            0x01: ["FIDO_2_0"],
            0x02: ["credProtect"],
            0x03: AAGUID,
            0x04: {"rk": True, "up": True, "uv": True, "plat": False},
            0x05: MAX_MESSAGE,
            0x07: MAX_CREDENTIALS_IN_LIST,
            0x08: MAX_CREDENTIAL_ID_LENGTH,
            0x09: ["usb"],
            0x0A: [{"alg": alg, "type": "public-key"} for alg in cose.SUPPORTED_ALGORITHMS],
            0x0E: _version_number(),
        }

    def _reset(self, params, ctx):
        log.info("Refusing authenticatorReset; delete passkeys with `localpasskey delete` instead")
        raise CtapError(CTAP2_ERR_NOT_ALLOWED)

    def _requester(self) -> Requester:
        requester = self.resolver.resolve()
        if requester is None:
            log.warning("Could not tell which local user sent the request; denying it")
            raise CtapError(CTAP2_ERR_OPERATION_DENIED)
        return requester

    def _require_approval(self, requester, message, ctx, request, action):
        """Ask the user; ``request`` identifies the ceremony as
        (command, RP ID, clientDataHash), ``action`` completes "the request
        to ..." in notifications."""
        if ctx.channel.just_declined(request):
            # Firefox takes OPERATION_DENIED from built-in UV for a misread
            # fingerprint and resends the request at once; the user said no.
            raise CtapError(CTAP2_ERR_KEEPALIVE_CANCEL)
        ctx.set_status(STATUS_UPNEEDED)
        try:
            verdict = self.verifier.verify(requester, message, ctx.cancelled, self.prompt_timeout)
        finally:
            ctx.set_status(STATUS_PROCESSING)
        if verdict is Verdict.APPROVED and ctx.cancelled.is_set():
            verdict = Verdict.CANCELLED
        if verdict is Verdict.APPROVED:
            return
        log.info("User verification for uid %d %s", requester.uid, verdict.value)
        if verdict in (Verdict.DENIED, Verdict.UNAVAILABLE):
            ctx.channel.declined = (request, time.monotonic())
        if verdict is Verdict.UNAVAILABLE:
            self._notify(
                requester,
                "Passkey request blocked",
                "LocalPasskey could not ask you to confirm a passkey request. Make sure a "
                "polkit authentication agent is running in your desktop session.",
            )
        elif verdict is Verdict.DENIED:
            self._notify(
                requester, "Passkey request declined", f"The request to {action} was not confirmed."
            )
        elif verdict is Verdict.TIMED_OUT:
            self._notify(
                requester,
                "Passkey request timed out",
                f"The request to {action} was not confirmed in time.",
            )
        # CANCELLED means the browser gave up, for example because another
        # security key answered; that needs no notification.
        raise CtapError(_VERDICT_ERRORS[verdict])

    def _notify(self, requester, summary, body, kind=PROBLEM):
        if self.notifier is None or requester is None:
            return
        if kind != ACTIVITY and self._repeated(requester, summary, body):
            log.debug("Not repeating the notification %r", summary)
            return
        try:
            self.notifier.notify(requester, summary, body, kind)
        except Exception:
            log.exception("Could not show a desktop notification")

    def _repeated(self, requester, summary, body):
        # Every use of a passkey is worth a note, but a problem only once.
        now = time.monotonic()
        note = (requester.uid, summary, body)
        with self._notes_lock:
            self._recent_notes = {
                key: at for key, at in self._recent_notes.items() if now - at < NOTIFICATION_MEMORY
            }
            if note in self._recent_notes:
                return True
            self._recent_notes[note] = now
            return False

    @staticmethod
    def _app(requester):
        return _label(requester.app_name or "", 40) or "An application"

    def _make_credential(self, params, ctx):
        client_data_hash = _param(params, 0x01, bytes)
        if len(client_data_hash) != 32:
            raise CtapError(CTAP1_ERR_INVALID_PARAMETER, "clientDataHash must be 32 bytes")
        rp = _param(params, 0x02, dict)
        user = _param(params, 0x03, dict)
        cred_params = _param(params, 0x04, list)
        exclude_list = _param(params, 0x05, list, [])
        extensions = _param(params, 0x06, dict, {})
        options = _param(params, 0x07, dict, {})
        _reject_pin_uv_auth(params, 0x08, 0x09)
        if 0x0A in params:
            raise CtapError(CTAP1_ERR_INVALID_PARAMETER, "enterprise attestation is not supported")

        rp_id = _param(rp, "id", str)
        rp_name = _param(rp, "name", str, "")
        user_id = _param(user, "id", bytes)
        user_name = _param(user, "name", str, "")
        display_name = _param(user, "displayName", str, "")
        if len(user_id) > MAX_USER_ID_LENGTH:
            raise CtapError(CTAP1_ERR_INVALID_PARAMETER, "user id too long")
        rk = _param(options, "rk", bool, False)
        _param(options, "uv", bool, False)  # the user is verified either way
        if not _param(options, "up", bool, True):
            raise CtapError(CTAP2_ERR_INVALID_OPTION, "up=false is not valid for makeCredential")
        alg = _choose_algorithm(cred_params)
        cred_protect = extensions.get("credProtect")
        if isinstance(cred_protect, bool) or cred_protect not in (1, 2, 3):
            cred_protect = None
        excluded_ids = set(_descriptor_ids(exclude_list))

        request = (CMD_MAKE_CREDENTIAL, rp_id, client_data_hash)
        if rp_id in DUMMY_RP_IDS:
            return self._touch_request(rp_id, request, ctx)

        # A real registration answers its own prompt, so it uses up any touch approval.
        ctx.channel.take_preverification(None)
        requester = self._requester()
        site, account, app = _label(rp_id), _account(user_name, display_name), self._app(requester)
        stored = self.store.credentials(requester.uid, requester.username)
        if any(c.rp_id == rp_id and c.id in excluded_ids for c in stored):
            # CTAP wants user interaction before revealing that a credential
            # exists, so that sites cannot silently probe for it.
            self._require_approval(
                requester,
                f"{app} wants to save a passkey on {site}, but a passkey for this "
                "account is already stored on this computer.",
                ctx,
                request,
                f"save a passkey on {site}",
            )
            self._notify(
                requester,
                "Passkey already saved",
                f"A passkey for this account on {site} is already stored on this computer, "
                "so no new one was saved.",
            )
            raise CtapError(CTAP2_ERR_CREDENTIAL_EXCLUDED)

        self._require_approval(
            requester,
            f"{app} wants to save a passkey for “{account}” on {site}.",
            ctx,
            request,
            f"save a passkey on {site}",
        )

        private_key = cose.generate_private_key(alg)
        cred_id = secrets.token_bytes(CREDENTIAL_ID_LENGTH)
        cred = Credential(
            id=cred_id,
            rp_id=rp_id,
            user_id=user_id,
            alg=alg,
            sealed_key=self.store.seal(requester.uid, cred_id, cose.private_key_to_bytes(private_key)),
            rp_name=rp_name[:MAX_LABEL_LENGTH],
            user_name=user_name[:MAX_LABEL_LENGTH],
            user_display_name=display_name[:MAX_LABEL_LENGTH],
            discoverable=rk,
            cred_protect=cred_protect or 1,
            created=time.time(),
        )
        try:
            self.store.add(requester.uid, requester.username, cred)
        except StoreFull:
            self._notify(
                requester,
                "Passkey not saved",
                f"No more passkeys fit on this computer, so none was saved for {site}. "
                "Delete passkeys you no longer need with LocalPasskey or `localpasskey delete`.",
                ERROR,
            )
            raise CtapError(CTAP2_ERR_KEY_STORE_FULL) from None
        log.info(
            "Saved a new %s passkey (%s) for uid %d",
            "discoverable" if rk else "server-side",
            cose.ALGORITHM_NAMES[alg],
            requester.uid,
        )
        log.debug("New passkey %s is for %s", cred_id.hex()[:12], rp_id)
        self._notify(requester, "Passkey saved", f"{app} saved a passkey for “{account}” on {site}.", ACTIVITY)

        auth_data = _auth_data(
            rp_id,
            FLAG_UP | FLAG_UV,
            attested=(cred_id, cose.public_key(private_key, alg)),
            extensions={"credProtect": cred.cred_protect} if cred_protect else None,
        )
        return {1: "none", 2: auth_data, 3: {}}

    def _wait_untouched(self, requester, rp_id, ctx):
        """Act like a security key that nobody touches, until the platform
        gives up or cancels.

        Used when a site asks for a passkey this computer doesn't have:
        browsers end the whole request when an authenticator with built-in
        user verification reports NO_CREDENTIALS, which would keep the user
        from using another security key instead.
        """
        self._notify(
            requester,
            "No passkey for this site",
            f"No passkey for {_label(rp_id)} is stored on this computer. "
            "Use another security key or sign in another way.",
        )
        ctx.set_status(STATUS_UPNEEDED)
        if ctx.cancelled.wait(self.prompt_timeout):
            raise CtapError(CTAP2_ERR_KEEPALIVE_CANCEL)
        raise CtapError(CTAP2_ERR_USER_ACTION_TIMEOUT)

    def _touch_request(self, rp_id, request, ctx):
        """Answer the dummy registration platforms use to collect a "touch".

        Chrome sends one after its silent probes found none of the requested
        credentials here, before it reports "not registered". Firefox and
        libfido2 send one to let the user choose between several security keys.
        """
        state = ctx.channel
        if state.recently_missed():
            self._wait_untouched(self.resolver.resolve(), state.no_credentials_rp, ctx)

        requester = self._requester()
        self._require_approval(
            requester,
            f"{self._app(requester)} wants to use a passkey stored on this computer.",
            ctx,
            request,
            "use a passkey",
        )
        # The real request follows on the same channel; don't ask twice.
        state.preverified_until = time.monotonic() + PREVERIFIED_WINDOW
        state.preverified_requester = requester
        throwaway = cose.generate_private_key(cose.ES256)
        auth_data = _auth_data(
            rp_id,
            FLAG_UP | FLAG_UV,
            attested=(secrets.token_bytes(CREDENTIAL_ID_LENGTH), cose.public_key(throwaway, cose.ES256)),
        )
        return {1: "none", 2: auth_data, 3: {}}

    def _get_assertion(self, params, ctx):
        rp_id = _param(params, 0x01, str)
        client_data_hash = _param(params, 0x02, bytes)
        if len(client_data_hash) != 32:
            raise CtapError(CTAP1_ERR_INVALID_PARAMETER, "clientDataHash must be 32 bytes")
        allow_list = _param(params, 0x03, list, [])
        _param(params, 0x04, dict, {})  # no getAssertion extensions are supported
        options = _param(params, 0x05, dict, {})
        _reject_pin_uv_auth(params, 0x06, 0x07)
        if "rk" in options:
            raise CtapError(CTAP2_ERR_UNSUPPORTED_OPTION, "rk is not valid for getAssertion")
        up = _param(options, "up", bool, True)
        uv = _param(options, "uv", bool, False)
        interactive = up or uv
        allowed_ids = _descriptor_ids(allow_list)

        requester = self._requester()
        stored = [
            c for c in self.store.credentials(requester.uid, requester.username) if c.rp_id == rp_id
        ]
        discoverable_flow = not allow_list
        if discoverable_flow:
            candidates = sorted((c for c in stored if c.discoverable), key=lambda c: -c.created)
        else:
            by_id = {c.id: c for c in stored}
            candidates = [by_id[i] for i in dict.fromkeys(allowed_ids) if i in by_id]
        candidates = [c for c in candidates if _cred_protect_allows(c, interactive, discoverable_flow)]

        state = ctx.channel
        # The touch approval covers this request whether or not it finds a passkey.
        preverified = interactive and state.take_preverification(requester)
        if not candidates:
            log.debug("No passkey for %s (uid %d)", rp_id, requester.uid)
            if interactive:
                self._wait_untouched(requester, rp_id, ctx)
            state.no_credentials_rp, state.no_credentials_at = rp_id, time.monotonic()
            raise CtapError(CTAP2_ERR_NO_CREDENTIALS)
        state.no_credentials_rp = None

        flags = 0
        site, app = _label(rp_id), self._app(requester)
        signing_in = f"sign in to {site}"
        if len(candidates) == 1:
            account = _account(candidates[0].user_name, candidates[0].user_display_name)
            signing_in_as = f"{signing_in} as “{account}”"
            message = f"{app} wants to {signing_in_as} with a passkey stored on this computer."
        else:
            signing_in_as = signing_in
            message = (
                f"{app} wants to {signing_in} with one of your "
                f"{len(candidates)} passkeys stored on this computer."
            )
        if interactive:
            if not preverified:
                # Account names come from the site; problem notifications
                # stay in the history, so they only name the site.
                self._require_approval(
                    requester, message, ctx, (CMD_GET_ASSERTION, rp_id, client_data_hash), signing_in
                )
            flags = FLAG_UP | FLAG_UV

        first, rest = candidates[0], candidates[1:]
        response = self._assertion(requester, rp_id, client_data_hash, first, flags, discoverable_flow)
        if discoverable_flow and rest:
            response[0x05] = len(candidates)
            state.pending_assertions = _PendingAssertions(
                requester, rp_id, client_data_hash, flags, rest,
                time.monotonic() + NEXT_ASSERTION_TIMEOUT,
            )
        log.info("Signed in uid %d with a passkey (%d candidate(s))", requester.uid, len(candidates))
        # Silent (up=false) assertions are browsers checking which key holds
        # a credential, not sign-ins.
        if interactive:
            self._notify(
                requester, "Signed in with a passkey", f"{app} used a passkey to {signing_in_as}.", ACTIVITY
            )
        return response

    def _get_next_assertion(self, params, ctx):
        pending = ctx.channel.pending_assertions
        if (pending is None or time.monotonic() > pending.deadline
                or self.resolver.resolve() != pending.requester):
            ctx.channel.pending_assertions = None
            raise CtapError(CTAP2_ERR_NOT_ALLOWED, "no assertions pending")
        cred = pending.remaining.pop(0)
        if pending.remaining:
            pending.deadline = time.monotonic() + NEXT_ASSERTION_TIMEOUT
        else:
            ctx.channel.pending_assertions = None
        return self._assertion(
            pending.requester, pending.rp_id, pending.client_data_hash, cred, pending.flags, True
        )

    def _assertion(self, requester, rp_id, client_data_hash, cred, flags, discoverable_flow):
        # A silent (up=false) probe is not a use: check the credential still exists without rewriting the file.
        if flags & FLAG_UP:
            try:
                self.store.record_use(requester.uid, requester.username, cred.id)
            except KeyError:
                raise CtapError(CTAP2_ERR_NO_CREDENTIALS, "credential was deleted") from None
        elif all(c.id != cred.id for c in self.store.credentials(requester.uid, requester.username)):
            raise CtapError(CTAP2_ERR_NO_CREDENTIALS, "credential was deleted")
        auth_data = _auth_data(rp_id, flags)
        private_key = cose.private_key_from_bytes(self.store.unseal(requester.uid, cred))
        response = {
            0x01: {"id": cred.id, "type": "public-key"},
            0x02: auth_data,
            0x03: cose.sign(private_key, cred.alg, auth_data + client_data_hash),
        }
        if cred.discoverable:
            user = {"id": cred.user_id}
            # Names are only revealed after user verification, for the
            # platform's account chooser.
            if discoverable_flow and flags & FLAG_UV:
                if cred.user_name:
                    user["name"] = cred.user_name
                if cred.user_display_name:
                    user["displayName"] = cred.user_display_name
            response[0x04] = user
        return response
