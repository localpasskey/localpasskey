import hashlib
import os
import pwd
import stat
import tempfile
import unittest
from unittest.mock import patch

from fido2.ctap2.pin import PinProtocolV1, PinProtocolV2

from localpasskey import clientpin
from localpasskey.clientpin import (
    MAX_PIN_RETRIES,
    PIN_AUTH_BLOCKED,
    PIN_AUTH_INVALID,
    PIN_BLOCKED,
    PIN_INVALID,
    PIN_NOT_SET,
    PIN_POLICY_VIOLATION,
    TOKEN_LIFETIME,
    PinError,
    PinManager,
)
from localpasskey.ctap2 import Requester
from localpasskey.store import CredentialStore, PinState

UID = os.getuid()
USERNAME = pwd.getpwuid(UID).pw_name


def requester(**overrides):
    fields = dict(uid=UID, username=USERNAME, pid=os.getpid(), app_name="Test Browser")
    fields.update(overrides)
    return Requester(**fields)


class CryptoTestCase(unittest.TestCase):
    """The PIN/UV protocols, checked against python-fido2 as the client."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.manager = PinManager(CredentialStore(self._tmp.name))

    def tearDown(self):
        self._tmp.cleanup()

    def protocols(self):
        return ((2, PinProtocolV2()), (1, PinProtocolV1()))

    def test_key_agreement_is_the_mandated_cose_key(self):
        key = self.manager.key_agreement()
        self.assertEqual(set(key), {1, 3, -1, -2, -3})
        self.assertEqual((key[1], key[3], key[-1]), (2, -25, 1))
        self.assertEqual((len(key[-2]), len(key[-3])), (32, 32))
        # A new key each time regenerate() runs, so old sessions stop working.
        before = self.manager.key_agreement()
        self.manager.regenerate()
        self.assertNotEqual(self.manager.key_agreement()[-2], before[-2])

    def test_shared_secret_matches_python_fido2(self):
        for version, protocol in self.protocols():
            with self.subTest(protocol=version):
                peer_key, client_secret = protocol.encapsulate(self.manager.key_agreement())
                secret = self.manager.shared_secret(version, peer_key)
                self.assertEqual(secret, client_secret)
                self.assertEqual(len(secret), 32 if version == 1 else 64)

    def test_encrypt_and_decrypt_interoperate_both_directions(self):
        for version, protocol in self.protocols():
            with self.subTest(protocol=version):
                peer_key, secret = protocol.encapsulate(self.manager.key_agreement())
                ours = self.manager.shared_secret(version, peer_key)
                plaintext = b"passkey data" * 4
                self.assertEqual(protocol.decrypt(ours, clientpin.encrypt(version, ours, plaintext)), plaintext)
                self.assertEqual(clientpin.decrypt(version, ours, protocol.encrypt(ours, plaintext)), plaintext)
                # A client's own key agrees with us too, not just ours with itself.
                self.assertEqual(self.manager.shared_secret(version, peer_key), secret)

    def test_protocol_2_prefixes_a_random_iv_and_protocol_1_does_not(self):
        self.assertNotEqual(
            clientpin.encrypt(2, bytes(64), bytes(16))[:16],
            clientpin.encrypt(2, bytes(64), bytes(16))[:16],
        )
        self.assertEqual(len(clientpin.encrypt(2, bytes(64), bytes(32))), 48)
        self.assertEqual(len(clientpin.encrypt(1, bytes(32), bytes(32))), 32)

    def test_authenticate_matches_python_fido2(self):
        for version, protocol in self.protocols():
            with self.subTest(protocol=version):
                peer_key, _ = protocol.encapsulate(self.manager.key_agreement())
                secret = self.manager.shared_secret(version, peer_key)
                message = b"\x00\x01\x02" * 9
                ours = clientpin.authenticate(version, secret, message)
                self.assertEqual(ours, protocol.authenticate(secret, message))
                self.assertEqual(len(ours), 16 if version == 1 else 32)
                self.assertTrue(clientpin.verify(version, secret, message, ours))
                self.assertFalse(clientpin.verify(version, secret, message, ours[:-1] + bytes([ours[-1] ^ 0xFF])))

    def test_bad_peer_keys_raise_value_error(self):
        good = self.manager.key_agreement()
        bad_points = [
            None,
            [],
            {},
            {**good, -2: good[-2][:-1]},
            {**good, -3: b"x" * 32},
            {**good, -2: 1},
            {**good, -2: None},
            {k: v for k, v in good.items() if k != -2},
        ]
        for bad in bad_points:
            with self.subTest(peer=bad), self.assertRaises(ValueError):
                self.manager.shared_secret(2, bad)

    def test_unsupported_protocol_raises_value_error(self):
        with self.assertRaises(ValueError):
            self.manager.shared_secret(3, self.manager.key_agreement())
        with self.assertRaises(ValueError):
            clientpin.authenticate(3, bytes(32), b"m")

    def test_decrypt_rejects_short_or_ragged_ciphertext(self):
        with self.assertRaises(ValueError):
            clientpin.decrypt(2, bytes(64), bytes(16))
        with self.assertRaises(ValueError):
            clientpin.decrypt(1, bytes(32), bytes(15))


class PinManagerTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name
        self.store = CredentialStore(self.dir)
        self.manager = PinManager(self.store)
        self.requester = requester()

    def tearDown(self):
        self._tmp.cleanup()

    def digest(self, pin=b"1234"):
        return clientpin.pin_hash(pin)

    def assertCode(self, code, pin=b"1234", **kwargs):
        with self.assertRaises(PinError) as caught:
            self.manager.verify(UID, USERNAME, self.digest(pin), **kwargs)
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def test_no_pin_is_not_set_and_has_full_retries(self):
        self.assertFalse(self.manager.is_set(UID, USERNAME))
        self.assertEqual(self.manager.retries(UID, USERNAME), MAX_PIN_RETRIES)
        self.assertCode(PIN_NOT_SET)

    def test_set_stores_only_the_hash_and_persists(self):
        self.manager.set(UID, USERNAME, b"123456")
        self.assertTrue(self.manager.is_set(UID, USERNAME))
        state = self.store.pin(UID, USERNAME)
        self.assertEqual(state, PinState(hash=self.digest(b"123456"), retries=MAX_PIN_RETRIES))
        path = os.path.join(self.dir, "users", str(UID), "pin.json")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        with open(path, "rb") as f:
            self.assertNotIn(b"123456", f.read())
        # A fresh manager (daemon restart) reads the same state back.
        self.assertTrue(PinManager(CredentialStore(self.dir)).is_set(UID, USERNAME))

    def test_policy_violations(self):
        too_short, too_long = b"abc", b"a" * 64
        invalid_utf8, with_nul = b"\xff\xfe\xfd\xfc", b"12\x0034"
        for pin in (too_short, too_long, invalid_utf8, with_nul):
            with self.subTest(pin=pin), self.assertRaises(PinError) as caught:
                self.manager.set(UID, USERNAME, pin)
            self.assertEqual(caught.exception.code, PIN_POLICY_VIOLATION)
        self.assertFalse(self.manager.is_set(UID, USERNAME))
        # Exactly at the limits is allowed: a 63-byte pin and a 4-character one.
        self.manager.set(UID, USERNAME, b"a" * 63)
        self.manager.set(UID, USERNAME, "äöüß".encode())

    def test_pin_problem_names_the_first_problem(self):
        cases = [
            ("", None, "Enter a PIN"),
            ("123", "1234", "At least 4 characters"),
            ("a" * 64, None, "At most 63 bytes"),
            ("ä" * 32, None, "At most 63 bytes"),  # 32 code points, 64 bytes
            ("12\x0034", None, "No NUL characters"),
            ("\ud800abcd", None, "Use valid characters"),
            ("1234", "1235", "The PINs do not match"),
            ("1234", "", None),  # the repeat is only compared once it is typed
            ("1234", None, None),
            ("1234", "1234", None),
            ("a" * 63, None, None),
        ]
        for pin, repeat, problem in cases:
            with self.subTest(pin=pin, repeat=repeat):
                self.assertEqual(clientpin.pin_problem(pin, repeat), problem)

    def test_set_uses_pin_problem(self):
        with self.assertRaisesRegex(PinError, "At least 4 characters"):
            self.manager.set(UID, USERNAME, b"abc")

    def test_unicode_length_is_counted_in_code_points(self):
        # Four two-byte characters are 8 bytes but only 4 code points.
        self.manager.set(UID, USERNAME, "äöüß".encode())
        self.assertTrue(self.manager.is_set(UID, USERNAME))

    def test_mismatch_decrements_and_persists_retries(self):
        self.manager.set(UID, USERNAME, b"1234")
        self.store.set_pin(UID, USERNAME, PinState(hash=self.digest(), retries=3))
        for expected in (2, 1):
            self.assertCode(PIN_INVALID, pin=b"9999")
            self.assertEqual(self.store.pin(UID, USERNAME).retries, expected)
            self.assertEqual(self.manager.retries(UID, USERNAME), expected)
        # The count is on disk, so it survives a restart.
        self.assertEqual(PinManager(CredentialStore(self.dir)).retries(UID, USERNAME), 1)

    def test_match_resets_retries_and_the_mismatch_counter(self):
        self.manager.set(UID, USERNAME, b"1234")
        self.assertCode(PIN_INVALID, pin=b"9999")
        self.assertCode(PIN_INVALID, pin=b"9999")
        self.manager.verify(UID, USERNAME, self.digest())
        self.assertEqual(self.manager.retries(UID, USERNAME), MAX_PIN_RETRIES)
        # Two more mismatches must not trip the auth block from the earlier two.
        self.assertCode(PIN_INVALID, pin=b"9999")
        self.assertCode(PIN_INVALID, pin=b"9999")
        self.manager.verify(UID, USERNAME, self.digest())

    def test_pin_blocked_when_the_retries_run_out(self):
        self.manager.set(UID, USERNAME, b"1234")
        self.store.set_pin(UID, USERNAME, PinState(hash=self.digest(), retries=1))
        self.assertCode(PIN_BLOCKED, pin=b"9999")
        self.assertEqual(self.manager.retries(UID, USERNAME), 0)
        # Blocked stays blocked, even with the right PIN, until it is changed.
        self.assertCode(PIN_BLOCKED)
        self.manager.set(UID, USERNAME, b"5678")
        self.manager.verify(UID, USERNAME, self.digest(b"5678"))

    def test_three_consecutive_mismatches_block_authentication(self):
        self.manager.set(UID, USERNAME, b"1234")
        for expected in (PIN_INVALID, PIN_INVALID, PIN_AUTH_BLOCKED):
            self.assertCode(expected, pin=b"9999")
        # Blocked from there on, even with the right PIN.
        self.assertCode(PIN_AUTH_BLOCKED)
        # A restart (new manager, same store) is the power cycle that clears it.
        restarted = PinManager(CredentialStore(self.dir))
        restarted.verify(UID, USERNAME, self.digest())
        self.assertEqual(restarted.retries(UID, USERNAME), MAX_PIN_RETRIES)

    def test_remove_forgets_the_pin(self):
        self.manager.set(UID, USERNAME, b"1234")
        self.manager.remove(UID, USERNAME)
        self.assertFalse(self.manager.is_set(UID, USERNAME))
        self.assertFalse(os.path.exists(os.path.join(self.dir, "users", str(UID), "pin.json")))
        self.assertCode(PIN_NOT_SET)
        self.manager.remove(UID, USERNAME)  # removing twice is fine

    def test_tokens_are_bound_to_their_requester(self):
        token = self.manager.issue_token(self.requester)
        self.assertEqual(len(token), 32)
        self.assertEqual(self.manager.token_for(self.requester), token)
        self.assertIsNone(self.manager.token_for(requester(pid=os.getpid() + 1)))
        self.assertIsNone(self.manager.token_for(requester(app_name="Other App")))
        self.assertIsNone(self.manager.token_for(requester(uid=UID + 1)))

    def test_a_new_token_replaces_the_requesters_old_one(self):
        first = self.manager.issue_token(self.requester)
        second = self.manager.issue_token(self.requester)
        self.assertNotEqual(first, second)
        self.assertEqual(self.manager.token_for(self.requester), second)

    def test_set_and_remove_revoke_tokens(self):
        other = requester(uid=UID + 1)
        self.manager.issue_token(self.requester)
        self.manager.issue_token(other)
        self.manager.set(UID, USERNAME, b"1234")
        self.assertIsNone(self.manager.token_for(self.requester))
        self.assertIsNotNone(self.manager.token_for(other))
        self.manager.issue_token(self.requester)
        self.manager.remove(UID, USERNAME)
        self.assertIsNone(self.manager.token_for(self.requester))

    def test_tokens_expire(self):
        with patch("localpasskey.clientpin.time.monotonic", return_value=100.0):
            self.manager.issue_token(self.requester)
        with patch("localpasskey.clientpin.time.monotonic", return_value=100.0 + TOKEN_LIFETIME - 1):
            self.assertIsNotNone(self.manager.token_for(self.requester))
        with patch("localpasskey.clientpin.time.monotonic", return_value=100.0 + TOKEN_LIFETIME + 1):
            self.assertIsNone(self.manager.token_for(self.requester))
            # An expired token is dropped, not merely hidden.
            self.assertEqual(self.manager._tokens, [])

    def test_errors_carry_the_ctap_status_codes(self):
        self.assertEqual(
            [PIN_INVALID, PIN_BLOCKED, PIN_AUTH_INVALID, PIN_AUTH_BLOCKED, PIN_NOT_SET, 0x36, PIN_POLICY_VIOLATION],
            [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37],
        )
        self.assertEqual(clientpin.SUPPORTED_PROTOCOLS, (2, 1))
        error = PinError(PIN_INVALID, "wrong PIN")
        self.assertEqual(str(error), "0x31 wrong PIN")
        self.assertEqual(clientpin.pin_hash(b"1234"), hashlib.sha256(b"1234").digest()[:16])
        self.assertEqual(len(clientpin.pin_hash(b"1234")), 16)


if __name__ == "__main__":
    unittest.main()
