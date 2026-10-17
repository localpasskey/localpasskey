import unittest

from localpasskey import totp
from localpasskey.totp import OtpError

KEY = "JBSWY3DPEHPK3PXP"  # b"Hello!\xde\xad\xbe\xef"
SECRET = b"Hello!\xde\xad\xbe\xef"


class CodeTests(unittest.TestCase):
    def test_rfc4226_appendix_d(self):
        expected = ["755224", "287082", "359152", "969429", "338314",
                    "254676", "287922", "162583", "399871", "520489"]
        for counter, want in enumerate(expected):
            self.assertEqual(totp.hotp(b"12345678901234567890", counter), want)

    def test_rfc6238_appendix_b(self):
        keys = {
            "SHA1": b"12345678901234567890",
            "SHA256": b"12345678901234567890123456789012",
            "SHA512": b"1234567890" * 6 + b"1234",
        }
        table = [
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ]
        for now, *wants in table:
            for algorithm, want in zip(("SHA1", "SHA256", "SHA512"), wants):
                got, _ = totp.code(keys[algorithm], algorithm, 8, 30, now=now)
                self.assertEqual(got, want, (algorithm, now))

    def test_remaining_seconds(self):
        self.assertEqual(totp.code(SECRET, now=0)[1], 30)
        self.assertEqual(totp.code(SECRET, now=29.9)[1], 0.1)
        self.assertEqual(totp.code(SECRET, now=1.25)[1], 28.75)
        self.assertEqual(totp.code(SECRET, now=29.9)[0], totp.code(SECRET, now=0)[0])
        self.assertEqual(totp.code(SECRET, now=30)[1], 30)
        self.assertEqual(totp.code(SECRET, period=60, now=61)[1], 59)

    def test_default_now_and_six_digits(self):
        got, remaining = totp.code(SECRET)
        self.assertRegex(got, r"^[0-9]{6}$")
        self.assertTrue(0 <= remaining <= 30)


class SecretTests(unittest.TestCase):
    def test_lowercase_spaces_dashes_and_padding(self):
        self.assertEqual(totp.decode_secret("jbsw y3dp-ehpk 3pxp=="), SECRET)
        self.assertEqual(totp.decode_secret(" JBSWY3DP\tEHPK3PXP\n"), SECRET)

    def test_round_trip(self):
        self.assertEqual(totp.encode_secret(SECRET), KEY)
        self.assertEqual(totp.decode_secret(totp.encode_secret(b"\x01" * 33)), b"\x01" * 33)
        self.assertNotIn("=", totp.encode_secret(b"\x01" * 11))

    def test_not_remapped_or_invalid(self):
        for bad in ["JBSWY3DPEHPK3PX1", "JBSWY3DPEHPK3PX0", "JBSWY3DPEHPK3PX8", "JBSWY3DP!HPK3PXP"]:
            with self.assertRaisesRegex(OtpError, "not a valid setup key"):
                totp.decode_secret(bad)

    def test_non_ascii_letters_refused(self):
        # Each upper-cases to ASCII ("S", "I", "SS", "FF") and would decode to another key.
        for key in ("JBSWY3DPEHPK3PX\u017f", "JBSWY3DPEHPK3PX\u0131",
                    "JBSWY3DPEHPK3P\u00df", "JBSWY3DPEHPK3P\ufb00"):
            with self.assertRaisesRegex(OtpError, "not a valid setup key"):
                totp.decode_secret(key)
            with self.assertRaisesRegex(OtpError, "not a valid setup key"):
                totp.parse("otpauth://totp/x?secret=" + key)

    def test_impossible_lengths(self):
        for length in (17, 19, 22):  # 1, 3 and 6 mod 8
            with self.assertRaisesRegex(OtpError, "not a valid setup key"):
                totp.decode_secret("A" * length)

    def test_too_short_and_too_long(self):
        with self.assertRaisesRegex(OtpError, "too short"):
            totp.decode_secret("JBSWY3DP")
        with self.assertRaisesRegex(OtpError, "too short"):
            totp.decode_secret("")
        totp.decode_secret("A" * 16)  # exactly 10 bytes
        with self.assertRaisesRegex(OtpError, "too long"):
            totp.decode_secret(totp.encode_secret(b"\0" * 129))
        totp.decode_secret(totp.encode_secret(b"\0" * 128))


class ParseTests(unittest.TestCase):
    def test_bare_key(self):
        self.assertEqual(totp.parse("  jbsw y3dp ehpk 3pxp\n"), {
            "secret": SECRET, "issuer": "", "account": "",
            "algorithm": "SHA1", "digits": 6, "period": 30,
        })

    def test_full_link(self):
        got = totp.parse(
            "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ"
            "&issuer=ACME%20Co&algorithm=sha-256&digits=8&period=60"
        )
        self.assertEqual((got["issuer"], got["account"]), ("ACME Co", "john.doe@email.com"))
        self.assertEqual((got["algorithm"], got["digits"], got["period"]), ("SHA256", 8, 60))

    def test_encoded_colon_in_label_and_stripping(self):
        got = totp.parse(f"otpauth://totp/Big%20Corp%3A%20alice%40bigco.com?secret={KEY}")
        self.assertEqual((got["issuer"], got["account"]), ("Big Corp", "alice@bigco.com"))

    def test_percent_encoded_issuer_is_decoded_once(self):
        got = totp.parse(f"otpauth://totp/x?secret={KEY}&issuer=A%26B")
        self.assertEqual(got["issuer"], "A&B")
        got = totp.parse(f"otpauth://totp/x?secret={KEY}&issuer=A%2526B")
        self.assertEqual(got["issuer"], "A%26B")

    def test_label_without_issuer(self):
        got = totp.parse(f"otpauth://totp/alice@example.com?secret={KEY}")
        self.assertEqual((got["issuer"], got["account"]), ("", "alice@example.com"))

    def test_issuer_parameter_beats_prefix(self):
        got = totp.parse(f"otpauth://totp/Old:me?secret={KEY}&issuer=New")
        self.assertEqual(got["issuer"], "New")
        got = totp.parse(f"otpauth://totp/Old:me?secret={KEY}&issuer=")
        self.assertEqual(got["issuer"], "Old")

    def test_secret_with_spaces_and_padding(self):
        got = totp.parse("otpauth://totp/x?secret=jbsw-y3dp%20ehpk3pxp%3D%3D")
        self.assertEqual(got["secret"], SECRET)

    def test_first_occurrence_wins_and_unknown_ignored(self):
        got = totp.parse(f"otpauth://totp/x?Secret={KEY}&secret=AAAA&image=http://x/y.png&foo=bar&DIGITS=8")
        self.assertEqual((got["secret"], got["digits"]), (SECRET, 8))

    def test_uppercase_scheme_and_type(self):
        got = totp.parse(f"OTPAUTH://TOTP/x?secret={KEY}")
        self.assertEqual(got["secret"], SECRET)

    def test_labels_trimmed_and_cleaned(self):
        got = totp.parse(f"otpauth://totp/Bad%07Co:{'a' * 300}?secret={KEY}")
        self.assertEqual(got["issuer"], "Bad Co")
        self.assertEqual(len(got["account"]), totp.MAX_LABEL)

    def test_refused(self):
        cases = {
            f"otpauth://hotp/x?secret={KEY}&counter=0": "HOTP",
            "otpauth-migration://offline?data=CjMKCkhlbGxv": "not an otpauth://totp/ link",
            f"steam://{KEY}": "not an otpauth://totp/ link",
            f"https://example.com/?secret={KEY}": "not an otpauth://totp/ link",
            f"otpauth://xotp/x?secret={KEY}": "not an otpauth://totp/ link",
            "otpauth://totp/x": "secret",
            "otpauth://totp/x?secret=": "too short",
            "otpauth://totp/x?secret=JBSWY3DP": "too short",
            f"otpauth://totp/x?secret={KEY}&period=0": "period",
            f"otpauth://totp/x?secret={KEY}&period=301": "period",
            f"otpauth://totp/x?secret={KEY}&period=-30": "period",
            f"otpauth://totp/x?secret={KEY}&digits=7": "digits",
            f"otpauth://totp/x?secret={KEY}&digits=": "digits",
            f"otpauth://totp/x?secret={KEY}&algorithm=MD5": "algorithm",
            f"otpauth://totp/Steam:me?secret={KEY}&issuer=Steam&encoder=steam": "Steam codes are not supported",
            f"otpauth://totp/x?secret={KEY}&Encoder=STEAM": "Steam codes are not supported",
            f"otpauth://totp/x?secret={KEY}&encoder=yandex": "the encoder parameter is not supported",
        }
        for text, message in cases.items():
            with self.assertRaisesRegex(OtpError, message, msg=text):
                totp.parse(text)

    def test_an_empty_encoder_is_ignored(self):
        self.assertEqual(totp.parse(f"otpauth://totp/x?secret={KEY}&encoder=")["secret"], SECRET)

    def test_oversize_input(self):
        with self.assertRaisesRegex(OtpError, "too long"):
            totp.parse(KEY + " " * totp.MAX_INPUT)

    def test_error_never_contains_the_secret(self):
        for text in (f"otpauth://totp/x?secret={KEY}&digits=7", "JBSWY3DPEHPK3PX1"):
            with self.assertRaises(OtpError) as caught:
                totp.parse(text)
            self.assertNotIn("JBSWY3DP", str(caught.exception))


class SiteTests(unittest.TestCase):
    def test_site_from_issuer(self):
        self.assertEqual(totp.site_from_issuer("GitHub.com"), "github.com")
        self.assertEqual(totp.site_from_issuer("GitHub"), "")
        self.assertEqual(totp.site_from_issuer("ACME Co.uk"), "")
        self.assertEqual(totp.site_from_issuer(""), "")
        self.assertEqual(totp.site_from_issuer("a" * 300 + ".com"), "")
        # Only plain host names: a URL or an address is no website suggestion.
        self.assertEqual(totp.site_from_issuer("https://github.com"), "")
        self.assertEqual(totp.site_from_issuer("octocat@github.com"), "")
        self.assertEqual(totp.site_from_issuer("github.com."), "github.com")

    def test_normalize_site(self):
        self.assertEqual(totp.normalize_site("  GitHub.com "), "github.com")
        self.assertEqual(totp.normalize_site("https://GitHub.com/settings/security?x=1"), "github.com")
        self.assertEqual(totp.normalize_site("https://user@login.example.org:8443/"), "login.example.org")
        self.assertEqual(totp.normalize_site("example.com."), "example.com")
        self.assertEqual(totp.normalize_site(""), "")
        # Not a host name: kept as typed (stripped), for the service to judge.
        self.assertEqual(totp.normalize_site(" My Bank "), "My Bank")
        self.assertEqual(totp.normalize_site("localhost"), "localhost")
        self.assertEqual(totp.normalize_site("https://[::1"), "https://[::1")
        self.assertEqual(totp.normalize_site("bücher.de"), "bücher.de")
        # Without a scheme, a path, port, query or user name still leaves the host.
        self.assertEqual(totp.normalize_site("github.com/login"), "github.com")
        self.assertEqual(totp.normalize_site("www.GitHub.com:443"), "www.github.com")
        self.assertEqual(totp.normalize_site("me@github.com"), "github.com")
        self.assertEqual(totp.normalize_site("github.com?x=1"), "github.com")
        self.assertEqual(totp.normalize_site("www.github.com/"), "www.github.com")
        self.assertEqual(totp.normalize_site("My Bank/login"), "My Bank/login")
        self.assertEqual(totp.normalize_site("[::1"), "[::1")


if __name__ == "__main__":
    unittest.main()
