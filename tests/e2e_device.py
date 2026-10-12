"""End-to-end check against the running localpasskeyd over /dev/hidraw.

Run as a normal desktop user while the service is running:

    python3 -m tests.e2e_device

It registers passkeys for two accounts on example.com and one on
other.example.org, then signs in with each. Every step pops up the polkit
confirmation dialog unless a polkit rule approves it.
"""

import sys

from fido2.client import Fido2Client
from fido2.hid import CtapHidDevice
from fido2.server import Fido2Server
from fido2.webauthn import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from . import helpers  # noqa: F401  (python-fido2 built-in UV shim)

VENDOR_ID, PRODUCT_ID = 0x1209, 0x4C50


def find_device():
    for device in CtapHidDevice.list_devices():
        if (device.descriptor.vid, device.descriptor.pid) == (VENDOR_ID, PRODUCT_ID):
            return device
    sys.exit("localpasskeyd's virtual security key was not found (is the service running?)")


def register(device, rp_id, user_id, name):
    server = Fido2Server(PublicKeyCredentialRpEntity(id=rp_id, name=rp_id))
    options, state = server.register_begin(
        PublicKeyCredentialUserEntity(id=user_id, name=name, display_name=name.title()),
        resident_key_requirement=ResidentKeyRequirement.REQUIRED,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    result = Fido2Client(device, f"https://{rp_id}").make_credential(options["publicKey"])
    auth_data = server.register_complete(state, result.client_data, result.attestation_object)
    print(f"registered {name}@{rp_id}: flags={auth_data.flags:#04x}")
    return auth_data.credential_data


def sign_in(device, rp_id, credentials):
    server = Fido2Server(PublicKeyCredentialRpEntity(id=rp_id, name=rp_id))
    options, state = server.authenticate_begin(user_verification=UserVerificationRequirement.REQUIRED)
    selection = Fido2Client(device, f"https://{rp_id}").get_assertion(options["publicKey"])
    names = []
    for index, assertion in enumerate(selection.get_assertions()):
        response = selection.get_response(index)
        server.authenticate_complete(
            state, credentials, response.credential_id, response.client_data,
            response.authenticator_data, response.signature,
        )
        names.append(assertion.user.get("name"))
    print(f"signed in to {rp_id}; accounts offered: {names}")
    return names


def main():
    device = find_device()
    alice = register(device, "example.com", b"alice-id", "alice")
    bob = register(device, "example.com", b"bob-id", "bob")
    carol = register(device, "other.example.org", b"carol-id", "carol")
    assert sign_in(device, "example.com", [alice, bob]) == ["bob", "alice"]
    assert sign_in(device, "other.example.org", [carol]) == ["carol"]
    print("OK")


if __name__ == "__main__":
    main()
