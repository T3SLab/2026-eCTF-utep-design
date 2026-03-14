"""
Author: Ben Janis
Date: 2026

This source file is part of an example system for MITRE's 2026 Embedded CTF
(eCTF). This code is being provided only for educational purposes for the 2026 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2026 The MITRE Corporation
"""

import argparse
import json
from pathlib import Path
import secrets as secrets_module

from loguru import logger
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _generate_key_material():
    """Generate 8 Ed25519 key pairs and 8 AES keys.

    :returns: (hsm_devices_public, hsm_devices_private, aes_keys)
    """
    hsm_devices_public = []
    hsm_devices_private = []

    for i in range(8):
        private_key = Ed25519PrivateKey.generate()

        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        pub_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        hsm_devices_public.append({
            "hsm_id": i,
            "public_key": pub_bytes.hex(),
        })

        hsm_devices_private.append({
            "hsm_id": i,
            "private_key": priv_bytes.hex(),
            "public_key": pub_bytes.hex(),
        })

    aes_keys = [secrets_module.token_bytes(16).hex() for _ in range(8)]
    return hsm_devices_public, hsm_devices_private, aes_keys


def gen_secrets(groups: list[int]) -> bytes:
    """Generate the contents secrets file

    This will be passed to the Encoder, ectf26_design.gen_secrets,
    and the build process of the firmware

    NOTE: you should NOT write to secrets files within this function.
    All generated secrets must be contained in the returned bytes
    object.

    :param groups: List of permission groups that will be valid in this
        deployment.

    :returns: Contents of the secrets file
    """
    hsm_devices_public, hsm_devices_private, aes_keys = _generate_key_material()

    # Write host_keys.json to /secrets/ so the firmware build can assign
    # one private key per HSM without exposing all keys in secrets.h.
    # /secrets/ is always mounted by MITRE's pipeline before this is called.
    host_keys_path = Path("/secrets/host_keys.json")
    try:
        with open(host_keys_path, "w") as f:
            json.dump({"hsm_devices": hsm_devices_private}, f, indent=2)
    except OSError:
        # /secrets/ may not exist in local dev environments; main() handles that case.
        pass

    # Create the secrets object
    # You can change this to generate any secret material
    # The secrets file will never be shared with attackers [cite: 117]
    secrets = {
        "groups": groups,
        "hsm_devices": hsm_devices_public,
        "aes_keys": aes_keys,
    }

    # NOTE: if you choose to use JSON for your file type, you will not
    # be able to store binary data, and must either use a different file
    # type or encode the binary data to hex, base64, or another type of
    # ASCII-only encoding
    return json.dumps(secrets).encode()


def parse_args():
    """Define and parse the command line arguments
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force creation of secrets file, overwriting existing file",
    )
    parser.add_argument(
        "secrets_file",
        type=Path,
        help="Path to the secrets file to be created",
    )
    parser.add_argument(
        "groups",
        nargs="+",
        type=lambda x: int(x, 0),
        help="Supported group IDs",
    )
    return parser.parse_args()


def main():
    """Main function of gen_secrets

    You will likely not have to change this function
    """
    # Parse the command line arguments
    args = parse_args()

    secrets = gen_secrets(args.groups)

    # Print the generated secrets for your own debugging
    # Attackers will NOT have access to the output of this, but feel free to remove
    #
    # NOTE: Printing sensitive data is generally not good security practice
    logger.debug(f"Generated secrets: {secrets}")

    # Open the file, erroring if the file exists unless the --force arg is provided
    with open(args.secrets_file, "wb" if args.force else "xb") as f:
        # Dump the secrets to the file
        f.write(secrets)

    # For your own debugging. Feel free to remove
    logger.success(f"Wrote secrets to {str(args.secrets_file.absolute())}")


if __name__ == "__main__":
    main()
