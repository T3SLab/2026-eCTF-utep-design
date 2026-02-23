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
import secrets

from loguru import logger
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


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
    # Generate 8 unique RSA key pairs for authentication 
    hsm_devices = []

    for i in range(8):
        # 2048-bit keys for the mutual authentication handshake 
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        
        # Export to DER format [cite: 135]
        # Hex-encode binary data for JSON compatibility as per the NOTE below
        priv_hex = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).hex()

        pub_hex = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).hex()

        hsm_devices.append({
            "hsm_id": i,
            "private_key": priv_hex,
            "public_key": pub_hex
        })

    aes_key_hex = secrets.token_bytes(32).hex()  # 256-bit AES key for encrypting secrets
    # Create the secrets object
    # You can change this to generate any secret material
    # The secrets file will never be shared with attackers [cite: 117]
    secrets = {
        "groups": groups,
        "hsm_devices": hsm_devices, # Added RSA key material [cite: 124]
        "aes_key": aes_key_hex, # Added AES key for encrypting secrets
        "some_secrets": "EXAMPLE",
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
