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
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_der_private_key, load_der_public_key

# Must match bn.h constants
_WORD_BITS       = 16
_MAX_PRIME_LEN   = 32   # 512-bit primes as uint16_t words
_MAX_MODULUS_LEN = 64   # 1024-bit modulus as uint16_t words

def _int_to_dtype(x, length):
    return [(x >> (_WORD_BITS * (length - 1 - i))) & 0xffff for i in range(length)]

def _montgomery_inv(lsw):
    return (-pow(lsw, -1, 1 << _WORD_BITS)) % (1 << _WORD_BITS)

def _words_to_bytes(words):
    out = bytearray()
    for w in words:
        out += w.to_bytes(2, 'little')
    return bytes(out)

def _build_rsa_sk(priv_der):
    """Return rsa_sk struct bytes from a PKCS#8 DER private key."""
    key  = load_der_private_key(priv_der, password=None)
    nums = key.private_numbers()
    p, q  = nums.p, nums.q
    d1    = nums.dmp1
    d2    = nums.dmq1
    p_inv = pow(p, -1, q)
    p_mod = (1 << 512) % p
    q_mod = (1 << 512) % q
    p0_inv = _montgomery_inv(p & 0xffff)
    q0_inv = _montgomery_inv(q & 0xffff)
    words = (
        _int_to_dtype(p,     _MAX_PRIME_LEN) +
        _int_to_dtype(q,     _MAX_PRIME_LEN) +
        _int_to_dtype(d1,    _MAX_PRIME_LEN) +
        _int_to_dtype(d2,    _MAX_PRIME_LEN) +
        _int_to_dtype(p_inv, _MAX_PRIME_LEN) +
        _int_to_dtype(p_mod, _MAX_PRIME_LEN) +
        _int_to_dtype(q_mod, _MAX_PRIME_LEN) +
        [p0_inv, q0_inv]
    )
    return _words_to_bytes(words)

def _build_rsa_pk(pub_der):
    """Return rsa_pk struct bytes from a SubjectPublicKeyInfo DER public key."""
    key  = load_der_public_key(pub_der)
    nums = key.public_numbers()
    n, e  = nums.n, nums.e
    r_mod = (1 << 1024) % n
    n_inv = _montgomery_inv(n & 0xffff)
    words = (
        _int_to_dtype(n,     _MAX_MODULUS_LEN) +
        _int_to_dtype(e,     _MAX_PRIME_LEN)   +
        _int_to_dtype(r_mod, _MAX_MODULUS_LEN) +
        [n_inv]
    )
    return _words_to_bytes(words)


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
    hsm_devices_public = []
    hsm_devices_private = []

    for i in range(8):
        # 1024-bit keys for the mutual authentication handshake
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        
        # Export DER then convert to rsa_sk / rsa_pk struct bytes for direct
        # use by the firmware (no cryptography module needed inside Docker)
        priv_der = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        pub_der = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        priv_struct_hex = _build_rsa_sk(priv_der).hex()
        pub_struct_hex  = _build_rsa_pk(pub_der).hex()

        hsm_devices_public.append({
            "hsm_id": i,
            "public_key": pub_struct_hex,
        })

        hsm_devices_private.append({
            "hsm_id": i,
            "private_key": priv_struct_hex,
        })

    aes_keys = [secrets_module.token_bytes(16).hex() for _ in range(8)]  # 256-bit AES key for encrypting secrets
    
    # Store private keys in host only file
    host_keys = {"hsm_devices": hsm_devices_private}
    with open("host_keys.json", "w") as f:
        json.dump(host_keys, f, indent=2) 

    # Create the secrets object
    # You can change this to generate any secret material
    # The secrets file will never be shared with attackers [cite: 117]
    secrets = {
        "groups": groups,
        "hsm_devices": hsm_devices_public, # Added RSA key material [cite: 124]
        "aes_keys": aes_keys, # Added AES keys
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
