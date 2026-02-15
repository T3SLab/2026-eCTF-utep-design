"""
Author: Samuel Meyers
Date: 2026

This source file is part of an example system for MITRE's 2026 Embedded CTF
(eCTF). This code is being provided only for educational purposes for the 2026 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2026 The MITRE Corporation
"""

import os
import json
import argparse
import hashlib
from dataclasses import dataclass


@dataclass
class Permission:
    """Represents a permission for one group
    """
    group_id: int=None
    read: bool=False
    write: bool=False
    receive: bool=False

    @classmethod
    def deserialize(cls, perms: str):
        """Create a Permission object from a string

        :param perm: A string representing a permission. The permission shall be a pair
            of group ID and permissions separated by an equal sign (e.g.,
            "<group_id>=<permission>"). The group ID shall be a 16-bit hexadecimal
            number padded with 0s to be a total of 4 characters with no preceding '0x'
            (e.g., 4b1d). The permission shall be a 3-character string where present
            permissions are represented by their opcode and absent permissions are
            represented by a '-' (e.g., "RWC", "RW-", "--C").
        """
        group_id, perm_string = perms.split('=')

        perm_obj = cls(
            int(group_id, 16),
            read = perm_string[0] == 'R',
            write = perm_string[1] == 'W',
            receive = perm_string[2] == 'C',
        )
        return perm_obj

    def serialize(self):
        ret = f'{self.group_id:04x}='
        for perm, shorthand in {'read': 'R', 'write': 'W', 'receive': 'C'}.items():
            ret += shorthand if getattr(self, perm) else "-"
        return ret

class PermissionList(list):
    """Represents a set of permissions that an HSM can be built with.
    """
    def __init__(self, *args):
        for item in args:
            if isinstance(item, Permission):
                self.append(item)

    @classmethod
    def deserialize(cls, perms: str):
        """Create a list of permission objects from a string
        representation

        :param perm: A string representing the permission set. The string shall be a
            colon-separated list of permissions (e.g., "<perm1>:<perm2>:<perm3>").

        :returns: An instance of `PermissionList`
        """
        ret = cls()
        permissions_strings = perms.split(":")
        for entry in permissions_strings:
            perm_obj = Permission.deserialize(entry)
            ret.append(perm_obj)
        return ret

    def serialize(self):
        return ':'.join(perm.serialize() for perm in self)

def secrets_to_c_header(permissions, path, hsm_pin, secrets_bin):
        # Requirement 2: Hash PIN to avoid plaintext storage [cite: 131]
        pin_hash = hashlib.sha256(hsm_pin.encode()).digest()
        
        # In practice, secrets_bin would be parsed for RSA keys [cite: 240, 252]
        # For now, we assume the binary contains the private key at the start
        rsa_priv_key = secrets_bin[:256] 

        with open(os.path.join(path, "secrets.h"), 'w') as f:
            f.write("#ifndef __SECRETS_H__\n#define __SECRETS_H__\n\n#include <stdint.h>\n\n")
            
            # PIN Hash [cite: 141]
            f.write(f"const uint8_t PIN_HASH[32] = {{ {', '.join(hex(b) for b in pin_hash)} }};\n\n")
            
            # RSA Private Key for signatures [cite: 240]
            f.write(f"const uint8_t RSA_PRIV_KEY[] = {{ {', '.join(hex(b) for b in rsa_priv_key)} }};\n\n")
            
            # Requirement 1: Bitmask Matrix [cite: 30, 34]
            # Maps Group ID to 0x01(R), 0x02(W), 0x04(C)
            f.write("#define MAX_GROUPS 0x100\n")
            f.write("const uint8_t PERM_MATRIX[MAX_GROUPS] = {\n")
            for perm in permissions:
                mask = (0x01 if perm.read else 0) | (0x02 if perm.write else 0) | (0x04 if perm.receive else 0)
                f.write(f"    [{hex(perm.group_id)}] = {hex(mask)},\n")
            f.write("};\n\n#endif\n")

if __name__ == '__main__':
    def parse_args():
        parser = argparse.ArgumentParser()

        parser.add_argument("secrets", type=argparse.FileType("rb"), help="Path to secrets file")
        parser.add_argument("hsm_pin", type=str, help="User PIN for the HSM")
        parser.add_argument("permissions", type=str, help="List of colon-separated permissions. E.g., \"1234=R--:4321=RWC\"")

        return parser.parse_args()

    args = parse_args()
    perms = PermissionList.deserialize(args.permissions)
    secrets_to_c_header(perms, './inc/', args.hsm_pin, args.secrets.read())
