/**
 * @file security.c
 * @author Samuel Meyers
 * @brief Stub file to hold security checks
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */
#include "security.h"
#include "host_messaging.h"
#include "simple_crypto.h"
#include <secrets.h>
#include <wolfssl/wolfcrypt/rsa.h>

extern const uint8_t HSMPIN_HMAC[32];

bool check_pin(unsigned char* pin) {
    print_debug("Checking PIN\n");
    if (pin == NULL) {
        return false;
    }
    else{
        uint8_t mac_out[32];
        
        hmac_sha256(HMAC_KEY, 32, pin, strlen((char*)pin), mac_out);

        if (memcmp(mac_out, HSMPIN_HMAC, 32) != 0){
            timeout_start_4s(); // Incorrect PIN, start timeout
            return false;
        }
        return true; // Correct PIN
    }
}
// Requirement 3: RSA Verification Pipeline [cite: 422, 436]
bool verify_hsm_origin(uint8_t* signature, uint8_t* nonce) {
    // 1. Verify RSA signature with Peer Public Key [cite: 405, 493]
    // 2. Decrypt packet with AES-GCM first [cite: 426, 511]
    if (wc_RsaSSL_Verify(nonce, 32, signature, 256, &peerPubKey) != 0) {
        timeout_start_4s(); // Trigger Requirement 3 lockout [cite: 435]
        return false;
    }
    return true;
}

bool validate_permission(uint16_t group_id, permission_enum_t perm) {
    char output_buf[128] = {0};

    sprintf(output_buf, "Checking %c permissions for group: %hx\n", perm, group_id);
    print_debug(output_buf);

    bool authorized = false;

    // 1. Search the provisioned ID list in global secrets [cite: 352, 430, 517]
    for (int i = 0; i < MAX_PERMS; i++) {
        if (global_permissions[i].group_id == group_id) {
            // 2. Retrieve and check associated permissions [cite: 353, 354, 393]
            switch (perm) {
                case PERM_READ:
                    authorized = global_permissions[i].read;
                    break;
                case PERM_WRITE:
                    authorized = global_permissions[i].write;
                    break;
                case PERM_RECEIVE:
                    authorized = global_permissions[i].receive;
                    break;
                default:
                    authorized = false;
                    break;
            }
            // Once the group is found, we have our answer
            break; 
        }
    }
    // 3. If the check fails, trigger the Fail-Fast Mechanism [cite: 491, 507, 512, 526]
    if (!authorized) {
        print_debug("Auth Failure: Initiating 4s Penalty\n");
        timeout_start_4s(); 
    }

    return authorized;
}
