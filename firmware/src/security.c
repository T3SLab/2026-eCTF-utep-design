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
#include <ti/driverlib/dl_timerg.h>

extern const uint8_t HSMPIN_HMAC[32];

#define CPU_FREQ_HZ  32000000U  // SDK default CPU frequency 32MHz

void delay_ms(uint32_t ms){
    uint64_t total_cycles = (uint64_t)ms * (CPU_FREQ_HZ / 1000U);
    delay_cycles((uint32_t)total_cycles);  // Safe for ms < 134s
}

bool check_pin(unsigned char* pin) {
    print_debug("Checking PIN\n");
    if (pin == NULL) {
        return false;
    }
    else{
        uint8_t mac_out[32];
        
        hmac_sha256(HMAC_KEY, 32, pin, PIN_LENGTH, mac_out);

        return memcmp(mac_out, HSMPIN_HMAC, 32) == 0;
    }
}
bool validate_permission(uint16_t group_id, permission_enum_t perm) {
    char output_buf[128] = {0};

    sprintf(output_buf, "Checking %c permissions for group: %hx\n", perm, group_id);
    print_debug(output_buf);

    bool found = false;
    for (int i = 0; i < MAX_PERMS; i++) {
        bool match = (global_permissions[i].group_id == group_id);
        if(match){
            found = true;
            switch (perm) {
                case PERM_READ:
                    return global_permissions[i].read;
                case PERM_WRITE:
                    return global_permissions[i].write;
                case PERM_RECEIVE:
                    return global_permissions[i].receive;
                default:
                    return false; // Invalid permission type
            }
      
        }
    }
    return false;
}


