/**
 * @file    HSM.c
 * @author  Samuel Meyers
 * @brief   Boot code and main function for the HSM
 * @date    2026
 *
 * This source file is part of an example system for MITRE's 2026
 * Embedded CTF (eCTF). This code is being provided only for
 * educational purposes for the 2026 MITRE eCTF competition, and may not
 * meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

/*********************** INCLUDES *************************/
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include "rng.h"
#include "simple_flash.h"
#include "host_messaging.h"
#include "commands.h"
#include "filesystem.h"
#include "ti_msp_dl_config.h"
#include "status_led.h"
#include "simple_uart.h"
#include "secrets.h"


/* Code between this #ifdef and the subsequent #endif will
*  be ignored by the compiler if CRYPTO_EXAMPLE is not set in
*  the Makefile. */
#ifdef CRYPTO_EXAMPLE
/* The simple crypto example included with the reference design is
*  intended to be an example of how you *may* use cryptography in your
*  design. You are not limited nor required to use this interface in
*  your design. It is recommended for newer teams to start by only using
*  the simple crypto library until they have a working design. */
#include "simple_crypto.h"
#endif  //CRYPTO_EXAMPLE

/**********************************************************
 ************************ GLOBALS *************************
 **********************************************************/

static unsigned char uart_buf[MAX_MSG_SIZE];


/**********************************************************
 ******************** HELPER FUNCTIONS ********************
 **********************************************************/



/* Code between this #ifdef and the subsequent #endif will
*  be ignored by the compiler if CRYPTO_EXAMPLE is not set in
*  the projectk.mk file. */
#ifdef CRYPTO_EXAMPLE
void crypto_example(void) {
    uint8_t nonce[32];
    uint8_t sig[ED25519_SIG_SIZE];
    int ret;

    print_debug("Ed25519 cycle start\n");

    generate_nonce(nonce, sizeof(nonce));

    ret = ed25519_sign(nonce, sizeof(nonce), ED25519_PRIV_KEY, ED25519_PUB_KEYS[HSM_ID], sig);
    if (ret != 0) {
        print_error("Ed25519 sign failed\n");
        return;
    }

    ret = ed25519_verify(nonce, sizeof(nonce), sig, ED25519_PUB_KEYS[HSM_ID]);
    if (ret != 0) {
        print_error("Ed25519 verify failed\n");
        return;
    }

    print_debug("Ed25519 cycle end\n");
}
#endif  //CRYPTO_EXAMPLE

/**********************************************************
 ********************* CORE FUNCTIONS *********************
 **********************************************************/


/** @brief Initializes peripherals for system boot.
*/
void init() {
    // Initialize all of the hardware components
    SYSCFG_DL_init();

    rng_init();
    init_fs();
}

/**********************************************************
 *********************** MAIN LOOP ************************
 **********************************************************/

int main(void) {
    char output_buf[128] = {0};
    msg_type_t cmd;
    int result;
    uint16_t pkt_len;

    // initialize the device
    init();

    // process commands forever
    while (1) {
        print_debug("Ready\n");

        STATUS_LED_ON();

        pkt_len = 0;
        result = read_packet(CONTROL_INTERFACE, &cmd, uart_buf, &pkt_len);

        if (result != MSG_OK) {
            STATUS_LED_OFF();
            switch (result)
            {
            case MSG_BAD_PTR:
                print_error("Bad cmd pointer\n");
                break;
            case MSG_NO_ACK:
                print_error("Failed to receive ACK from host\n");
                break;
            case MSG_BAD_LEN:
                print_error("Received bad length\n");
                break;
            default:
                print_error("Failed to receive cmd from host\n");
                break;
            }
            continue;
        }

        // Handle the requested command
        switch (cmd) {

        // Handle list command
        case LIST_MSG:
            STATUS_LED_OFF();
            list(pkt_len, uart_buf);
            break;

        // Handle read command
        case READ_MSG:
            STATUS_LED_OFF();
            read(pkt_len, uart_buf);
            break;

        // Handle write command
        case WRITE_MSG:
            STATUS_LED_OFF();
            write(pkt_len, uart_buf);
            break;

        // Handle receive command
        case RECEIVE_MSG:
            STATUS_LED_OFF();
            receive(pkt_len, uart_buf);
            break;

        // Handle interrogate command
        case INTERROGATE_MSG:
            STATUS_LED_OFF();
            interrogate(pkt_len, uart_buf);
            break;

        // Handle listen command
        case LISTEN_MSG:
            STATUS_LED_OFF();
            listen(pkt_len, uart_buf);
            break;

        // Handle bad command
        default:
            STATUS_LED_OFF();
            sprintf(output_buf, "Invalid Command: %c\n", cmd);
            print_error(output_buf);
            break;
        }
    }
}
