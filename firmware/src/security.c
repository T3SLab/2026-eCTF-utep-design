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
#include <stdint.h>
#include <stdbool.h>


#define TIMEOUT_TIMER TIMG0

bool check_pin(unsigned char *pin) {
    print_debug("Checking PIN\n");
    if (pin == NULL) {
        print_debug("PIN is NULL\n");
        return false;
    }
    else if (strcmp((char *)pin, "1234") != 0) {
        print_debug("PIN is incorrect\n");
        return false;
    }

    return true;
}

bool validate_permission(uint16_t group_id, permission_enum_t perm) {
    char output_buf[128] = {0};

    sprintf(output_buf, "Checking %c permissions for group: %hx\n", perm, group_id);
    print_debug(output_buf);

    // TODO: the reference design doesn't implement *ANY* security.
    // This function currently does nothing. Your team should add the
    // appropriate security checks here to implement the security
    // requirements.
    return true;
}



// Pick the instance you actually have (often TIMG0 on L-series)

static volatile bool g_timeout_active = false;
static volatile bool g_timeout_done   = false;

static void timeout_start_4s(void)
{
    g_timeout_done   = false;
    g_timeout_active = true;

    // Configure TIMEOUT_TIMER for one-shot interval timing.
    // Clock source: MFCLK (4 MHz), divider+prescaler so fTIMCLK = 15625 Hz (4MHz / 256)
    //
    // Example settings:
    //   CLKSEL = MFCLK
    //   CLKDIV.RATIO = 0   -> divide by (0+1)=1
    //   CPS.PCNT = 255     -> divide by (255+1)=256
    //   LOAD = 62500 - 1   -> 4 seconds at 15625 Hz

    // Pseudocode / typical flow:
    // 1) Disable timer
    // 2) Select clock
    // 3) Set divider + prescaler
    // 4) Set one-shot mode
    // 5) Set reload/load value
    // 6) Clear pending interrupts
    // 7) Enable interrupt
    // 8) Start timer

    // Replace these with the actual DL_ calls or register writes your project uses.

    // DL_TimerG_stopCounter(TIMEOUT_TIMER);
    // DL_TimerG_setClockSource(TIMEOUT_TIMER, DL_TIMER_CLOCK_MFCLK);
    // DL_TimerG_setClockDivider(TIMEOUT_TIMER, 1);      // CLKDIV.RATIO = 0
    // DL_TimerG_setPrescaler(TIMEOUT_TIMER, 256);       // CPS.PCNT = 255
    // DL_TimerG_setOneShotMode(TIMEOUT_TIMER);
    // DL_TimerG_setLoadValue(TIMEOUT_TIMER, 62500 - 1);
    // DL_TimerG_clearInterruptStatus(TIMEOUT_TIMER, DL_TIMER_INTERRUPT_ZERO_EVENT);
    // DL_TimerG_enableInterrupt(TIMEOUT_TIMER, DL_TIMER_INTERRUPT_ZERO_EVENT);
    // DL_TimerG_startCounter(TIMEOUT_TIMER);
}

// In your main logic:
static inline bool timeout_is_blocking(void)
{
    return g_timeout_active && !g_timeout_done;
}

// ISR (name depends on instance; e.g., TIMG0_IRQHandler)
void TIMG0_IRQHandler(void)
{
    // Read/clear interrupt status, then mark done.
    // DL_TimerG_clearInterruptStatus(TIMEOUT_TIMER, DL_TIMER_INTERRUPT_ZERO_EVENT);

    g_timeout_done   = true;
    g_timeout_active = false;
}