#include <stdint.h>
#include <stddef.h>
#include "rng.h"
#include "ti_msp_dl_config.h"
#include "ti/devices/msp/msp.h"
#include <ti/driverlib/dl_trng.h>

void rng_init(void){
    // Changed TRNG0 -> TRNG for MSPM0L222x compatibility
    DL_TRNG_enablePower(TRNG);
    
    // Safety check: ensure TRNG is ready to be used
    while(DL_TRNG_isPowerEnabled(TRNG) != true);
}

uint32_t trng_get_word(void){
    // Changed TRNG0 -> TRNG
    while(!DL_TRNG_isCaptureReady(TRNG)){
        ;
    }
    return DL_TRNG_getCapture(TRNG);
}

// This looks solid, Seb. Standard byte-unpacking from a 32-bit word.
void generate_nonce(uint8_t *out, size_t len){
    for(size_t i = 0; i < len; ){
        uint32_t r = trng_get_word();
        for(int j = 0; j < 4 && i < len; j++, i++){
            out[i] = (uint8_t)(r >> (8 * j));
        }
    }
}