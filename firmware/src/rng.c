#include <stdint.h>
#include <stddef.h>
#include "rng.h"
#include "ti_msp_dl_config.h"
#include "ti/devices/msp/msp.h"
#include <ti/driverlib/dl_trng.h>

void rng_init(void){
    DL_TRNG_enablePower(TRNG);
}

uint32_t trng_get_word(void){
    
    while(!DL_TRNG_isCaptureReady(TRNG)){
        ;
    }

    return DL_TRNG_getCapture(TRNG);
}

void generate_nonce(uint8_t *out, size_t len){
    for(size_t i = 0; i < len; ){
        uint32_t r = trng_get_word();
        for(int j = 0; j < 4 && i < len; j++, i++){
            out[i] = (uint8_t)(r >> ((8 * j)));
        }
    }

}