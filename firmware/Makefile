MSPM0_SDK_INSTALL_DIR ?= $(abspath ../../../../../..)

include $(MSPM0_SDK_INSTALL_DIR)/tools/imports_mak/imports.mak.linux

CC = "$(TICLANG_ARMCOMPILER)/bin/tiarmclang"
LNK = "$(TICLANG_ARMCOMPILER)/bin/tiarmclang"
OBJCOPY = "$(TICLANG_ARMCOMPILER)/bin/tiarmobjcopy"
BUILDDIR ?= /tmp/build
VPATH = "src"
LINKERFILE = "firmware.ld"

# to download wolfssl for the simple crypto example, `cd ./firmware/ && git clone https://github.com/wolfSSL/wolfssl`
# then set this variable to 1
CRYPTO_EXAMPLE = 1

OBJECTS = $(BUILDDIR)/HSM.so \
    $(BUILDDIR)/simple_uart.so \
    $(BUILDDIR)/ti_msp_dl_config.so \
    $(BUILDDIR)/startup_mspm0l222x_ticlang.so \
    $(BUILDDIR)/simple_flash.so \
    $(BUILDDIR)/host_messaging.so \
    $(BUILDDIR)/security.so \
    $(BUILDDIR)/filesystem.so \
    $(BUILDDIR)/commands.so

ifeq ($(CRYPTO_EXAMPLE), 1)
OBJECTS += $(BUILDDIR)/simple_crypto.so

# Base Crypto Configuration
CFLAGS += -DCRYPTO_EXAMPLE=1
CFLAGS += -DNO_WOLFSSL_DIR
CFLAGS += -DWOLFSSL_AES_DIRECT
CFLAGS += -DHAVE_AESGCM
CFLAGS += -DSINGLE_THREADED  # Essential for No-RTOS 

# ---> THE CULLING DIET FLAGS <---
CFLAGS += -DWOLFCRYPT_ONLY      # Removes SSL/TLS overhead 
CFLAGS += -DNO_ERROR_STRINGS    # Saves several KB of Flash 
CFLAGS += -DNO_RSA -DNO_DH -DNO_DSA # Removes heavy PKE math
CFLAGS += -DNO_MD4 -DNO_MD5 -DNO_DES3 -DNO_RC4 # Removes legacy algos
CFLAGS += -DNO_PWDBASED -DNO_SHA -DNO_HMAC_SHA # Keep only what you use
CFLAGS += -DGCM_SMALL           # Trades speed for SRAM [cite: 11]

# Hardware Specifics
CFLAGS += -DHAVE_PK_CALLBACKS
CFLAGS += -DWOLFSSL_USER_IO
CFLAGS += -DNO_WRITEV -DTIME_T_NOT_64BIT
CFLAGS += -DNO_FILESYSTEM       # Reduces RAM buffer usage 
CFLAGS += -DNO_DEV_RANDOM
CFLAGS += -DWC_NO_DEFAULT_DEVID
CFLAGS += -DWOLF_CRYPTO_CB

WOLFSSL_INC = ./wolfssl/wolfcrypt/src
CFLAGS += -I./wolfssl

# Culled Object List (Removed md5.o and sha.o to save space)
OBJECTS += $(WOLFSSL_INC)/aes.o $(WOLFSSL_INC)/hash.o
OBJECTS += $(WOLFSSL_INC)/cryptocb.o $(WOLFSSL_INC)/sha256.o
OBJECTS += $(WOLFSSL_INC)/hmac.o
endif

NAME = hsm

CFLAGS += -I.. \
    -D__MSPM0L2228__ \
    -O2 \
    "-I$(MSPM0_SDK_INSTALL_DIR)/source/third_party/CMSIS/Core/Include" \
    "-I$(MSPM0_SDK_INSTALL_DIR)/source" \
	"-I./inc" \
    -gdwarf-3 \
    -mcpu=cortex-m0plus \
    -march=thumbv6m \
    -mfloat-abi=soft \
    -mthumb

LFLAGS += "-l$(MSPM0_SDK_INSTALL_DIR)/source/ti/drivers/lib/ticlang/m0p/drivers_mspm0l122x_l222x.a" \
    "-l$(MSPM0_SDK_INSTALL_DIR)/kernel/nortos/lib/ticlang/m0p/nortos_mspm0l122x_l222x.a" \
    "-l$(MSPM0_SDK_INSTALL_DIR)/source/ti/driverlib/lib/ticlang/m0p/mspm0l122x_l222x/driverlib.a" \
    "-L$(MSPM0_SDK_INSTALL_DIR)/source" \
    -L.. \
    ./$(LINKERFILE) \
    "-Wl,-m,$(BUILDDIR)/$(NAME).map" \
    -Wl,--rom_model \
    -Wl,--warn_sections \
    "-L$(TICLANG_ARMCOMPILER)/lib" \
    -llibc.a

all: $(BUILDDIR)/$(NAME).elf $(BUILDDIR)/$(NAME).bin

$(BUILDDIR):
	@ mkdir -p $(BUILDDIR)

$(BUILDDIR)/%.so: ./src/%.c | $(BUILDDIR)
	@ echo Building $@
	@ $(CC) $(CFLAGS) -c $< -o $@

# if compiling with the crypto example, compile all crypto objects
ifeq ($(CRYPTO_EXAMPLE), 1)
$(WOLFSSL_INC)/%.o: $(WOLFSSL_INC)/%.c
	@ echo Building $@
	@ $(CC) $(CFLAGS) -c $< -o $@
endif

$(BUILDDIR)/$(NAME).elf: $(OBJECTS)
	@ echo linking $@
	@ $(LNK) -Wl,-u,_c_int00 $(OBJECTS)  $(LFLAGS) -o $(BUILDDIR)/$(NAME).elf

$(BUILDDIR)/$(NAME).bin: $(BUILDDIR)/$(NAME).elf
	@ $(OBJCOPY) -O binary $(BUILDDIR)/$(NAME).elf $(BUILDDIR)/$(NAME).bin

clean:
	@ echo Cleaning...
	@ $(RM) $(OBJECTS) > $(DEVNULL) 2>&1
	@ $(RM) $(NAME).elf > $(DEVNULL) 2>&1
	@ $(RM) $(NAME).map > $(DEVNULL) 2>&1
