/**
 * @file user_settings.h
 * @brief wolfSSL user configuration for MSPM0L2228 eCTF firmware
 *
 * Included by wolfSSL settings.h when WOLFSSL_USER_SETTINGS is defined.
 * All defines are guarded so Makefile -D flags take precedence.
 */

#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#ifndef HAVE_AESGCM
#define HAVE_AESGCM
#endif
#ifndef WOLFSSL_AES_DIRECT
#define WOLFSSL_AES_DIRECT
#endif
#ifndef GCM_SMALL
#define GCM_SMALL
#endif

#ifndef HAVE_HMAC
#define HAVE_HMAC
#endif

#ifndef WOLFSSL_SHA256
#define WOLFSSL_SHA256
#endif

#ifndef HAVE_ED25519
#define HAVE_ED25519
#endif
#ifndef WOLFSSL_SHA512
#define WOLFSSL_SHA512
#endif

#ifndef NO_RSA
#define NO_RSA
#endif

#ifndef SINGLE_THREADED
#define SINGLE_THREADED
#endif

#ifndef CUSTOM_RAND_GENERATE_BLOCK
#define CUSTOM_RAND_GENERATE_BLOCK trng_generate_block
#endif

#ifndef WOLFCRYPT_ONLY
#define WOLFCRYPT_ONLY
#endif

#ifndef NO_ERROR_STRINGS
#define NO_ERROR_STRINGS
#endif
#ifndef NO_DH
#define NO_DH
#endif
#ifndef NO_DSA
#define NO_DSA
#endif
#ifndef NO_MD4
#define NO_MD4
#endif
#ifndef NO_MD5
#define NO_MD5
#endif
#ifndef NO_DES3
#define NO_DES3
#endif
#ifndef NO_RC4
#define NO_RC4
#endif
#ifndef NO_PWDBASED
#define NO_PWDBASED
#endif

#ifndef WOLFSSL_USER_IO
#define WOLFSSL_USER_IO
#endif
#ifndef NO_WRITEV
#define NO_WRITEV
#endif
#ifndef TIME_T_NOT_64BIT
#define TIME_T_NOT_64BIT
#endif
#ifndef NO_FILESYSTEM
#define NO_FILESYSTEM
#endif
#ifndef NO_DEV_RANDOM
#define NO_DEV_RANDOM
#endif
#ifndef WC_NO_DEFAULT_DEVID
#define WC_NO_DEFAULT_DEVID
#endif

/* Suppress timing hardening warning — no OS support on bare-metal target */
#ifndef WC_NO_HARDEN
#define WC_NO_HARDEN
#endif

#endif /* WOLFSSL_USER_SETTINGS_H */
