/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/err.h>
#include <openssl/sm9.h>

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

# define ERR_FUNC(func) ERR_PACK(ERR_LIB_SM9,func,0)
# define ERR_REASON(reason) ERR_PACK(ERR_LIB_SM9,0,reason)

static ERR_STRING_DATA SM9_str_functs[] = {
    {ERR_FUNC(SM9_F_OLD_SM9_MASTER_DECODE), "old_sm9_master_decode"},
    {ERR_FUNC(SM9_F_OLD_SM9_PRIV_DECODE), "old_sm9_priv_decode"},
    {ERR_FUNC(SM9_F_SM9CIPHERTEXT_CHECK), "SM9Ciphertext_check"},
    {ERR_FUNC(SM9_F_SM9ENCPARAMETERS_DECRYPT), "SM9EncParameters_decrypt"},
    {ERR_FUNC(SM9_F_SM9ENCPARAMETERS_ENCRYPT), "SM9EncParameters_encrypt"},
    {ERR_FUNC(SM9_F_SM9ENCPARAMETERS_GENERATE_MAC),
     "SM9EncParameters_generate_mac"},
    {ERR_FUNC(SM9_F_SM9ENCPARAMETERS_GET_KEY_LENGTH),
     "SM9EncParameters_get_key_length"},
    {ERR_FUNC(SM9_F_SM9PUBLICPARAMETERS_GET_POINT_SIZE),
     "SM9PublicParameters_get_point_size"},
    {ERR_FUNC(SM9_F_SM9_COMPUTE_SHARE_KEY_A), "SM9_compute_share_key_A"},
    {ERR_FUNC(SM9_F_SM9_COMPUTE_SHARE_KEY_B), "SM9_compute_share_key_B"},
    {ERR_FUNC(SM9_F_SM9_DECRYPT), "SM9_decrypt"},
    {ERR_FUNC(SM9_F_SM9_DO_DECRYPT), "SM9_do_decrypt"},
    {ERR_FUNC(SM9_F_SM9_DO_ENCRYPT), "SM9_do_encrypt"},
    {ERR_FUNC(SM9_F_SM9_ENCRYPT), "SM9_encrypt"},
    {ERR_FUNC(SM9_F_SM9_EXTRACT_PRIVATE_KEY), "SM9_extract_private_key"},
    {ERR_FUNC(SM9_F_SM9_EXTRACT_PUBLIC_PARAMETERS),
     "SM9_extract_public_parameters"},
    {ERR_FUNC(SM9_F_SM9_GENERATE_KEY_EXCHANGE), "SM9_generate_key_exchange"},
    {ERR_FUNC(SM9_F_SM9_GENERATE_MASTER_SECRET),
     "SM9_generate_master_secret"},
    {ERR_FUNC(SM9_F_SM9_KEY_NEW), "SM9_KEY_new"},
    {ERR_FUNC(SM9_F_SM9_MASTER_DECODE), "sm9_master_decode"},
    {ERR_FUNC(SM9_F_SM9_MASTER_ENCODE), "sm9_master_encode"},
    {ERR_FUNC(SM9_F_SM9_MASTER_KEY_EXTRACT_KEY),
     "SM9_MASTER_KEY_extract_key"},
    {ERR_FUNC(SM9_F_SM9_MASTER_KEY_NEW), "SM9_MASTER_KEY_new"},
    {ERR_FUNC(SM9_F_SM9_PARAMS_DECODE), "sm9_params_decode"},
    {ERR_FUNC(SM9_F_SM9_PRIV_DECODE), "sm9_priv_decode"},
    {ERR_FUNC(SM9_F_SM9_PRIV_ENCODE), "sm9_priv_encode"},
    {ERR_FUNC(SM9_F_SM9_PUB_DECODE), "sm9_pub_decode"},
    {ERR_FUNC(SM9_F_SM9_SIGN), "SM9_sign"},
    {ERR_FUNC(SM9_F_SM9_SIGNFINAL), "SM9_SignFinal"},
    {ERR_FUNC(SM9_F_SM9_SIGNINIT), "SM9_SignInit"},
    {ERR_FUNC(SM9_F_SM9_UNWRAP_KEY), "SM9_unwrap_key"},
    {ERR_FUNC(SM9_F_SM9_VERIFY), "SM9_verify"},
    {ERR_FUNC(SM9_F_SM9_VERIFYFINAL), "SM9_VerifyFinal"},
    {ERR_FUNC(SM9_F_SM9_VERIFYINIT), "SM9_VerifyInit"},
    {ERR_FUNC(SM9_F_SM9_WRAP_KEY), "SM9_wrap_key"},
    {0, NULL}
};

static ERR_STRING_DATA SM9_str_reasons[] = {
    {ERR_REASON(SM9_R_BUFFER_TOO_SMALL), "buffer too small"},
    {ERR_REASON(SM9_R_DECODE_ERROR), "decode error"},
    {ERR_REASON(SM9_R_DIGEST_FAILURE), "digest failure"},
    {ERR_REASON(SM9_R_EC_LIB), "ec lib"},
    {ERR_REASON(SM9_R_EXTENSION_FIELD_ERROR), "extension field error"},
    {ERR_REASON(SM9_R_GENERATE_MAC_FAILURE), "generate mac failure"},
    {ERR_REASON(SM9_R_HASH_FAILURE), "hash failure"},
    {ERR_REASON(SM9_R_INVALID_CIPHERTEXT), "invalid ciphertext"},
    {ERR_REASON(SM9_R_INVALID_DIGEST_TYPE), "invalid digest type"},
    {ERR_REASON(SM9_R_INVALID_ENCPARAMETERS), "invalid encparameters"},
    {ERR_REASON(SM9_R_INVALID_HASH1), "invalid hash1"},
    {ERR_REASON(SM9_R_INVALID_HASH2_DIGEST), "invalid hash2 digest"},
    {ERR_REASON(SM9_R_INVALID_ID), "invalid id"},
    {ERR_REASON(SM9_R_INVALID_ID_LENGTH), "invalid id length"},
    {ERR_REASON(SM9_R_INVALID_INPUT), "invalid input"},
    {ERR_REASON(SM9_R_INVALID_KEM_KEY_LENGTH), "invalid kem key length"},
    {ERR_REASON(SM9_R_INVALID_KEY_AGREEMENT_CHECKSUM),
     "invalid key agreement checksum"},
    {ERR_REASON(SM9_R_INVALID_KEY_LENGTH), "invalid key length"},
    {ERR_REASON(SM9_R_INVALID_MD), "invalid md"},
    {ERR_REASON(SM9_R_INVALID_PAIRING_TYPE), "invalid pairing type"},
    {ERR_REASON(SM9_R_INVALID_PARAMETER), "invalid parameter"},
    {ERR_REASON(SM9_R_INVALID_POINTPPUB), "invalid pointppub"},
    {ERR_REASON(SM9_R_INVALID_PRIVATE_POINT), "invalid private point"},
    {ERR_REASON(SM9_R_INVALID_SCHEME), "invalid scheme"},
    {ERR_REASON(SM9_R_INVALID_SIGNATURE), "invalid signature"},
    {ERR_REASON(SM9_R_INVALID_SIGNATURE_FORMAT), "invalid signature format"},
    {ERR_REASON(SM9_R_INVALID_TYPE1CURVE), "invalid type1curve"},
    {ERR_REASON(SM9_R_KDF_FAILURE), "kdf failure"},
    {ERR_REASON(SM9_R_NO_MASTER_SECRET), "no master secret"},
    {ERR_REASON(SM9_R_PAIRING_ERROR), "pairing error"},
    {ERR_REASON(SM9_R_RATE_PAIRING_ERROR), "rate pairing error"},
    {ERR_REASON(SM9_R_TWIST_CURVE_ERROR), "twist curve error"},
    {ERR_REASON(SM9_R_VERIFY_FAILURE), "verify failure"},
    {ERR_REASON(SM9_R_ZERO_ID), "zero id"},
    {0, NULL}
};

#endif

int ERR_load_SM9_strings(void)
{
#ifndef OPENSSL_NO_ERR

    if (ERR_func_error_string(SM9_str_functs[0].error) == NULL) {
        ERR_load_strings(0, SM9_str_functs);
        ERR_load_strings(0, SM9_str_reasons);
    }
#endif
    return 1;
}
