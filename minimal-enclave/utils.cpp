/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "Enclave_u.h"
#include "sgx_tcrypto.h"
#include "utils.h"
#include "mbusafecrt.h" /* memcpy_s */

int get_public_key(sgx_enclave_id_t eid, uint8_t **pp_key, uint32_t *p_key_size)
{
    sgx_status_t retval;
    sgx_status_t sgx_status = SGX_SUCCESS;
    rsa_params_t rsa_key;

    sgx_status = enclave_create_pubkey(eid, &retval, &rsa_key);
    if ((SGX_SUCCESS != sgx_status) || (0 != retval)) {
        return -1;
    }

    // Public key format : <exponent:E_SIZE_IN_BYTES><modulus:N_SIZE_IN_BYTES>
    *pp_key = (uint8_t*)malloc(N_SIZE_IN_BYTES + E_SIZE_IN_BYTES);
    if (NULL == *pp_key) {
        return -1;
    }
    memcpy_s(*pp_key, E_SIZE_IN_BYTES, ((const char *)rsa_key.e), E_SIZE_IN_BYTES);
    memcpy_s(*pp_key + E_SIZE_IN_BYTES, E_SIZE_IN_BYTES, ((const char *)rsa_key.n), N_SIZE_IN_BYTES);

    *p_key_size = E_SIZE_IN_BYTES + N_SIZE_IN_BYTES;

    return 0;
}

void free_public_key(uint8_t *p_key)
{
    free(p_key);
}

