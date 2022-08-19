/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "Enclave_t.h"

#include "sgx_trts.h"
#include "sgx_error.h"
#include "sgx_report.h"
#include "sgx_utils.h"
#include "sgx_tcrypto.h"
#include "mbusafecrt.h" /* memcpy_s */

/* Global copy of RSA key pair */
static rsa_params_t g_rsa_key;

/* Have we generated RSA key pair already? */
static bool key_pair_created = false;

uint32_t enclave_create_pubkey(
    rsa_params_t* key)
{
    sgx_status_t status;
    key->e[0] = 0x10001;
    g_rsa_key.e[0] = 0x10001;

    if (!key_pair_created) {

        status = sgx_create_rsa_key_pair(N_SIZE_IN_BYTES,
                                           E_SIZE_IN_BYTES,
                                           (unsigned char*)g_rsa_key.n,
                                           (unsigned char*)g_rsa_key.d,
                                           (unsigned char*)g_rsa_key.e,
                                           (unsigned char*)g_rsa_key.p,
                                           (unsigned char*)g_rsa_key.q,
                                           (unsigned char*)g_rsa_key.dmp1,
                                           (unsigned char*)g_rsa_key.dmq1,
                                           (unsigned char*)g_rsa_key.iqmp);

        if (SGX_SUCCESS != status) {
            //printf("RSA key pair creation failed.");
            return status;
        }
        key_pair_created = true;
    }

    for(int i = 0; i < N_SIZE_IN_BYTES; i++) {
        key->n[i] = g_rsa_key.n[i];
    }
    for(int i = 0; i < E_SIZE_IN_BYTES; i++) {
        key->e[i] = g_rsa_key.e[i];
    }

    return SGX_SUCCESS;
}

uint32_t enclave_create_report(const sgx_target_info_t* p_qe3_target,
                                uint8_t* nonce,
                                uint32_t nonce_size,
                                sgx_report_t* p_report)
{
    sgx_status_t status = SGX_SUCCESS;
    sgx_report_data_t report_data = {0};
    uint8_t msg_hash[64] = {0};

    const uint32_t size = nonce_size + E_SIZE_IN_BYTES + N_SIZE_IN_BYTES;

    uint8_t* pdata = (uint8_t *)malloc(size);
    if (!pdata) {
        //printf("ReportData memory allocation failed.");
        return status;
    }

    errno_t err = 0;
    err = memcpy_s(pdata, nonce_size, nonce, nonce_size);
    if (err != 0) {
            //printf("memcpy of nonce failed.");
            goto CLEANUP;
    }

    err = memcpy_s(pdata + nonce_size, E_SIZE_IN_BYTES, ((unsigned char *)g_rsa_key.e), E_SIZE_IN_BYTES);
    if (err != 0) {
        //printf("memcpy of exponent failed.");
        goto CLEANUP;
    }

    err = memcpy_s(pdata + nonce_size + E_SIZE_IN_BYTES, N_SIZE_IN_BYTES, ((unsigned char *)g_rsa_key.n), N_SIZE_IN_BYTES);
    if (err != 0) {
        //printf("memcpy of modulus failed.");
        goto CLEANUP;
    }

    status = sgx_sha256_msg(pdata, size, (sgx_sha256_hash_t *)msg_hash);
    if (SGX_SUCCESS != status) {
        //printf("Hash of userdata failed!");
        goto CLEANUP;
    }

    err = memcpy_s(report_data.d, sizeof(msg_hash), msg_hash, sizeof(msg_hash));
    if (err != 0) {
            //printf("memcpy of reportdata failed.");
            status = SGX_ERROR_UNEXPECTED;
        goto CLEANUP;
    }

    // Generate the report for the app_enclave
    status = sgx_create_report(p_qe3_target, &report_data, p_report);
    if (SGX_SUCCESS != status) {
        //printf("Enclave report creation failed!");
        goto CLEANUP;
    }

CLEANUP:
    free(pdata);
    return status;
}

