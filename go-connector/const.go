/*
 *   Copyright (c) 2022-2023 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package connector

const (
	headerXApiKey     = "x-api-key"
	headerAccept      = "Accept"
	headerContentType = "Content-Type"
	HeaderRequestId   = "request-id"
	HeaderTraceId     = "trace-id"

	nonceEndpoint = "/appraisal/v1/nonce"
	// TODO:  "tpm only" attestation should be directed to /azure.
	//	attestEndpoint = "/appraisal/v2/attest/azure"
	attestEndpoint = "/appraisal/v2/attest"

	mimeApplicationJson        = "application/json"
	AtsCertChainMaxLen         = 10
	MaxRetries                 = 2
	DefaultRetryWaitMinSeconds = 2
	DefaultRetryWaitMaxSeconds = 10
	ServiceUnavailableError    = `service unavailable`

	HttpsScheme = "https"
)

type JwtAlg string

const (
	RS256 JwtAlg = "RS256"
	PS384 JwtAlg = "PS384"
)
