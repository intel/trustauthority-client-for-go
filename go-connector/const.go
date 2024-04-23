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

	nonceEndpoint  = "/appraisal/v1/nonce"
	attestEndpoint = "/appraisal/v1/attest/azure/tdxvm"

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

const (
	DefaultApiUrl  = "https://trustauthority.intel.com"
	DefaultBaseUrl = "https://api.trustauthority.intel.com"
)
