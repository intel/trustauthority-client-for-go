/*
 *   Copyright (c) 2022-2024 Intel Corporation
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

	nonceEndpoint         = "/appraisal/v2/nonce"
	attestEndpoint        = "/appraisal/v1/attest"
	attestAzureTdEndpoint = "/appraisal/v1/attest/azure/tdxvm"
	attestV2Endpoint      = "/appraisal/v2/attest"

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

func validJwtTokenSignAlgs() []string {
	return []string{string(RS256), string(PS384)}
}
