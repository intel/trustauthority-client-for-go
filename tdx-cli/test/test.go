/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gorilla/mux"
	"github.com/intel/trustauthority-client/go-connector"
)

var nonce = `
{
    "val": "WmxZeHZVMTA4SVdvS0tlRXg3RTJWZkpYSFdjcGhLNTVYUFpHbGNRS3Q1aXQwMVhic2xnUVJ6NlVBUVR6dXRENmVhZ2ZmbzBDMlF5WUFzdzl4aXhtdXc9PQ==",
    "iat": "MjAyMi0xMi0xNCAwOTozMzoyNi41MTE4MzY5MjUgKzAwMDAgVVRD",
    "signature": "WxZemPKfFVbwaLMmbnDt2Qqw3M8N2OmiWjQgN8cKGrdsVFReV/il0UhIbSsK7bebvje0B+XI9Hs1ycYOVe6/5vvj9rd+Nky5tvHb++07XP5ZuMqpaFiGuH9p8dNZPuaDNhTr/hx0wFi0MHuPyn73xsQ4GAZux1FHkBeCSXHNItxcKGj+NvBs6oWD/V8OLmN+jwGYIlhSfwu0bnXpHd8jy6TnKm4e23poSagJ8gmMhZEsNEPXlgBIUfOp3LOd6z+W266hyPeumna2DEOX4sAOQfR8pI9dWdPQ3IU+83jHKXzyInubUA+BwcUUdJdDxF4eOzAPj1kPBy1xbd47+yAlZuCS345opzgwgNivr9wy5yrq+vGJeRHFUXzblqy1jhTkbPeWKajIqFPKqvtyWgJgRz7ywMCdoM4zw9tQoSzkg+oWt3lxg7ztuH33+LrJ9BvZknbKdSkvzXSPm6artH+M51ZRO55KIPGYYn3X1NLEUlqmGAm6ijVB9UiFw+rPa6vL79u1DdEQ8AOXBnI9bgeM5PYGBTARRmABS21RBbpEOeFAMNSFalna2ZleMiCcFBCE6P5GtVXT6IIREMKBoLabL/aAOWsGVK45IXtooX8HroEbX+i2d66dOMXeG6ginPaU75hMn1el01ii34RqlE15d94bj2qqvrDi7wrJbju6ED4="
}
`
var attestationToken = `
{
    "token": "eyJhbGciOiJQUzM4NCIsImprdSI6Imh0dHBzOi8vd3d3LmludGVsLmNvbS9hbWJlci9jZXJ0cyIsImtpZCI6ImM4Mjk4OWJhMTg0ZjQ2ZmYzNjNkMjNlZDk2MTJjMGFiMzg0OWM3MTIiLCJ0eXAiOiJKV1QifQ.eyJhbWJlcl90cnVzdF9zY29yZSI6MCwiYW1iZXJfcmVwb3J0X2RhdGEiOiJmZmVhNDQwNDIzMmZhNWFmNTUzN2I0NTYyZTc5ZWZlNDQwYzI5NmUzMTlmYzkwNDAyODYxNTQyZDg2MTY1YTdkMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsImFtYmVyX3RlZV9oZWxkX2RhdGEiOiJBUUFCQU11TGRKSGJVYk9RMGFNTkJJZzVrSmJVMk82cHB1Zjh1cXRYU3AxRHR1WkFwVWVjUS9XamFENTNnMm1rS0ZndDZYUTg2bk1mMXJNNGhhVjM1cWJ0R3BJSm9sbW96NjJ6SXA1MDFhbEhLelVqVzFpNXdtYUVEbGczTStUUkR4R2pvYTBwSUVjNkE5dTFZSTFxVTZLUHh1Mmp5MXNhR2s4RXZwZGRXS1NGamNvSWp2R2c5TFJSWTMxVFNvMWJZWi9SQ0tiZTVhTFA5VGJ5ZGJpd0diNSs2VE1TUCtwT3laWHpYeEVnK051YjJpcTJqNUlkdHBDMG1xbzYwS1dsVStLcElzVkJIT0c0MXRMOENBSzBHRFJNUkZ2RnMzRGdMUkdSZ0s5d2Z4SVltdTRjRmJnS0lEM1NWcndnaGJER3d4QXlwSlByMXJuMlZkaXd1ZldSNG9zS3huUWFuM3lhN0tsTk5EaFJpY3RJd2UwVFdxeEpEZGp1RmxBSG8wcU9pVkphL1pVYzErUWxMVm5wenZlSy9BSVR2dit1TGNJYnJsRWZNT1ViRUpYc1YzWGhEeG1sRnZDb0V3YWtKT1NKVnBsQUNHSmVrWG5rclhFMjZKNTFtbHhLWTBHZlVuaWYvNUpmQnd0T253eTczZ255OFp1VGY4akhRVkxINHA0RG01TUNFdz09IiwiYW1iZXJfc2d4X21yZW5jbGF2ZSI6IjJmNjlmOTcwNzAyYTFhODVkYjM1NDc5ZWU3ZWQ4ODhmYmQ3ZmYzZTY2NjY2MTZmZjlhMWY0OTZhNzQ4YjY1MzkiLCJhbWJlcl9zZ3hfaXNfZGVidWdnYWJsZSI6ZmFsc2UsImFtYmVyX3NneF9tcnNpZ25lciI6ImQ1N2M0ZDcxZjc1MTIxNjlkNDk4NGZmNDRmOTI3MDViOWFiNTZkNmI5MzhhZDVlODcwYzA5YTFlZTMzMDVkYjIiLCJhbWJlcl9zZ3hfaXN2cHJvZGlkIjowLCJhbWJlcl9zZ3hfaXN2c3ZuIjowLCJhbWJlci1mYWl0aGZ1bC1zZXJ2aWNlLWlkcyI6WyIyZWQ4OTg0YS0zNDcwLTQ0OGEtOGRhNC0yODM4ZjY2ZDdhNDEiLCI3NDIzMmQ2Ni05MGUzLTQ4ODAtYmU4Zi02ZWRmZWMxMmYzYmEiXSwiYW1iZXJfdGNiX3N0YXR1cyI6Ik9VVF9PRl9EQVRFIiwiYW1iZXJfZXZpZGVuY2VfdHlwZSI6IlNHWCIsImFtYmVyX3NpZ25lZF9ub25jZSI6dHJ1ZSwidmVyIjoiMS4wIiwiZXhwIjoxNjcxODAwNzk4LCJqdGkiOiIxNzIxODc4ZS00ZTczLTRhNTgtODM3Ny1hNzQxNTg5YTgwNDgiLCJpYXQiOjE2NzE3OTk1NjgsImlzcyI6IkFTIEF0dGVzdGF0aW9uIFRva2VuIElzc3VlciJ9.Gb4A2jpAnYR3v3k4JF-2sN8WDwEXwhtsrK-ScODpsHJverZ7VBuCVfdsooei7QptXllhw4yIzlopFo8g0mkghj1SHtGomxQg2ficE-GulAkYJEkN5Pfzo6vXzbf6Iyil0hy9r0kRNRDVK6yJuDq_TVOsSYT2RWaLwJNOGk8in0_OuD0xKHDHQGCNKb9OJKMntP_9bS7g77vMgsjMPj9-2PEsUldE1JgB_Vy2dUP3T87HiWVMCh6TKd66R6rsFBE_WloNqdH6MVfU3UkDcETuZ-YERUIuf2rcld-uCWbI-OwwRKosi3jaI_B-6DIZx-HmhqbZWrelpW4kKKnbWNix0uxOyG1eCQdK_Hl_lYHhuKF-o9TQ94nOz_ei9YznGAKTzJSDKH2-kXlINvNN511WhEnwzWiFbUT0CDhqr7b4Hj3fWtqDWSgymttxWS04pySwC0agxkCW_PHZZFz_Gc1v5jkIpmVDYPDs_HagLVn_kakPLwVRRqaK7FWIDziST00l"
}
`

func MockTrustAuthorityServer(t *testing.T) *httptest.Server {
	nonceApi := "/appraisal/v2/nonce"
	attestApi := "/appraisal/v2/attest"

	r := mux.NewRouter()

	r.HandleFunc(nonceApi, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add(connector.HeaderRequestId, "req1")
		w.Header().Add(connector.HeaderTraceId, "JVygrGiiIAMEJPw=")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		_, err := w.Write([]byte(nonce))
		if err != nil {
			t.Log("Unable to write data")
		}
	}).Methods(http.MethodGet)

	r.HandleFunc(attestApi, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add(connector.HeaderRequestId, "req1")
		w.Header().Add(connector.HeaderTraceId, "JVygrGiiIAMEJPw=")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		_, err := w.Write([]byte(attestationToken))
		if err != nil {
			t.Log("Unable to write data")
		}
	}).Methods(http.MethodPost)

	httpServer := httptest.NewTLSServer(r)
	os.Setenv("SSL_CERT_FILE", "../../go-connector/test-resources/tls-cert.pem")

	fmt.Println(httpServer.URL)
	return httpServer
}
