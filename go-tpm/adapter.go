/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package tpm

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/intel/trustauthority-client/go-connector"
	"github.com/sirupsen/logrus"

	"github.com/pkg/errors"
)

// TpmAdapterOptions for creating an evidence adapter using the host's TPM.
type TpmAdapterOptions func(*tpmAdapter) error

type tpmAdapter struct {
	tpmFactory       TpmFactory
	akHandle         int
	pcrSelections    []PcrSelection
	deviceType       TpmDeviceType
	ownerAuth        string
	withImaLogs      string
	withUefiLogs     string
	akCertificateUri *url.URL
}

var defaultAdapter = tpmAdapter{
	akHandle:      DefaultAkHandle,
	pcrSelections: defaultPcrSelections,
	deviceType:    TpmDeviceLinux,
	ownerAuth:     "",
	withImaLogs:   "",
	withUefiLogs:  "",
}

type TpmAdapterFactory interface {
	New(opts ...TpmAdapterOptions) (connector.CompositeEvidenceAdapter, error)
}

type tpmAdapterFactory struct {
	tpmFactory TpmFactory
}

func (t *tpmAdapterFactory) New(opts ...TpmAdapterOptions) (connector.CompositeEvidenceAdapter, error) {
	// create an adapter with default values
	tca := defaultAdapter
	tca.tpmFactory = t.tpmFactory

	// iterate over the options and apply them to the adapter
	for _, option := range opts {
		if err := option(&tca); err != nil {
			return nil, err
		}
	}

	return &tca, nil
}

func NewTpmAdapterFactory(tpmFactory TpmFactory) TpmAdapterFactory {
	return &tpmAdapterFactory{tpmFactory: tpmFactory}
}

// WithOwnerAuth specifies the owner password used to communicate
// with the TPM.  By default, the empty string is used.
func WithOwnerAuth(ownerAuth string) TpmAdapterOptions {
	return func(tca *tpmAdapter) error {
		tca.ownerAuth = ownerAuth
		return nil
	}
}

// WithDeviceType specifies the type of TPM device to use.  By default,
// the Linux device is used (/dev/tpmrm0).
func WithDeviceType(deviceType TpmDeviceType) TpmAdapterOptions {
	return func(tca *tpmAdapter) error {
		tca.deviceType = deviceType
		return nil
	}
}

// WithAkHandle specifies the ak handle to use during quote generation.  By default,
// it uses
func WithAkHandle(akHandle int) TpmAdapterOptions {
	return func(tca *tpmAdapter) error {
		if akHandle == 0 {
			akHandle = DefaultAkHandle
		}

		tca.akHandle = akHandle
		return nil
	}
}

// WithPcrSelections configures which PCRs to include during TPM quote generation.
func WithPcrSelections(selections string) TpmAdapterOptions {
	return func(tca *tpmAdapter) error {
		pcrSelections, err := parsePcrSelections(selections)
		if err != nil {
			return err
		}
		tca.pcrSelections = pcrSelections
		return nil
	}
}

// WithImaLogs controls the inclusion of IMA logs into TPM evidence.  When enabled,
// logs from "/sys/kernel/security/ima/ascii_runtime_measurements" will be included
// in evidence.
func WithImaLogs(enabled bool) TpmAdapterOptions {
	return func(tca *tpmAdapter) error {
		if enabled {
			tca.withImaLogs = DefaultImaPath
		} else {
			tca.withImaLogs = ""
		}
		return nil
	}
}

// WithUefiEventLogs controls the inclusion of UEFI event logs into TPM evidence.  When enabled,
// logs from "/sys/kernel/security/tpm0/binary_bios_measurements" will be included
// in evidence.
func WithUefiEventLogs(enabled bool) TpmAdapterOptions {
	return func(tca *tpmAdapter) error {
		if enabled {
			tca.withUefiLogs = DefaultUefiEventLogPath
		} else {
			tca.withUefiLogs = ""
		}
		return nil
	}
}

// WithAkCertificateUri specifies the full path to an AK certificate file
// in PEM format that will be used by ITA to verify the TPM quotes.
func WithAkCertificateUri(uriString string) TpmAdapterOptions {
	return func(tca *tpmAdapter) error {
		// Azure vTPM does not require an AK certificate -- an empty string is allowed
		if uriString == "" {
			logrus.Warn("The ak_certificate was not defined in configuration and will not be included in TPM evidence.")
			return nil
		}

		uri, err := url.Parse(uriString)
		if err != nil {
			return errors.Wrapf(err, "Failed to parse AK certificate URI %s", uriString)
		}

		if uri.Scheme == "file" || uri.Scheme == "nvram" {
			// ok, path/nvram validation will occur when the cert is read in readAkCertificate()
		} else {
			return errors.Errorf("Unsupported URI scheme %s", uri.Scheme)
		}

		tca.akCertificateUri = uri
		return nil
	}
}

func (tca *tpmAdapter) GetEvidenceIdentifier() string {
	return "tpm"
}

func (tca *tpmAdapter) GetEvidence(verifierNonce *connector.VerifierNonce, userData []byte) (interface{}, error) {

	tpm, err := tca.tpmFactory.New(tca.deviceType, tca.ownerAuth)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrTpmOpenFailure, err)
	}
	defer tpm.Close()

	// Create a sha256 hash of the verifier-nonce and user-data.
	nonceHash, err := createNonceHash(verifierNonce, userData)
	if err != nil {
		return nil, err
	}

	quote, signature, err := tpm.GetQuote(tca.akHandle, nonceHash, tca.pcrSelections...)
	if err != nil {
		return nil, fmt.Errorf("%w: AK handle 0x%x: %w", ErrQuoteFailure, tca.akHandle, err)
	}

	pcrs, err := tpm.GetPcrs(tca.pcrSelections...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPCRsFailure, err)
	}

	var imaLogs []byte
	if tca.withImaLogs != "" {
		imaLogs, err = readFile(tca.withImaLogs)
		if err != nil {
			return nil, fmt.Errorf("%w: path %q", ErrFailedToReadIMALogs, tca.withImaLogs)
		}
	}

	var uefiEventLogs []byte
	if tca.withUefiLogs != "" {
		uefiBytes, err := readFile(tca.withUefiLogs)
		if err != nil {
			return nil, fmt.Errorf("%w: path %q", ErrFailedToReadUEFILogs, tca.withUefiLogs)
		}

		eventLogFilter, err := newEventLogFilter(uefiBytes, tca.pcrSelections...)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to create event log filter for file")
		}

		uefiEventLogs, err = eventLogFilter.FilterEventLogs()
		if err != nil {
			return nil, errors.Wrap(err, "Failed to parse uefi event log file")
		}
	}

	// When specified by WithAkCertificatePath, read the AK certificate from the
	// file system, convert it to der format so that it is included in the evidence.
	var akDer []byte
	if tca.akCertificateUri != nil {
		akDer, err = readAkCertificate(tca.akCertificateUri, tpm)
		if err != nil {
			return nil, err
		}
	}

	tpmEvidence := struct {
		Q []byte                   `json:"quote"`
		S []byte                   `json:"signature"`
		P []byte                   `json:"pcrs"`
		U []byte                   `json:"user_data,omitempty"`
		I []byte                   `json:"ima_logs,omitempty"`
		E []byte                   `json:"uefi_event_logs,omitempty"`
		V *connector.VerifierNonce `json:"verifier_nonce,omitempty"`
		A []byte                   `json:"ak_certificate_der,omitempty"`
	}{
		Q: quote,
		S: signature,
		P: pcrs,
		U: userData,
		I: imaLogs,
		E: uefiEventLogs,
		V: verifierNonce,
		A: akDer,
	}

	return &tpmEvidence, nil
}

func createNonceHash(verifierNonce *connector.VerifierNonce, userData []byte) ([]byte, error) {
	if verifierNonce == nil && len(userData) == 0 {
		return nil, nil
	}

	// Assume there are four possible combinations of verifier-nonce and user-data:
	// - None: no verifier-nonce or user-data (empty array)
	// - Just verifier-nonce (no user-data)
	// - Just user-data (no verifier-nonce)
	// - Both verifier-nonce and user-data
	//
	// The order will always be "verifier-nonce.Val" followed by "user-data".
	nonceBytes := []byte{}
	if verifierNonce != nil {
		nonceBytes = append(nonceBytes, verifierNonce.Val...)
		nonceBytes = append(nonceBytes, verifierNonce.Iat...)
	}

	if len(userData) > 0 {
		nonceBytes = append(nonceBytes, userData...)
	}

	h := sha256.New()
	_, err := h.Write(nonceBytes)
	if err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

func readFile(filePath string) ([]byte, error) {
	err := validateFilePath(filePath)
	if err != nil {
		return nil, err
	}

	return os.ReadFile(filePath)
}

// validateFilePath performs checks fo path traversal (CT203 and T162),
// and symlinks (T572) and assumes that os.Lstat (aka "linux") will
// perform checks for the file's existence, unallowed characters (T34),
// permissions, etc.
func validateFilePath(filePath string) error {

	if strings.Contains(filePath, "..") {
		return ErrPathTraversal
	}

	info, err := os.Lstat(filePath)
	if err != nil {
		return err
	}

	if info.Mode()&os.ModeSymlink != 0 {
		return ErrSymlinksNotAllowed
	}

	return nil
}

func readAkCertificate(akUri *url.URL, tpm TrustedPlatformModule) ([]byte, error) {
	var akBytes []byte
	var results []byte
	var err error

	if akUri.Scheme == "file" {
		akBytes, err = readFile(akUri.Path)
		if err != nil {
			return nil, fmt.Errorf("%w: Failed to read AK certificate PEM from file %s", ErrReadAkFileFailure, akUri.Path)
		}
	} else if akUri.Scheme == "nvram" {
		hexString := strings.TrimPrefix(akUri.Host, "0x")
		nvIdx, err := strconv.ParseInt(hexString, 16, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: Failed to parse %s: %w", ErrReadAkNvramInvalidHex, hexString, err)
		}

		akBytes, err = tpm.NVRead(int(nvIdx))
		if err != nil {
			return nil, fmt.Errorf("%w: Failed to read AK certificate from NV index 0x%x: %w", ErrReadAkNvramFailure, nvIdx, err)
		}
	}

	akCert, err := parseCertificateBytes(akBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse AK certificate from %s: %w", akUri, err)
	}
	results = append(results, akCert.Raw...)

	caCert, err := getCAIssuerCertificate(akCert)
	if err != nil {
		return nil, fmt.Errorf("failed to get CA issuer from %s: %w", akUri, err)
	}

	// it's possible that the AK certificate does not contain an issuer
	if caCert != nil {
		results = append(results, caCert.Raw...)
	}

	return results, nil
}

var (
	// OID for Authority Information Access
	oidAuthorityInfoAccess = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}

	// OID for id-ad-caIssuers
	oidCAIssuers = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
)

// GeneralName type 6 = URI
const generalNameURI = 6

type accessDescription struct {
	AccessMethod   asn1.ObjectIdentifier
	AccessLocation asn1.RawValue
}

func getCAIssuerCertificate(akCert *x509.Certificate) (*x509.Certificate, error) {
	issuerUrl := ""
	for _, ext := range akCert.Extensions {
		if ext.Id.Equal(oidAuthorityInfoAccess) {
			var aia []accessDescription
			_, err := asn1.Unmarshal(ext.Value, &aia)
			if err != nil {
				return nil, err
			}

			for _, ad := range aia {
				if ad.AccessMethod.Equal(oidCAIssuers) && ad.AccessLocation.Tag == generalNameURI {
					issuerUrl = string(ad.AccessLocation.Bytes)
					break
				}
			}
		}
	}

	// cert did not contain an issuer
	if issuerUrl == "" {
		logrus.Debug("AK certificate did not contain an issuer URL")
		return nil, nil
	}

	return getIssuerCertificate(issuerUrl, http.Get)
}

type GetFunc func(url string) (*http.Response, error)

func getIssuerCertificate(issuerUrl string, getFx GetFunc) (*x509.Certificate, error) {
	resp, err := getFx(issuerUrl)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to fetch certificate from %s: %w", ErrIssuerCAHttpError, issuerUrl, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: downloading cert %s return error status: %s", ErrIssuerCAStatusError, issuerUrl, resp.Status)
	}

	// Read response body (expected to be DER)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate data: %w", err)
	}

	ca, err := parseCertificateBytes(body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	logrus.Debugf("Successfully downloaded intermediate CA certificate from %s\n", issuerUrl)
	return ca, nil
}

// parseCertificateBytes parses the certificate bytes in either PEM or DER format.
func parseCertificateBytes(certBytes []byte) (*x509.Certificate, error) {
	var cb []byte

	block, _ := pem.Decode(certBytes)
	if block != nil {
		if block.Type != "CERTIFICATE" {
			return nil, ErrInvalidPemType
		}

		cb = block.Bytes
	} else {
		cb = certBytes
	}

	cert, err := x509.ParseCertificate(cb)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse certificate: %w", ErrInvalidCertificate, err)
	}

	return cert, nil
}
