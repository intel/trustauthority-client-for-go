//go:build !test

/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tpm

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"strings"

	"github.com/intel/trustauthority-client/go-connector"

	"github.com/pkg/errors"
)

// TpmAdapterOptions for creating an evidence adapter using the host's TPM.
type TpmAdapterOptions func(*tpmAdapter) error

type tpmAdapter struct {
	akHandle         int
	pcrSelections    []PcrSelection
	deviceType       TpmDeviceType
	ownerAuth        string
	imaLogPath       string
	uefiEventLogPath string
}

var defaultAdapter = tpmAdapter{
	akHandle:         DefaultAkHandle,
	pcrSelections:    defaultPcrSelections,
	deviceType:       Linux,
	ownerAuth:        "",
	imaLogPath:       "",
	uefiEventLogPath: "",
}

// NewCompositeEvidenceAdapter creates a new composite adapter for the host's TPM.
func NewCompositeEvidenceAdapter(akHandle int, pcrSelections string, ownerAuth string) (connector.CompositeEvidenceAdapter, error) {
	selections, err := parsePcrSelections(pcrSelections)
	if err != nil {
		return nil, err
	}

	if akHandle == 0 {
		akHandle = DefaultAkHandle
	}

	return &tpmAdapter{
		akHandle:      akHandle,
		pcrSelections: selections,
		ownerAuth:     ownerAuth,
	}, nil
}

// NewCompositeEvidenceAdapterWithOptions creates a new composite adapter for the host's TPM.
func NewCompositeEvidenceAdapterWithOptions(opts ...TpmAdapterOptions) (connector.CompositeEvidenceAdapter, error) {
	// create an adpater with default values
	tca := defaultAdapter

	// iterate over the options and apply them to the adapter
	for _, option := range opts {
		if err := option(&tca); err != nil {
			return nil, err
		}
	}

	return &tca, nil
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

// WithImaLogs will include the IMA log into TPM evidence using the
// specified 'imaPath' parameter. If the path is empty, the default value of
// "/sys/kernel/security/ima/ascii_runtime_measurements" is used.  An error
// is returned if the specified file cannot be read.
func WithImaLogs(imaPath string) TpmAdapterOptions {
	return func(tca *tpmAdapter) error {
		var logPath string
		if len(imaPath) == 0 {
			logPath = DefaultImaPath
		} else {
			logPath = imaPath
		}

		_, err := os.Stat(logPath)
		if err != nil {
			return errors.Wrapf(err, "Failed to open ima log file %q", logPath)
		}

		tca.imaLogPath = logPath
		return nil
	}
}

// WithUefiEventLogs will include the UEFI event log into TPM evidence using the
// specified 'uefiLogPath'.  If the uefiLogPath is empty, the default value of
// "/sys/kernel/security/tpm0/binary_bios_measurements" is used.  An error is returned
// if the specified file cannot be read.
func WithUefiEventLogs(uefiLogPath string) TpmAdapterOptions {
	return func(tca *tpmAdapter) error {
		var logPath string
		if len(uefiLogPath) == 0 {
			logPath = DefaultUefiEventLogPath
		} else {
			logPath = uefiLogPath
		}

		_, err := os.Stat(logPath)
		if err != nil {
			return errors.Wrapf(err, "Failed to open uefi event log file %q", logPath)
		}

		tca.uefiEventLogPath = logPath
		return nil
	}
}

func (tca *tpmAdapter) GetEvidenceIdentifier() string {
	return "tpm"
}

func (tca *tpmAdapter) GetEvidence(verifierNonce *connector.VerifierNonce, userData []byte) (interface{}, error) {
	tpm, err := New(
		WithTpmDeviceType(tca.deviceType),
		WithTpmOwnerAuth(tca.ownerAuth),
	)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to open TPM")
	}

	// Create a sha256 hash of the verifier-nonce and user-data.
	nonceHash, err := createNonceHash(verifierNonce, userData)
	if err != nil {
		return nil, err
	}

	quote, signature, err := tpm.GetQuote(tca.akHandle, nonceHash, tca.pcrSelections...)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to get quote using AK handle 0x%x", tca.akHandle)
	}

	pcrs, err := tpm.GetPcrs(tca.pcrSelections...)
	if err != nil {
		return nil, err
	}

	var imaLogs []byte
	if tca.imaLogPath != "" {
		imaLogs, err = os.ReadFile(tca.imaLogPath)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to get ima logs from file %q", tca.imaLogPath)
		}
	}

	var uefiEventLogs []byte
	if tca.uefiEventLogPath != "" {
		uefiBytes, err := os.ReadFile(tca.uefiEventLogPath)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to open uefi event logs from file %q", tca.uefiEventLogPath)
		}

		uefiEventLogs, err = filterEventLogs(uefiBytes, tca.pcrSelections...)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to read uefi event logs from file %q", tca.uefiEventLogPath)
		}
	}

	tpmEvidence := struct {
		Q []byte                   `json:"quote"`
		S []byte                   `json:"signature"`
		P []byte                   `json:"pcrs"`
		U []byte                   `json:"user_data,omitempty"`
		I []byte                   `json:"ima_logs,omitempty"`
		E []byte                   `json:"tcg_event_logs,omitempty"`
		V *connector.VerifierNonce `json:"verifier_nonce,omitempty"`
	}{
		Q: quote,
		S: signature,
		P: pcrs,
		U: userData,
		I: imaLogs,
		E: uefiEventLogs,
		V: verifierNonce,
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

// filterEventLogs filters TCG event logs to only include the PCRs and hashes selected
// by the user (ex. via "selection" parameter).  The goal of this filtering
// is to 1.) reduce the oversize of logs transmitted to the ITA server and 2.) to allow
// customers to avoid event-log replay errors caused byPCR brittleness (ex. they can exclude
// problematic PCRs that may fail verification on the ITA server).
//
// The event log is populated by the UEFI firmware and is configured in the BIOS to enable/disable
// different PCR banks.  For example, the user may update their BIOS to only enable sha1 pcrs,
// use a combination (ex. sha1 and sha256) or enable all pcrs (sha1,sha256,sha384,sha512).
//
// This function linearly parses the TCG event data, skipping over events with PCRs and hashes
// that are not part of the "selection".  The initial "spec03" event is always included.  Event
// hashes are also stripped (ex. the event contains SHA384 but that PCR bank was not selected).
// The output is a byte array containing the filtered event logs in TCG format (i.e., that is sent
// to the ITA server).
//
// The following table describes the expected results for different pcr selections:
//
// UEFI Enabled PCRs   ITA Selected PCRs              Expected Results
// ----------------    -------------------            -----------------
// sha1                sha1:all					   	  UEFI events is the same as filtered events.
// sha1                sha1:1,3,7                     Event-log is filtered to only include pcr1, pcr3, and pcr7.
// sha1                sha256:all                     Empty (filtered events only includes spec03 event).
// sha1,sha256		   sha256:1,3,7                   Event-og is filtered to only include pcr1, pcr3, and pcr7 (no sha1 digests).
func filterEventLogs(evlBuffer []byte, selection ...PcrSelection) ([]byte, error) {
	var buf bytes.Buffer
	pos := 0

	// Maps selected pcr indices to the list of hash selected algorithms.
	// Used to determine which event data should be included in the
	// results.
	filterLookup := make(map[int][]crypto.Hash)
	for _, sel := range selection {
		for _, pcr := range sel.Pcrs {
			if _, ok := filterLookup[pcr]; !ok {
				filterLookup[pcr] = []crypto.Hash{}
			}

			filterLookup[pcr] = append(filterLookup[pcr], sel.Hash)
		}
	}

	// preallocate 40k for uefi event logs
	buf.Grow(40960)

	// always validate the TCG header and included it in the results
	// (unless errors are encountered).
	pos, err := validateTcgHeader(evlBuffer)
	if err != nil {
		return nil, errors.Wrap(err, "Invalid event log header")
	}
	_, err = buf.Write(evlBuffer[0:pos])
	if err != nil {
		return nil, err
	}

	// Loop through the event log entries and create the resulting output buffer.
	//
	// The event log format is as follows:
	// FIELD             LEN
	// -------------     ---------------
	// PCR Index         4 bytes
	// Event Type        4 bytes
	// Digest Count      4 bytes
	//    Algorithm ID   2 bytes (for each digest)
	//    Digest Value   "Hash size from alg id" (for each digest)
	// Event Size        4 bytes
	// Event Data        "Event Size" bytes
	for true {
		if pos >= len(evlBuffer) {
			goto done
		}

		// pcr index
		pcr := int32(binary.LittleEndian.Uint32(evlBuffer[pos : pos+4]))
		if pcr < 0 || pcr > 23 {
			return nil, errors.Errorf("Event log contained invalid PCR index %d at offset %d", pcr, pos)
		}
		pos += 4

		// event type
		eventType := int32(binary.LittleEndian.Uint32(evlBuffer[pos : pos+4]))
		pos += 4

		// digest count
		digestCount := int32(binary.LittleEndian.Uint32(evlBuffer[pos : pos+4]))
		if digestCount < 0 || digestCount > 4 { // Assume less than 4 (sha1, sha256, sha384, sha512)
			return nil, errors.Errorf("Event log contained invalid digest count %d at offset %d", pcr, pos)
		}
		pos += 4

		// Create a map of hash algorithms to their offsets in the event log so
		// they can be added to the results.
		digestOffsets := make(map[crypto.Hash]int)
		for i := 0; i < int(digestCount); i++ {
			// algorithm id
			algId := int16(binary.LittleEndian.Uint16(evlBuffer[pos : pos+2]))
			pos += 2

			var h crypto.Hash
			if algId == 0x4 {
				h = crypto.SHA1
			} else if algId == 0xB {
				h = crypto.SHA256
			} else if algId == 0xC {
				h = crypto.SHA384
			} else if algId == 0xD {
				h = crypto.SHA512
			} else {
				return nil, errors.Errorf("Event log contained invalid digest algorithm %d at offset %d", algId, pos)
			}

			digestOffsets[h] = pos
			pos += h.Size()
		}

		// event size
		eventSize := int32(binary.LittleEndian.Uint32(evlBuffer[pos : pos+4]))
		if eventSize < 0 || eventSize > 1024*32 { // this can include secure boot certs and other large data (assume 32k max)
			return nil, errors.Errorf("Event log contained invalid event size  %d at offset %d", eventSize, pos)
		}
		pos += 4

		// skip pass event data
		eventStart := pos
		pos += int(eventSize)

		// Write the filtered event logs to the output buffer.
		//
		// Assume the event log...
		// - Includes digests based on the PCR banks enabled in te BIOS (ex.
		//   if sha1 is enabled, then all events in the log will have a sha1 digest).
		//
		// Example...
		// pcr index of event is not in selection:  exclude
		// pcr index of event is in selection BUT does not match the selected digest algorithms:  exclude
		// pcr index of event is in selection AND has one or more matching, selected digest algorithms:  include
		if selectedHashAlgs, ok := filterLookup[int(pcr)]; ok {

			// exclude events that where the PCR index is the selection, but its hash algorithm is not
			dCount := 0
			for _, hashAlg := range selectedHashAlgs {
				if _, ok := digestOffsets[hashAlg]; ok {
					dCount++
				}
			}
			if dCount == 0 {
				continue
			}

			// add pcr index
			err = binary.Write(&buf, binary.LittleEndian, uint32(pcr))
			if err != nil {
				return nil, err
			}

			// add event type
			err = binary.Write(&buf, binary.LittleEndian, uint32(eventType))
			if err != nil {
				return nil, err
			}

			// add digest count (only include selected hash algorithms)
			err = binary.Write(&buf, binary.LittleEndian, uint32(dCount))
			if err != nil {
				return nil, err
			}

			for _, hashAlg := range selectedHashAlgs {
				if _, ok := digestOffsets[hashAlg]; !ok {
					continue
				}

				// algorithm id
				var algId int16
				switch hashAlg {
				case crypto.SHA1:
					algId = 0x4
				case crypto.SHA256:
					algId = 0xB
				case crypto.SHA384:
					algId = 0xC
				case crypto.SHA512:
					algId = 0xD
				default:
					return nil, errors.Errorf("Event log contained invalid hash algorithm %v", hashAlg)
				}

				// add algorithm id
				err = binary.Write(&buf, binary.LittleEndian, uint16(algId))
				if err != nil {
					return nil, err
				}

				// ad digest value
				_, err = buf.Write(evlBuffer[digestOffsets[hashAlg] : digestOffsets[hashAlg]+hashAlg.Size()])
			}

			// add event size
			err = binary.Write(&buf, binary.LittleEndian, uint32(eventSize))
			if err != nil {
				return nil, err
			}

			// add event data
			_, err = buf.Write(evlBuffer[eventStart:pos])
			if err != nil {
				return nil, err
			}
		}
	}

done:

	return buf.Bytes(), nil
}

// This function parses the TVG event log header and returns the offset to the first
// real event.  It just attempts to validate that the file is a TCG event log and does
// not attempt to extract any meaningful data from the header event.
//
// See...
// Section 9.4.5.1: https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
func validateTcgHeader(evlBuffer []byte) (int, error) {
	pos := 0

	// pcr index should be 0
	pcr := int32(binary.LittleEndian.Uint32(evlBuffer[pos : pos+4]))
	if pcr != 0 {
		return 0, errors.New("The event log header did not start with PCR 0")
	}
	pos += 4

	// event type should be 3
	eventType := int32(binary.LittleEndian.Uint32(evlBuffer[pos : pos+4]))
	if eventType != 3 {
		return 0, errors.New("The event log header did not have event type 3")
	}
	pos += 4

	pos += 20 // header digest

	// The tdTCG_EfiSpecIdEvent event is minimally 35 bytes long.  Make sure
	// it is that minimum length, not too long (12 extra bytes if four algs
	// are employed) and that it starts with "Spec ID Event03".
	eventSize := int32(binary.LittleEndian.Uint32(evlBuffer[pos : pos+4]))
	if int(eventSize) < 35 || int(eventSize) > 47 {
		return 0, errors.Errorf("The event log header had an correct event size %d", eventSize)
	}
	pos += 4

	specId := string(evlBuffer[pos : pos+int(eventSize)])
	if !strings.HasPrefix(specId, specIdEvent03) {
		return 0, errors.Errorf("The event log header did not contain 'Spec ID Event03'")
	}
	pos += int(eventSize)

	return pos, nil
}
