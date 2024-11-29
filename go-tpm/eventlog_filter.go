/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package tpm

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"strings"

	"github.com/pkg/errors"
)

// tuple used for looking up PCR and hash algorithm selections.
type pcrTuple struct {
	pcr  int
	hash crypto.Hash
}

var (

	// The minimim event size in a log's header event.
	minHeaderEventSize = min(len(startupLocality), len(specIdEvent03))

	// The maximum event size in a log's header event (TCG_EfiSpecIDEvent structure
	// with max of 4 TCG_EfiSpecIdEventAlgorithmSize)
	maxHeaderEventSize = 16 + 4 + 1 + 1 + 1 + 1 + 4 + (4 * 4) + 1 + 0xFF
)

// eventLogFilter filters TCG event logs to only include the PCRs and hashes selected
// by the user.  The goal of this filtering is to 1.) reduce the oversize of logs transmitted
// to the ITA server and 2.) to allow customers to avoid event-log replay errors caused by PCR
// brittleness (ex. they can exclude problematic PCRs that may fail verification on the ITA
// server).
//
// The event log is populated by the UEFI firmware and is configured in the BIOS to enable/disable
// different PCR banks.  For example, the user may update their BIOS to only enable sha1 pcrs,
// use a combination (ex. sha1 and sha256) or enable all pcrs (sha1,sha256,sha384,sha512).
//
// The following table describes the expected results for different pcr selections:
//
// UEFI Enabled PCRs	Selected PCRs	Expected Results
// -----------------	-------------	----------------
// sha1					sha1:all		UEFI events is the same as filtered events.
// sha1					sha1:1,3,7		Event-log is filtered to only include pcr1, pcr3, and pcr7.
// sha1					sha256:all		Empty (filtered events only includes spec03 event).
// sha1,sha256			sha256:1,3,7	Event-og is filtered to only include pcr1, pcr3, and pcr7 (no sha1 digests).
type eventLogFilter interface {
	FilterEventLogs() ([]byte, error)
}

// newEventLogFilter parses the initial bytes of the event log to determine which
// type of event log filter to create.
func newEventLogFilter(evlBuffer []byte, pcrSelections ...PcrSelection) (eventLogFilter, error) {
	// Create a map of selected pcr indices to the list of hash selected algorithms.
	// Used to determine which event data should be included in the results.
	pcrFilterLookup := make(map[int][]crypto.Hash)
	for _, sel := range pcrSelections {
		for _, pcr := range sel.Pcrs {
			if _, ok := pcrFilterLookup[pcr]; !ok {
				pcrFilterLookup[pcr] = []crypto.Hash{}
			}

			pcrFilterLookup[pcr] = append(pcrFilterLookup[pcr], sel.Hash)
		}
	}

	pos := 0

	// pcr index should be 0
	pcr := int32(binary.LittleEndian.Uint32(evlBuffer[pos : pos+4]))
	if pcr != 0 {
		return nil, errors.New("The event log header did not start with PCR 0")
	}
	pos += 4

	// event type should be 3 (EV_NO_ACTION)
	eventType := int32(binary.LittleEndian.Uint32(evlBuffer[pos : pos+4]))
	if eventType != 3 {
		return nil, errors.New("The event log header did not have event type 3")
	}
	pos += 4

	pos += 20 // header digest

	eventSize := int(binary.LittleEndian.Uint32(evlBuffer[pos : pos+4]))
	if eventSize < minHeaderEventSize || eventSize > maxHeaderEventSize {
		return nil, errors.Errorf("The event log header had an correct event size %d", eventSize)
	}
	pos += 4

	eventString := string(evlBuffer[pos : pos+minHeaderEventSize])
	pos += eventSize
	if strings.HasPrefix(eventString, specIdEvent03) {
		return &tcg20EventLogFilterImpl{
			start:           pos,
			evlBuffer:       evlBuffer,
			pcrFilterLookup: pcrFilterLookup,
		}, nil
	} else if strings.HasPrefix(eventString, startupLocality) {
		return &tcg12EventLogFilterImpl{
			start:           pos,
			evlBuffer:       evlBuffer,
			pcrFilterLookup: pcrFilterLookup,
		}, nil
	} else {
		return nil, errors.Errorf("The event log header did not contain %q or %q", specIdEvent03, startupLocality)
	}
}

// This filter implementation linearly parses the TCG 2.0 ("crypto agile log format") event
// data that contains various digest types/length (see Figure 15 in the TCG PC Client
// Platform Firmware Profile).
type tcg20EventLogFilterImpl struct {
	start           int
	evlBuffer       []byte
	pcrFilterLookup map[int][]crypto.Hash
}

func (t *tcg20EventLogFilterImpl) FilterEventLogs() ([]byte, error) {
	var results bytes.Buffer

	// preallocate 40k for  event logs
	results.Grow(40960)

	// write the header as it is needed by the verifier
	_, err := results.Write(t.evlBuffer[0:t.start])
	if err != nil {
		return nil, err
	}

	// Loop through the fixed TCG_PCR_EVENT2 event log entries and create
	// the resulting output buffer.
	//
	// See section 10.2.2 of the TCG PC Client Platform Firmware Profile for more
	// information about the TCG_PCR_EVENT2 structure which has the following
	// format...
	//
	// FIELD             LEN
	// -------------     ---------------
	// PCR Index         4 bytes
	// Event Type        4 bytes
	// Digest Count      4 bytes
	//    Algorithm ID   2 bytes (for each digest)
	//    Digest Value   "Hash size from alg id" (for each digest)
	// Event Size        4 bytes
	// Event Data        "Event Size" bytes
	pos := t.start
	for true {
		if pos >= len(t.evlBuffer) {
			goto done
		}

		// pcr index
		pcr := int32(binary.LittleEndian.Uint32(t.evlBuffer[pos : pos+4]))
		if pcr < 0 || pcr > 23 {
			return nil, errors.Errorf("Event log contained invalid PCR index %d at offset %d", pcr, pos)
		}
		pos += 4

		// event type
		eventType := int32(binary.LittleEndian.Uint32(t.evlBuffer[pos : pos+4]))
		pos += 4

		// digest count
		digestCount := int32(binary.LittleEndian.Uint32(t.evlBuffer[pos : pos+4]))
		if digestCount < 0 || digestCount > 4 { // Assume less than 4 (sha1, sha256, sha384, sha512)
			return nil, errors.Errorf("Event log contained invalid digest count %d at offset %d", pcr, pos)
		}
		pos += 4

		// Create a map of hash algorithms to their offsets in the event log so
		// they can be added to the results.
		digestOffsets := make(map[crypto.Hash]int)
		for i := 0; i < int(digestCount); i++ {
			// algorithm id
			algId := int16(binary.LittleEndian.Uint16(t.evlBuffer[pos : pos+2]))
			pos += 2

			h, err := algIdToCryptoHash(algId)
			if err != nil {
				return nil, err
			}

			digestOffsets[h] = pos
			pos += h.Size()
		}

		// event size
		eventSize := int32(binary.LittleEndian.Uint32(t.evlBuffer[pos : pos+4]))
		if eventSize < 0 || eventSize > 1024*32 { // this can include secure boot certs and other large data (assume 32k max)
			return nil, errors.Errorf("Event log contained invalid event size  %d at offset %d", eventSize, pos)
		}
		pos += 4

		// skip pass event data
		eventStart := pos
		pos += int(eventSize)

		// Write the filtered event logs to the output buffer when the pcr/hash is in the
		// list of pcr selections.
		//
		// Assume the event log...
		// - Includes digests based on the PCR banks enabled in te BIOS (ex.
		//   if sha1 is enabled, then all events in the log will have a sha1 digest).
		//
		// Example...
		// pcr index of event is not in selection:  exclude
		// pcr index of event is in selection BUT does not match the selected digest algorithms:  exclude
		// pcr index of event is in selection AND has one or more matching, selected digest algorithms:  include
		if selectedHashAlgs, ok := t.pcrFilterLookup[int(pcr)]; ok {

			// exclude events where the PCR index is the selection, but its hash algorithm is not
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
			err = binary.Write(&results, binary.LittleEndian, uint32(pcr))
			if err != nil {
				return nil, err
			}

			// add event type
			err = binary.Write(&results, binary.LittleEndian, uint32(eventType))
			if err != nil {
				return nil, err
			}

			// add digest count (only include selected hash algorithms)
			err = binary.Write(&results, binary.LittleEndian, uint32(dCount))
			if err != nil {
				return nil, err
			}

			for _, hashAlg := range selectedHashAlgs {
				if _, ok := digestOffsets[hashAlg]; !ok {
					continue
				}

				// algorithm id
				algId, err := cryptoHash2AldId(hashAlg)
				if err != nil {
					return nil, err
				}

				// add algorithm id
				err = binary.Write(&results, binary.LittleEndian, uint16(algId))
				if err != nil {
					return nil, err
				}

				// add digest value
				_, err = results.Write(t.evlBuffer[digestOffsets[hashAlg] : digestOffsets[hashAlg]+hashAlg.Size()])
			}

			// add event size
			err = binary.Write(&results, binary.LittleEndian, uint32(eventSize))
			if err != nil {
				return nil, err
			}

			// add event data
			_, err = results.Write(t.evlBuffer[eventStart:pos])
			if err != nil {
				return nil, err
			}
		}
	}

done:
	return results.Bytes(), nil
}

// This filter implementation linearly parses the TCG 1.2 ("sha 1 log format") event
// data that contains fixed (sha1) digest types/length (see Figure 15 in the TCG PC Client
// Platform Firmware Profile).
type tcg12EventLogFilterImpl struct {
	start           int
	evlBuffer       []byte
	pcrFilterLookup map[int][]crypto.Hash
}

func (t *tcg12EventLogFilterImpl) FilterEventLogs() ([]byte, error) {
	var results bytes.Buffer

	// preallocate 40k for  event logs
	results.Grow(40960)

	// write the header as it is needed by the verifier
	_, err := results.Write(t.evlBuffer[0:t.start])
	if err != nil {
		return nil, err
	}

	// Loop through the fixed TCG_PCClientPCREvent event log entries and create
	// the resulting output buffer.
	//
	// See section 10.2.1 of the TCG PC Client Platform Firmware Profile for more
	// information about the TCG_PCClientPCREvent structure which has the following
	// format...
	//
	// FIELD             LEN
	// -------------     ---------------
	// PCR Index         4 bytes
	// Event Type        4 bytes
	// Digest            20 bytes (sha1)
	// Event Size        4 bytes
	// Event Data        "Event Size" bytes
	pos := t.start
	for true {
		if pos >= len(t.evlBuffer) {
			goto done
		}

		// pcr index
		pcr := int32(binary.LittleEndian.Uint32(t.evlBuffer[pos : pos+4]))
		if pcr < 0 || pcr > 23 {
			return nil, errors.Errorf("Event log contained invalid PCR index %d at offset %d", pcr, pos)
		}
		pos += 4

		// event type
		eventType := int32(binary.LittleEndian.Uint32(t.evlBuffer[pos : pos+4]))
		pos += 4

		digest := t.evlBuffer[pos : pos+20]
		pos += 20

		// event size
		eventSize := int(binary.LittleEndian.Uint32(t.evlBuffer[pos : pos+4]))
		if eventSize < 0 || eventSize > 1024*32 { // this can include secure boot certs and other large data (assume 32k max)
			return nil, errors.Errorf("Event log contained invalid event size  %d at offset %d", eventSize, pos)
		}
		pos += 4

		event := t.evlBuffer[pos : pos+eventSize]
		pos += eventSize

		// Write the filtered event logs to the output buffer when sha1 pcr index is
		// in the selection.
		if selectedHashAlgs, ok := t.pcrFilterLookup[int(pcr)]; ok {

			// Check if sha1 is in the selection
			sha1InSelection := false
			for _, hashAlg := range selectedHashAlgs {
				if hashAlg == crypto.SHA1 {
					sha1InSelection = true
					break
				}
			}
			if !sha1InSelection {
				continue
			}

			// add pcr index
			err = binary.Write(&results, binary.LittleEndian, uint32(pcr))
			if err != nil {
				return nil, err
			}

			// add event type
			err = binary.Write(&results, binary.LittleEndian, uint32(eventType))
			if err != nil {
				return nil, err
			}

			// add digest
			_, err = results.Write(digest)
			if err != nil {
				return nil, err
			}

			// add event size
			err = binary.Write(&results, binary.LittleEndian, uint32(eventSize))
			if err != nil {
				return nil, err
			}

			// add event data
			_, err = results.Write(event)
			if err != nil {
				return nil, err
			}
		}
	}

done:

	return results.Bytes(), nil
}

func algIdToCryptoHash(algId int16) (crypto.Hash, error) {
	switch algId {
	case 0x4:
		return crypto.SHA1, nil
	case 0xB:
		return crypto.SHA256, nil
	case 0xC:
		return crypto.SHA384, nil
	case 0xD:
		return crypto.SHA512, nil
	default:
		return 0, errors.Errorf("Invalid algorithm ID %d", algId)
	}
}

func cryptoHash2AldId(h crypto.Hash) (int16, error) {
	switch h {
	case crypto.SHA1:
		return 0x4, nil
	case crypto.SHA256:
		return 0xB, nil
	case crypto.SHA384:
		return 0xC, nil
	case crypto.SHA512:
		return 0xD, nil
	default:
		return 0, errors.Errorf("Invalid hash algorithm %v", h)
	}
}
