/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tdx

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// EventLogParser - Public interface for collecting eventlog data
type EventLogParser interface {
	GetEventLogs() ([]RtmrEventLog, error)
}

// NewEventLogParser returns an instance of EventLogParser
func NewEventLogParser() EventLogParser {

	// If the Application has been compiled with a different 'uefiEventLogFile'
	// use that to create the event-logs.  Otherwise, fall back to parsing
	// /sys/firmware (default)
	var uefiParser EventLogParser
	if uefiEventLogFile != "" {
		log.Infof("Configured to use UEFI event log file %q", uefiEventLogFile)
		uefiParser = &fileEventLogParser{file: uefiEventLogFile}
	} else {
		uefiParser = &uefiEventLogParser{
			uefiTableFilePath:    TdelPath,
			uefiEventLogFilePath: TdelDataPath,
		}
	}
	return uefiParser
}

// ParseTcgSpecEvent - Function to parse and Skip TCG_PCR_EVENT(Intel TXT spec. ver. 16.2) from Event Log Data
func parseTcgSpecEvent(buf *bytes.Buffer, size uint32) (*bytes.Buffer, uint32, error) {

	tcgPcrEvent := tcgPcrEventV1{}
	err := binary.Read(buf, binary.LittleEndian, &tcgPcrEvent.PcrIndex)
	if err != nil {
		return nil, 0, errors.Wrap(err, "error reading TCG_PCR_EVENT PCR Index from Event Log buffer")
	}

	err = binary.Read(buf, binary.LittleEndian, &tcgPcrEvent.EventType)
	if err != nil {
		return nil, 0, errors.Wrap(err, "error reading TCG_PCR_EVENT Event Type from Event Log buffer")
	}

	err = binary.Read(buf, binary.LittleEndian, &tcgPcrEvent.Digest)
	if err != nil {
		return nil, 0, errors.Wrap(err, "error reading TCG_PCR_EVENT Digest from Event Log buffer")
	}

	err = binary.Read(buf, binary.LittleEndian, &tcgPcrEvent.EventSize)
	if err != nil {
		return nil, 0, errors.Wrap(err, "error reading TCG_PCR_EVENT Event Size from Event Log buffer")
	}

	tcgPcrEvent.Event = buf.Next(int(tcgPcrEvent.EventSize))
	return buf, size - (tcgPcrEvent.EventSize + 32), nil
}

// createEventLog - Function to create RTMR Event log data
func createEventLog(buf *bytes.Buffer, size uint32, rtmrEventLogs []RtmrEventLog) ([]RtmrEventLog, error) {

	tcgPcrEvent2 := tcgPcrEventV2{}
	tpmlDigestValues := tpmlDigestValue{}
	var offset int64
	var err error
	for offset = 0; offset < int64(size); {
		err = binary.Read(buf, binary.LittleEndian, &tcgPcrEvent2.PcrIndex)
		if err != nil {
			return nil, errors.Wrap(err, "error reading TCG_PCR_EVENT2 PCR Index from Event Log buffer")
		}

		offset = offset + Uint32Size
		if tcgPcrEvent2.PcrIndex > 4 || tcgPcrEvent2.PcrIndex < 1 {
			break
		}

		err = binary.Read(buf, binary.LittleEndian, &tcgPcrEvent2.EventType)
		if err != nil {
			return nil, errors.Wrap(err, "error reading TCG_PCR_EVENT2 Event Type from Event Log buffer")
		}

		offset = offset + Uint32Size
		eventTypeStr := fmt.Sprintf("0x%x", tcgPcrEvent2.EventType)
		err = binary.Read(buf, binary.LittleEndian, &tpmlDigestValues.Count)
		if err != nil {
			return nil, errors.Wrap(err, "error reading TCG_PCR_EVENT2 Digest Count from Event Log buffer")
		}

		offset = offset + Uint32Size
		// From Tpm2.0 spec: https://dox.ipxe.org/Tpm20_8h_source.html#l01081
		// It supports only 5 types of digest algorithm
		if tpmlDigestValues.Count <= 0 || tpmlDigestValues.Count > 5 {
			break
		}

		var hashIndex int
		eventData := make([]RtmrEvent, tpmlDigestValues.Count)
		rtmr := make([]RtmrData, tpmlDigestValues.Count)
		for hashIndex = 0; hashIndex < int(tpmlDigestValues.Count); hashIndex++ {
			var digestSize int
			var algID uint16
			err = binary.Read(buf, binary.LittleEndian, &algID)
			if err != nil {
				return nil, errors.Wrap(err, "error reading TCG_PCR_EVENT2 Algorithm ID from Event Log buffer")
			}

			offset = offset + Uint16Size
			switch algID {
			case AlgSHA256:
				eventData[hashIndex].Measurement, offset, buf = getHashData(offset, sha256.Size, buf)
				rtmr[hashIndex].Bank = SHA256
			case AlgSHA384:
				digestSize = 48
				eventData[hashIndex].Measurement, offset, buf = getHashData(offset, digestSize, buf)
				rtmr[hashIndex].Bank = SHA384
			case AlgSHA512:
				eventData[hashIndex].Measurement, offset, buf = getHashData(offset, sha512.Size, buf)
				rtmr[hashIndex].Bank = SHA512
			case AlgSM3_256:
				digestSize = 32
				eventData[hashIndex].Measurement, offset, buf = getHashData(offset, digestSize, buf)
				rtmr[hashIndex].Bank = SM3_256
			default:
				return nil, errors.Errorf("Invalid SHA algorithm id '%d'", algID)
			}

			eventData[hashIndex].TypeID = eventTypeStr
			rtmr[hashIndex].Index = tcgPcrEvent2.PcrIndex
			// Map Event name against the specified types from the TCG PC Client Platform Firmware Profile Specification v1.5
			eventName, ok := eventNameList[tcgPcrEvent2.EventType]
			if ok {
				eventData[hashIndex].TypeName = eventName
			}

			// After parsing of TPML_DIGEST_VALUES form (Intel TXT spec. ver. 16.2) increment the offset to read the next TCG_PCR_EVENT2
			if hashIndex+1 == int(tpmlDigestValues.Count) {
				err = binary.Read(buf, binary.LittleEndian, &tcgPcrEvent2.EventSize)
				if err != nil {
					return nil, errors.Wrap(err, "error reading TCG_PCR_EVENT2 Event Size from Event Log buffer")
				}

				offset = offset + Uint32Size
				tcgPcrEvent2.Event = buf.Next(int(tcgPcrEvent2.EventSize))
				offset = offset + int64(tcgPcrEvent2.EventSize)
				// Adding eventlog data according to RtmrEventLog
				for index := 0; index < int(tpmlDigestValues.Count); index++ {
					var tempRtmrEventLog RtmrEventLog
					// Handling of Uefi Event Tag according to TCG PC Client Platform Firmware Profile Specification v1.5
					eventData[index].Tags, err = getEventTag(tcgPcrEvent2.EventType, tcgPcrEvent2.Event, tcgPcrEvent2.EventSize, tcgPcrEvent2.PcrIndex)
					if err != nil {
						log.WithError(err).Warnf("error in getting Event Tag. PcrIndex = %x, EventType = %x", tcgPcrEvent2.PcrIndex, tcgPcrEvent2.EventType)
					}
					var cleanTags []string
					for _, tag := range eventData[index].Tags {
						cleanTags = append(cleanTags, removeUnicode(tag))
					}
					eventData[index].Tags = cleanTags

					tempRtmrEventLog.Rtmr = rtmr[index]
					tempRtmrEventLog.RtmrEvents = append(tempRtmrEventLog.RtmrEvents, eventData[index])
					if len(rtmrEventLogs) == 0 {
						rtmrEventLogs = append(rtmrEventLogs, tempRtmrEventLog)
					} else {
						var flag int = 0
						for i := range rtmrEventLogs {
							// Check rtmr index and bank if already existing in current array and then add eventlog data in array
							if (rtmrEventLogs[i].Rtmr.Index == rtmr[index].Index) && (rtmrEventLogs[i].Rtmr.Bank == rtmr[index].Bank) {
								rtmrEventLogs[i].RtmrEvents = append(rtmrEventLogs[i].RtmrEvents, eventData[index])
								flag = 1
								break
							}
						}

						if flag == 0 {
							rtmrEventLogs = append(rtmrEventLogs, tempRtmrEventLog)
						}
					}
				}
			}
		}
	}

	return rtmrEventLogs, nil
}

// removeUnicode - Function to remove unicode characters from string
func removeUnicode(input string) string {
	cleanInput := strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, input)
	return cleanInput
}

// GetHashData - Returns string of hash data, the incremented offset and buffer
func getHashData(offset int64, digestSize int, buf *bytes.Buffer) (string, int64, *bytes.Buffer) {

	digest := buf.Next(digestSize)
	offset = offset + int64(digestSize)
	digestStr := hex.EncodeToString(digest)
	return digestStr, offset, buf
}

// GetEventTag - Function to get tag for uefi events
func getEventTag(eventType uint32, eventData []byte, eventSize uint32, pcrIndex uint32) ([]string, error) {

	// Handling EV_EFI_VARIABLE_DRIVER_CONFIG, EV_EFI_VARIABLE_BOOT, EV_EFI_VARIABLE_BOOT2 and EV_EFI_VARIABLE_AUTHORITY as all
	// These events are associated with UEFI_VARIABLE_DATA
	var err error
	if eventType == Event80000001 || eventType == Event80000002 || eventType == Event8000000C || eventType == Event800000E0 {
		var uefiVarData uefiVariableData
		var unicodeName []byte
		var index, index1 int
		buf := bytes.NewBuffer(eventData)
		err = binary.Read(buf, binary.LittleEndian, &uefiVarData.VariableName)
		if err != nil {
			return nil, errors.Wrap(err, "error reading Variable Name from TCG_PCR_EVENT2 buffer")
		}

		err = binary.Read(buf, binary.LittleEndian, &uefiVarData.UnicodeNameLength)
		if err != nil {
			return nil, errors.Wrap(err, "error reading UnicodeName Length from TCG_PCR_EVENT2 buffer")
		}

		err = binary.Read(buf, binary.LittleEndian, &uefiVarData.VariableDataLength)
		if err != nil {
			return nil, errors.Wrap(err, "error reading VariableData Length from TCG_PCR_EVENT2 buffer")
		}

		// Check whether garbage data is filled in place of event data
		if (uefiVarData.UnicodeNameLength + uefiVarData.VariableDataLength) > uint64(eventSize-32) {
			return nil, errors.Wrap(err, "Garbage data is filled in place of event data.")
		}

		unicodeName = buf.Next(int(uefiVarData.UnicodeNameLength * 2))
		runeChar := make([]rune, uefiVarData.UnicodeNameLength)
		for index = 0; index1 < int((uefiVarData.UnicodeNameLength * 2)); index++ {
			runeChar[index] = rune(unicodeName[index1])
			index1 = index1 + 2
		}

		return []string{string(runeChar)}, nil
	}

	//Handling EV_EFI_PLATFORM_FIRMWARE_BLOB2 as it is associated with UEFI_PLATFORM_FIRMWARE_BLOB2
	// 0x8000000B is EV_EFI_HANDOFF_TABLES2 but the description starts from second byte similar to UEFI_PLATFORM_FIRMWARE_BLOB2 so handling here.
	if eventType == Event8000000A || eventType == Event8000000B {
		var blobDescriptionSize uint8
		buf := bytes.NewBuffer(eventData)
		err = binary.Read(buf, binary.LittleEndian, &blobDescriptionSize)
		if err != nil {
			return nil, errors.Wrap(err, "error reading Blob Description Size from TCG_PCR_EVENT2 buffer")
		}

		blobDesc := buf.Next(int(blobDescriptionSize))
		tagName := string(blobDesc)
		return []string{tagName}, nil
	}

	// Handling EV_IPL, EV_POST_CODE, EV_ACTION, EV_EFI_ACTION, EV_PLATFORM_CONFIG_FLAGS, EV_COMPACT_HASH(Only when PCR6),
	// EV_OMIT_BOOT_DEVICE_EVENTS and EV_EFI_HCRTM_EVENT all these events as the event data is a String.
	//
	// EV_S_CRTM_CONTENTS also having descriptive string only in real time. But in spec it is mentioned that this
	// event will have UEFI_PLATFORM_FIRMWARE_BLOB2 data. To make this work handling here.
	//
	// EV_IPL is considered deprecated but captured by EFI in PCRs 8/9, recording grub commmand line arguments
	// and other information.  Add these as tags so they can be verified by "eventlog_includes" and "eventlog_equals"
	// flavor-template rules.
	if eventType == EV_IPL || eventType == Event00000001 || eventType == Event00000005 || eventType == Event80000007 || eventType == Event0000000A || (eventType == Event0000000C && pcrIndex == 0x6) || eventType == Event00000012 || eventType == Event80000010 || eventType == Event00000007 {
		buf := bytes.NewBuffer(eventData)
		postCode := buf.Next(int(eventSize))
		tagName := string(postCode)
		//In some cases Event data may have extra bytes along with descriptive string followed by null char. So need to display only the string till null char.
		if strings.Contains(tagName, NullUnicodePoint) {
			nullIndex := strings.Index(tagName, NullUnicodePoint)
			if nullIndex == 0 {
				return nil, nil
			}
			return []string{tagName[:nullIndex]}, nil
		}
		return []string{tagName}, nil
	}

	//Handling EV_NO_ACTION Event. If this Event has the event data as StartupLocality followed by 3, the tag should be "StartupLocality3"
	//Event data has StartupLocality followed by 0, then the tag should be "StartupLocality0"
	if eventType == Event00000003 {
		buf := bytes.NewBuffer(eventData)
		noAction := buf.Next(int(eventSize))
		tagName := string(noAction)
		//In some cases Event data may have extra bytes along with descriptive string followed by null char. So need to display only the string till null char.
		if strings.Contains(tagName, NullUnicodePoint) {
			nullIndex := strings.Index(tagName, NullUnicodePoint)
			if nullIndex == 0 {
				return nil, nil
			}
			tagName = fmt.Sprintf("%s%d", tagName[:nullIndex], tagName[nullIndex+1])
			return []string{tagName}, nil
		}
		return []string{tagName}, nil
	}

	return nil, nil
}
