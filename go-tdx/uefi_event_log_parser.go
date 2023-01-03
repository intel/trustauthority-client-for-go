/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tdx

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// uefiEventLogParser manages TD eventlog collection from ACPI tables
type uefiEventLogParser struct {
	uefiTableFilePath    string
	uefiEventLogFilePath string
}

// GetEventLogs is used to get TD eventlog by reading through ACPI tables
func (parser *uefiEventLogParser) GetEventLogs() ([]RtmrEventLog, error) {

	tdelSig := make([]byte, Uint32Size)
	tdelLen := make([]byte, Uint32Size)
	uefiEventSize := make([]byte, Uint64Size)
	if _, err := os.Stat(parser.uefiTableFilePath); os.IsNotExist(err) {
		return nil, errors.Wrapf(err, "%s file does not exist", parser.uefiTableFilePath)
	}

	file, err := os.Open(parser.uefiTableFilePath)
	if err != nil {
		return nil, errors.Wrapf(err, "error opening %s", parser.uefiTableFilePath)
	}
	defer func() {
		derr := file.Close()
		if derr != nil {
			log.WithError(derr).Warnf("error closing %s", parser.uefiTableFilePath)
		}
	}()

	// Validate TDEL file signature
	_, err = io.ReadFull(file, tdelSig)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading TDEL Signature from %s", parser.uefiTableFilePath)
	}

	tdelSignature := string(tdelSig)
	if TdelSignature != tdelSignature {
		return nil, errors.Errorf("Invalid TDEL Signature in %s", parser.uefiTableFilePath)
	}

	// Validate TDEL file length
	_, err = io.ReadFull(file, tdelLen)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading TDEL File Length from %s", parser.uefiTableFilePath)
	}

	tdelFileLength := binary.LittleEndian.Uint32(tdelLen)
	if tdelFileLength < TdelFileLength {
		return nil, errors.Errorf("UEFI Event Info missing in %s", parser.uefiTableFilePath)
	}

	_, err = file.Seek(UefiSizeOffset, io.SeekStart)
	if err != nil {
		return nil, errors.Wrapf(err, "error seeking %s for UEFI Event Size Offset", parser.uefiTableFilePath)
	}

	_, err = io.ReadFull(file, uefiEventSize)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading UEFI Event Size from %s", parser.uefiTableFilePath)
	}

	uefiEventSizeLE := binary.LittleEndian.Uint32(uefiEventSize)

	uefiEventBuf, err := readUefiEvent(parser.uefiEventLogFilePath, uefiEventSizeLE)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading UEFI Event Log from %s", parser.uefiEventLogFilePath)
	}

	// Parse and skip TCG_PCR_EVENT(Intel TXT spec. ver. 16.2) from event-log buffer
	realUefiEventBuf, realUefiEventSize, err := parseTcgSpecEvent(uefiEventBuf, uefiEventSizeLE)
	if err != nil {
		return nil, errors.Wrap(err, "error while parsing UEFI Event Log Data")
	}

	var uefiEventLogs []RtmrEventLog
	uefiEventLogs, err = createEventLog(realUefiEventBuf, realUefiEventSize, uefiEventLogs)
	if err != nil {
		return nil, errors.Wrap(err, "error while creating event-log data for UEFI Events")
	}

	return uefiEventLogs, nil
}

// ReadUefiEvent - Function to read Uefi Event binary data from /sys/firmware/acpi/tables/data/TDEL
func readUefiEvent(uefiEventLogFilePath string, uefiEventSize uint32) (*bytes.Buffer, error) {

	eventLogBuffer := make([]byte, uefiEventSize)
	if _, err := os.Stat(uefiEventLogFilePath); os.IsNotExist(err) {
		return nil, errors.Wrapf(err, "%s file does not exist", uefiEventLogFilePath)
	}

	file, err := os.Open(uefiEventLogFilePath)
	if err != nil {
		return nil, errors.Wrapf(err, "error opening %s", uefiEventLogFilePath)
	}
	defer func() {
		derr := file.Close()
		if derr != nil {
			log.WithError(derr).Warnf("error closing %s", uefiEventLogFilePath)
		}
	}()

	_, err = io.ReadFull(file, eventLogBuffer)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading UEFI Event Log from %s", uefiEventLogFilePath)
	}

	buf := bytes.NewBuffer(eventLogBuffer)
	return buf, nil
}
