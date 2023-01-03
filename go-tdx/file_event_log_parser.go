/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tdx

import (
	"bytes"
	"io/ioutil"

	"github.com/pkg/errors"
)

// fileEventLogParser manages TD eventlog collection from file
type fileEventLogParser struct {
	file string
}

// GetEventLogs is used to get TD eventlog by reading through file
func (parser *fileEventLogParser) GetEventLogs() ([]RtmrEventLog, error) {

	var eventLogs []RtmrEventLog
	b, err := ioutil.ReadFile(parser.file)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to read event log file %s", parser.file)
	}

	eventBuf := bytes.NewBuffer(b)
	// Parse and skip TCG_PCR_EVENT(Intel TXT spec. ver. 16.2) from event-log buffer
	realEventBuf, realEventSize, err := parseTcgSpecEvent(eventBuf, uint32(len(b)))
	if err != nil {
		return nil, errors.Wrap(err, "error while parsing UEFI event log data")
	}

	eventLogs, err = createEventLog(realEventBuf, realEventSize, eventLogs)
	if err != nil {
		return nil, errors.Wrap(err, "error while creating event-log data for UEFI Events")
	}
	return eventLogs, nil
}
