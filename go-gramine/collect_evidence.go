/*
 *   Copyright (c) 2023 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package gramine

import (
	"crypto/sha256"
	"os"

	"github.com/intel/trustauthority-client/go-connector"
	"github.com/pkg/errors"
)

const (
	QuoteFile          = "/dev/attestation/quote"
	UserReportDataFile = "/dev/attestation/user_report_data"
	QuoteSizeMax       = 8192
)

func (adapter *gramineAdapter) CollectEvidence(nonce []byte) (*connector.Evidence, error) {

	hash := sha256.New()
	_, err := hash.Write(nonce)
	if err != nil {
		return nil, err
	}
	_, err = hash.Write(adapter.uData)
	if err != nil {
		return nil, err
	}
	reportData := hash.Sum(nil)

	userReportDataFile, err := os.OpenFile(UserReportDataFile, os.O_WRONLY, 0)
	if err != nil {
		return nil, errors.Wrapf(err, "Error while opening file %s", UserReportDataFile)
	}
	defer func() {
		err = userReportDataFile.Close()
		if err != nil {
			errors.Errorf("Error closing file %s", UserReportDataFile)
		}
	}()

	_, err = userReportDataFile.Write(reportData)
	if err != nil {
		return nil, errors.Wrapf(err, "Error while writing reportdata to file %s", UserReportDataFile)
	}

	quoteFile, err := os.Open(QuoteFile)
	if err != nil {
		return nil, errors.Wrapf(err, "Error while opening file %s", QuoteFile)
	}
	defer func() {
		err = quoteFile.Close()
		if err != nil {
			errors.Errorf("Error closing file %s", QuoteFile)
		}
	}()

	quote := make([]byte, QuoteSizeMax)
	quoteSize, err := quoteFile.Read(quote)
	if err != nil {
		return nil, errors.Wrapf(err, "Error while reading quote from file %s", QuoteFile)
	}

	return &connector.Evidence{
		Type:     0,
		Evidence: quote[:quoteSize],
		UserData: adapter.uData,
	}, nil
}
