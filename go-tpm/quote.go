/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package tpm

import (
	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func (tpm *trustedPlatformModule) GetQuote(akHandle int, nonce []byte, selection ...PcrSelection) ([]byte, []byte, error) {
	logrus.Debugf("Collecting TPM quote using AK handle 0x%x", akHandle)

	// make sure the akHandle is a valid persistant handle and it DOES NOT exist
	ak := tpm2.Handle(akHandle)
	if ak.Type() != tpm2.HandleTypePersistent {
		return nil, nil, ErrInvalidHandle
	}

	if !tpm.ctx.DoesHandleExist(ak) {
		return nil, nil, ErrHandleDoesNotExist
	}

	akContext, err := tpm.ctx.NewResourceContext(ak)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "Failed to create resource context for handle 0x%x", akHandle)
	}
	akContext.SetAuthValue(tpm.ownerAuth)

	pcrSelection, err := toTpm2PcrSelectionList(selection...)
	if err != nil {
		return nil, nil, err
	}

	quoted, signature, err := tpm.ctx.Quote(akContext, tpm2.Data(nonce), nil, pcrSelection, nil)
	if err != nil {
		return nil, nil, err
	}

	quoteBytes, err := mu.MarshalToBytes(quoted)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Failed to marshal quote")
	}

	signatureBytes, err := mu.MarshalToBytes(signature)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Failed to marshal signature")
	}

	return quoteBytes, signatureBytes, nil
}
