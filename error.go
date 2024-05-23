// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package twofa

import "errors"

// Global error variables
var (
	ErrorFailedToRetrieveInfo       = errors.New("failed to retrieve 2FA information")
	ErrorFailedToUnmarshalInfo      = errors.New("failed to unmarshal 2FA information")
	ErrorFailedToMarshalInfo        = errors.New("failed to marshal updated 2FA information")
	ErrorFailedToStoreInfo          = errors.New("failed to store updated 2FA information")
	ErrorFailedToDeleteInfo         = errors.New("failed to delete 2FA information")
	ErrorFailedToResetStorage       = errors.New("failed to reset storage")
	ErrorFailedToCloseStorage       = errors.New("failed to close storage")
	ErrorContextKeyNotSet           = errors.New("ContextKey is not set")
	ErrorFailedToRetrieveContextKey = errors.New("failed to retrieve context key")
)
