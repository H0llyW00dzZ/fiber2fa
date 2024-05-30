// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package twofa

import (
	"fmt"
	"time"
)

// InfoManager defines the interface for managing 2FA information.
type InfoManager interface {
	GetSecret() string
	GetCookieValue() string
	GetExpirationTime() time.Time
	IsRegistered() bool
	GetIdentifier() string
	GetQRCodeData() []byte
	SetSecret(secret string)
	SetCookieValue(value string)
	SetExpirationTime(expiration time.Time)
	SetContextKey(contextKey string)
	SetRegistered(registered bool)
	SetIdentifier(identifier string)
	SetQRCodeData(data []byte)
}

// Info represents the 2FA information stored for a user.
type Info struct {
	ContextKey     string    `json:"contextkey,omitempty"`
	Secret         string    `json:"secret"`
	CookieValue    string    `json:"cookie,omitempty"`
	ExpirationTime time.Time `json:"expiration,omitempty"`
	Registered     bool      `json:"registered"`
	Identifier     string    `json:"identifier,omitempty"`
	QRCodeData     []byte    `json:"qrcodedata,omitempty"`
}

// NewInfo creates a new empty Info struct based on the provided Config.
func NewInfo(cfg *Config) *Info {
	return &Info{
		ContextKey:     "",
		Secret:         cfg.Secret,
		CookieValue:    "",
		ExpirationTime: time.Time{},
		Registered:     false,
		Identifier:     "",
		QRCodeData:     nil,
	}
}

// GetSecret returns the secret for 2FA.
func (i *Info) GetSecret() string {
	return i.Secret
}

// GetCookieValue returns the cookie value.
func (i *Info) GetCookieValue() string {
	return i.CookieValue
}

// GetExpirationTime returns the cookie expiration time.
func (i *Info) GetExpirationTime() time.Time {
	return i.ExpirationTime
}

// IsRegistered returns the registration status.
func (i *Info) IsRegistered() bool {
	return i.Registered
}

// GetIdentifier returns the identifier.
func (i *Info) GetIdentifier() string {
	return i.Identifier
}

// GetQRCodeData returns the QRCode data.
func (i *Info) GetQRCodeData() []byte {
	return i.QRCodeData
}

// SetSecret sets the secret for 2FA.
func (i *Info) SetSecret(secret string) {
	i.Secret = secret
}

// SetCookieValue sets the cookie value.
func (i *Info) SetCookieValue(value string) {
	i.CookieValue = value
}

// SetExpirationTime sets the cookie expiration time.
func (i *Info) SetExpirationTime(expiration time.Time) {
	i.ExpirationTime = expiration
}

// SetContextKey sets the context key in the Info struct.
func (i *Info) SetContextKey(contextKey string) {
	i.ContextKey = contextKey
}

// SetRegistered sets the registration status.
func (i *Info) SetRegistered(registered bool) {
	i.Registered = registered
}

// SetIdentifier sets the identifier.
func (i *Info) SetIdentifier(identifier string) {
	i.Identifier = identifier
}

// SetQRCodeData sets the QRCode data.
func (i *Info) SetQRCodeData(data []byte) {
	i.QRCodeData = data
}

// getInfoFromStorage retrieves the 2FA information for the user from the storage.
func (m *Middleware) getInfoFromStorage(contextKey string) (*Info, error) {
	rawInfo, err := m.Config.Storage.Get(contextKey)
	if err != nil {
		return nil, ErrorFailedToRetrieveInfo
	}

	if rawInfo == nil {
		return nil, nil
	}

	var info Info
	if err := m.Config.JSONUnmarshal(rawInfo, &info); err != nil {
		return nil, ErrorFailedToUnmarshalInfo
	}

	return &info, nil
}

// updateInfoInStorage updates the Info struct in the storage.
func (m *Middleware) updateInfoInStorage(contextKey string) error {
	updatedRawInfo, err := m.Config.JSONMarshal(m.Info)
	if err != nil {
		return ErrorFailedToMarshalInfo
	}

	var expiration time.Duration
	if m.Config.StorageExpiration > 0 {
		expiration = m.Config.StorageExpiration
	}

	err = m.Config.Storage.Set(contextKey, updatedRawInfo, expiration)
	if err != nil {
		return ErrorFailedToStoreInfo
	}

	return nil
}

// deleteInfoFromStorage deletes the 2FA information for the user from the storage.
func (m *Middleware) deleteInfoFromStorage(contextKey string) error {
	err := m.Config.Storage.Delete(contextKey)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrorFailedToDeleteInfo, err)
	}

	return nil
}

// resetStorage resets the storage and deletes all keys.
func (m *Middleware) resetStorage() error {
	err := m.Config.Storage.Reset()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrorFailedToResetStorage, err)
	}

	return nil
}

// closeStorage closes the storage and stops any running garbage collectors and open connections.
func (m *Middleware) closeStorage() error {
	err := m.Config.Storage.Close()
	if err != nil {
		return ErrorFailedToCloseStorage
	}

	return nil
}
