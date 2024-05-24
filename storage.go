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
	SetSecret(secret string)
	SetCookieValue(value string)
	SetExpirationTime(expiration time.Time)
	SetContextKey(contextKey string)
}

// Info represents the 2FA information stored for a user.
type Info struct {
	ContextKey     string    `json:"context_key"`
	Secret         string    `json:"secret"`
	CookieValue    string    `json:"cookie_value"`
	ExpirationTime time.Time `json:"expiration_time"`
}

// NewInfo creates a new empty Info struct based on the provided Config.
func NewInfo(cfg *Config) *Info {
	return &Info{
		ContextKey:     cfg.ContextKey,
		Secret:         cfg.Secret,
		CookieValue:    "",
		ExpirationTime: time.Time{},
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

	err = m.Config.Storage.Set(contextKey, updatedRawInfo, time.Duration(m.Config.CookieMaxAge)*time.Second)
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
