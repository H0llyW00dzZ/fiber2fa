// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package twofa

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2/utils"
)

// GenerateCookieValue generates a signed cookie value using HMAC.
//
// TODO: Implement an extra layer of cookie value (in addition to the current timestamp)
// and enhance security by using custom cryptography for encryption and decryption value.
// Use a user secret derived from 2FA for encryption/decryption and bind it to a UUID for identification purposes.
// This will replace the current implementation that uses HMAC.
func (m *Middleware) GenerateCookieValue(expirationTime time.Time) string {
	data := fmt.Sprintf("%d", expirationTime.Unix())
	hash := hmac.New(sha256.New, utils.CopyBytes([]byte(m.Config.Secret)))
	hash.Write(utils.CopyBytes([]byte(data)))
	signature := base64.RawURLEncoding.EncodeToString(utils.CopyBytes(hash.Sum(nil)))
	return fmt.Sprintf("%s.%s", utils.CopyString(data), signature)
}

// validateCookie validates the cookie value using HMAC.
func (m *Middleware) validateCookie(cookie string) bool {
	parts := strings.Split(cookie, ".")
	if len(parts) != 2 {
		return false
	}

	data := parts[0]
	signature := parts[1]

	hash := hmac.New(sha256.New, utils.CopyBytes([]byte(m.Config.Secret)))
	hash.Write(utils.CopyBytes([]byte(data)))
	expectedSignature := base64.RawURLEncoding.EncodeToString(hash.Sum(nil))

	if subtle.ConstantTimeCompare(utils.CopyBytes([]byte(signature)), utils.CopyBytes([]byte(expectedSignature))) != 1 {
		return false
	}

	expirationTime, err := strconv.ParseInt(data, 10, 64)
	if err != nil {
		return false
	}

	return time.Now().Unix() <= expirationTime
}
