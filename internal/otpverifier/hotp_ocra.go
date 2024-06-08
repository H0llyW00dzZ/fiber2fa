// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package otpverifier

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"strconv"
	"strings"
)

// OCRAVerifier is an OCRA verifier (RFC 6287) that implements the OTPVerifier interface.
type OCRAVerifier struct {
	config Config
}

// NewOCRAVerifier creates a new OCRAVerifier with the given configuration.
func NewOCRAVerifier(config ...Config) *OCRAVerifier {
	c := DefaultConfig
	if len(config) > 0 {
		c = config[0]
	}

	// Use default values if not provided
	if c.Digits == 0 {
		c.Digits = DefaultConfig.Digits
	}
	if c.URITemplate == "" {
		c.URITemplate = DefaultConfig.URITemplate
	}

	return &OCRAVerifier{
		config: c,
	}
}

// GenerateToken generates an OCRA token based on the provided challenge.
func (v *OCRAVerifier) GenerateToken(challenge string) string {
	// Assume the following challenge string format: "OCRA-1:HOTP-<hash>-<digits>:<parameters>-<counter>-<question>"
	parts := strings.Split(challenge, ":")
	if len(parts) != 3 {
		panic("Invalid challenge format")
	}

	// Extract the relevant parts from the challenge
	ocraSuite := parts[0] + ":" + parts[1]
	remainingParts := strings.Split(parts[2], "-")
	if len(remainingParts) < 3 {
		panic("Invalid challenge format")
	}

	counter, err := strconv.ParseUint(remainingParts[1], 10, 64)
	if err != nil {
		panic("Invalid counter value: " + err.Error())
	}
	question := remainingParts[2]

	// Further checks on the OCRA suite format (if necessary)
	suiteComponents := strings.Split(ocraSuite, ":")
	if len(suiteComponents) != 2 || suiteComponents[0] != "OCRA-1" {
		panic("Unsupported OCRA suite")
	}

	// Determine the hash algorithm based on the OCRA suite
	//
	// TODO: use constant
	var hash func() hash.Hash
	switch {
	case strings.HasPrefix(suiteComponents[1], "HOTP-SHA1"):
		hash = sha1.New
	case strings.HasPrefix(suiteComponents[1], "HOTP-SHA256"):
		hash = sha256.New
	case strings.HasPrefix(suiteComponents[1], "HOTP-SHA512"):
		hash = sha512.New
	default:
		panic("Unsupported hash algorithm")
	}

	// Generate the OCRA token based on the OCRA suite
	return v.generateOCRA(counter, question, hash)
}

// generateOCRA generates an OCRA token using the specified hash algorithm.
func (v *OCRAVerifier) generateOCRA(counter uint64, question string, hash func() hash.Hash) string {
	// Prepare the input data
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, counter)
	questionBytes := []byte(question)

	// Concatenate the input data
	data := append(counterBytes, questionBytes...)

	// Generate the HMAC hash
	secret, _ := base32.StdEncoding.DecodeString(v.config.Secret)
	hmacHash := hmac.New(hash, secret)
	hmacHash.Write(data)
	hashValue := hmacHash.Sum(nil)

	// Truncate the hash to obtain the HOTP value
	//
	// Note: This method is the same as the one used in the GOTP library by xlzd.
	offset := hashValue[len(hashValue)-1] & 0xf
	truncatedHash := binary.BigEndian.Uint32(hashValue[offset : offset+4])
	hotp := truncatedHash % uint32(math.Pow10(v.config.Digits))

	// Format the HOTP value as a string with the specified number of digits
	return fmt.Sprintf(fmt.Sprintf("%%0%dd", v.config.Digits), hotp)
}

// GenerateOTPURL creates the URL for the QR code based on the provided URI template.
func (v *OCRAVerifier) GenerateOTPURL(issuer, accountName string) string {
	return v.config.generateOTPURL(issuer, accountName)
}

// Verify checks if the provided token and signature are valid for the specified challenge.
func (v *OCRAVerifier) Verify(token string, challenge string, signature ...string) bool {
	// Generate the expected OCRA token based on the challenge
	expectedToken := v.GenerateToken(challenge)

	// Compare the provided token with the expected token
	if subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) == 1 {
		return true
	}

	return false
}
