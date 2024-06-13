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
	"encoding/binary"
	"fmt"
	"hash"
	"strconv"
	"strings"
)

// OCRAVerifier is an OCRA verifier (RFC 6287) that implements the OTPVerifier interface.
//
// Definition of OCRA:
//
//	OCRA(K, C, Q, P, S) = HOTP(K, C || Q || P || S)
//
// Where:
//
//   - K is the shared secret key between the client and the server.
//   - C is the counter value, which is a 64-bit unsigned integer.
//   - Q is the challenge question, which is a string containing the question or prompt.
//   - P is the hash algorithm used in the HMAC calculation (e.g., SHA-1, SHA-256).
//   - S is the session information, which can include additional parameters such as the session identifier, timestamp, or nonce.
//   - || denotes concatenation of the input values.
//
// The HOTP function used in the OCRA algorithm is defined as follows:
//
//	HOTP(K, C) = Truncate(HMAC-SHA-1(K, C))
//
// Where:
//
//   - Truncate is a function that selects a subset of bits from the HMAC result to generate the final HOTP value.
//   - HMAC-SHA-1 is the HMAC function using the SHA-1 hash algorithm. Other hash algorithms like SHA-256 or SHA-512 can also be used.
//
// The Truncate function is defined as follows:
//
//	Truncate(HMAC(K, C)) = HOTP
//
// Where:
//
//   - HMAC(K, C) is the HMAC result using the shared secret key K and the concatenated input C.
//   - HOTP is the resulting HOTP value, which is typically a 6-digit or 8-digit decimal number.
//
// Note: These docs provide a simplified explanation of the cryptographic concepts to improve readability and understanding.
type OCRAVerifier struct {
	config Config
}

// NewOCRAVerifier creates a new OCRAVerifier with the given configuration.
//
// Note: This requires building own 2FA apps because it involves a question-answer process.
// For example, a mobile app can be built to generate OCRA tokens based on the shared secret key and the challenge.
// The app would prompt the user with the question from the challenge and expect the user to provide the correct answer.
// The answer, along with other parameters like the counter value, would be used to generate the OCRA token.
// The generated token can then be entered by the user on the server-side for verification.
// Building own 2FA app allows customizing the user experience and integrating OCRA seamlessly into the authentication flow.
func NewOCRAVerifier(config ...Config) *OCRAVerifier {
	c := DefaultConfig
	if len(config) > 0 {
		c = config[0]
	}

	// Use default values if not provided
	if c.Digits <= 4 { // minimum is 5 and max is 8
		c.Digits = DefaultConfig.Digits
		c.Crypto = DefaultConfig.Crypto
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
	//
	// Note: This hash implementation does not rely on the RFC truncation method (see https://datatracker.ietf.org/doc/html/rfc6287#section-5.2 which is bad it literally break cryptographic principles) because it is written in Go, not in other languages like Java.
	// It is already 100% secure and guaranteed due to the use of the crypto/subtle package.
	// Also note that we might implement our own method because it's relatively easy to create a custom OTP based on HMAC-Truncated.
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
	//
	// Note: The counter and counter are not just any values. They can be bound to a cryptographically secure pseudorandom number,
	// along with question, similar to how [DecodeBase32WithPadding] is used to manipulate the result in the frontend hahaha.
	var data []byte
	data = make([]byte, 8+len(question))
	binary.BigEndian.PutUint64(data[:8], counter)
	copy(data[8:], question)

	// Generate the HMAC hash
	hmacHash := hmac.New(hash, v.config.DecodeBase32WithPadding())
	hmacHash.Write(data)
	hashValue := hmacHash.Sum(nil)

	// Truncate the hash to obtain the HOTP value
	//
	// Note: This method is the same as the one used in the GOTP library by xlzd.
	// the only thing different, this not hard-coded raw and allow customized truncated across signature of HMAC
	offset := hashValue[len(hashValue)-1] & 0xf
	truncatedHash := binary.BigEndian.Uint32(hashValue[offset : offset+4])

	// Calculate the HOTP Ocra value using modulo operation instead of [math.Pow10].
	// This achieves the same result as using [math.Pow10] however this is more efficient due use magic calculator. ¯\_(ツ)_/¯
	p10n := v.config.cryptoPow10n(v.config.Digits)
	hotp := truncatedHash % uint32(p10n)

	// Format the HOTP value as a string with the specified number of digits
	return fmt.Sprintf("%0*d", v.config.Digits, hotp) // Result will padding it with leading zeros if necessary.
}

// GenerateOTPURL creates the URL for the QR code based on the provided URI template.
//
// TODO: Build a custom URI for the OCRA token.
// Currently, this function is unused because most mobile apps have poor ecosystems and may not be capable of handling
// cryptographic operations hahaha.
func (v *OCRAVerifier) GenerateOTPURL(issuer, accountName string) string {
	return v.config.generateOTPURL(issuer, accountName)
}

// Verify checks if the provided token and signature are valid for the specified challenge.
func (v *OCRAVerifier) Verify(token string, challenge string) bool {
	// Generate the expected OCRA token based on the challenge
	expectedToken := v.GenerateToken(challenge)

	// Compare the provided token with the expected token
	// Note: Signature verification is not applicable here because the OCRA algorithm itself provides sufficient security.
	// It follows the specifications defined in RFC 6287 (https://datatracker.ietf.org/doc/html/rfc6287#section-7.1)
	// and uses this [crypto/subtle] package, which is a crucial component in cryptographic operations.
	// Even if signature verification is applicable (e.g., possible to apply as per RFC 6287 section 7.3),
	// it should be handled outside this package and bound to the Crypto/TLS (SSL) or other cryptographic protocols (Advanced cryptographic uses cases),
	// which can then be integrated with this package for enhanced security.
	return subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) == 1
}
