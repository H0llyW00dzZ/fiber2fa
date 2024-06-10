// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package otpverifier_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/H0llyW00dzZ/fiber2fa/internal/otpverifier"
	"github.com/xlzd/gotp"
)

func BenchmarkTOTPVerify(b *testing.B) {
	secret := gotp.RandomSecret(16)

	hashFunctions := []string{
		otpverifier.SHA1,
		otpverifier.SHA224,
		otpverifier.SHA256,
		otpverifier.SHA384,
		otpverifier.SHA512,
		otpverifier.SHA512S224,
		otpverifier.SHA512S256,
		otpverifier.BLAKE2b256,
		otpverifier.BLAKE2b384,
		otpverifier.BLAKE2b512,
		otpverifier.BLAKE3256,
		otpverifier.BLAKE3384,
		otpverifier.BLAKE3512,
	}

	for _, hashFunc := range hashFunctions {
		b.Run(hashFunc, func(b *testing.B) {
			config := otpverifier.Config{
				Secret:     secret,
				Hash:       hashFunc,
				TimeSource: time.Now,
			}
			verifier := otpverifier.NewTOTPVerifier(config)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Note: This now each token are different
				token := verifier.GenerateToken()
				verifier.Verify(token)
			}
		})

		b.Run(hashFunc+"_WithSignature", func(b *testing.B) {
			config := otpverifier.Config{
				Secret:       secret,
				SyncWindow:   1,
				Hash:         hashFunc,
				TimeSource:   time.Now,
				UseSignature: true,
			}
			verifier := otpverifier.NewTOTPVerifier(config)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Note: This now each token are different
				token, signature := verifier.GenerateTokenWithSignature()
				verifier.Verify(token, signature)
			}
		})
	}
}

func BenchmarkHOTPVerify(b *testing.B) {
	secret := gotp.RandomSecret(16)

	hashFunctions := []string{
		otpverifier.SHA1,
		otpverifier.SHA224,
		otpverifier.SHA256,
		otpverifier.SHA384,
		otpverifier.SHA512,
		otpverifier.SHA512S224,
		otpverifier.SHA512S256,
		otpverifier.BLAKE2b256,
		otpverifier.BLAKE2b384,
		otpverifier.BLAKE2b512,
		otpverifier.BLAKE3256,
		otpverifier.BLAKE3384,
		otpverifier.BLAKE3512,
	}

	for _, hashFunc := range hashFunctions {
		b.Run(hashFunc, func(b *testing.B) {
			config := otpverifier.Config{
				Secret:     secret,
				SyncWindow: 1,
				Hash:       hashFunc,
			}
			verifier := otpverifier.NewHOTPVerifier(config)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Note: This now each token are different
				token := verifier.GenerateToken()
				verifier.Verify(token)
			}
		})

		b.Run(hashFunc+"_WithSignature", func(b *testing.B) {
			config := otpverifier.Config{
				Secret:       secret,
				Hash:         hashFunc,
				SyncWindow:   1,
				UseSignature: true,
			}
			verifier := otpverifier.NewHOTPVerifier(config)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Note: This now each token are different
				token, signature := verifier.GenerateTokenWithSignature()
				verifier.Verify(token, signature)
			}
		})
	}
}

func BenchmarkGenerateSecureRandomCounter(b *testing.B) {
	config := otpverifier.Config{
		Crypto: otpverifier.DefaultConfig.Crypto,
	}

	maxDigits := []int{6, 8, 30}

	for _, digits := range maxDigits {
		b.Run(fmt.Sprintf("MaxDigits_%d", digits), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				// goos: windows
				// goarch: amd64
				// pkg: github.com/H0llyW00dzZ/fiber2fa/internal/otpverifier
				// cpu: AMD Ryzen 9 3900X 12-Core Processor (Best CPU Cryptographic)
				// BenchmarkGenerateSecureRandomCounter/MaxDigits_6-24         	 8044269	       139.5 ns/op	       8 B/op	       1 allocs/op
				// BenchmarkGenerateSecureRandomCounter/MaxDigits_8-24         	 8346988	       139.8 ns/op	       8 B/op	       1 allocs/op
				// BenchmarkGenerateSecureRandomCounter/MaxDigits_30-24        	 7064142	       168.6 ns/op	       8 B/op	       1 allocs/op
				//
				// Note: 1 allocs/op it's cheap you poggers.
				config.GenerateSecureRandomCounter(digits)
			}
		})
	}
}

func BenchmarkOCRAVerify(b *testing.B) {
	// Create a new OCRAVerifier with default configuration
	config := otpverifier.DefaultConfig
	secret := gotp.RandomSecret(16)
	config.Secret = secret
	verifier := otpverifier.NewOCRAVerifier(config)

	// Define test cases
	testCases := []struct {
		ocraSuite string
		token     string
		expected  bool
	}{
		{
			ocraSuite: "OCRA-1:HOTP-SHA1-6",
			token:     "", // Token will be generated based on the challenge
			expected:  true,
		},
		{
			ocraSuite: "OCRA-1:HOTP-SHA256-8",
			token:     "", // Token will be generated based on the challenge
			expected:  true,
		},
		{
			ocraSuite: "OCRA-1:HOTP-SHA512-8",
			token:     "", // Token will be generated based on the challenge
			expected:  true,
		},
		{
			ocraSuite: "OCRA-1:HOTP-SHA1-6",
			token:     "123456",
			expected:  false,
		},
	}

	for _, tc := range testCases {
		b.Run("Hash="+tc.ocraSuite, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				challenge := generateRandomChallenge(config, tc.ocraSuite)
				if tc.token == "" {
					tc.token = generateOCRA(secret, challenge)
				}

				// goos: windows
				// goarch: amd64
				// pkg: github.com/H0llyW00dzZ/fiber2fa/internal/otpverifier
				// cpu: AMD Ryzen 9 3900X 12-Core Processor (Best CPU Cryptographic)
				// BenchmarkOCRAVerify/Hash=OCRA-1:HOTP-SHA1-6-24         	  504555	      2243 ns/op	     792 B/op	      22 allocs/op
				// BenchmarkOCRAVerify/Hash=OCRA-1:HOTP-SHA256-8-24       	  595725	      2027 ns/op	     832 B/op	      22 allocs/op
				// BenchmarkOCRAVerify/Hash=OCRA-1:HOTP-SHA512-8-24       	  425383	      2819 ns/op	    1185 B/op	      22 allocs/op
				// BenchmarkOCRAVerify/Hash=OCRA-1:HOTP-SHA1-6#01-24      	  529720	      2242 ns/op	     792 B/op	      22 allocs/op
				//
				// Note: 22 allocs/op it's because of Pseudorandom and Hash Function you poggers.
				verifier.Verify(tc.token, challenge)
			}
		})

	}
}
