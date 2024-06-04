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
	config := &otpverifier.Config{}

	maxDigits := []int{6, 8, 30}

	for _, digits := range maxDigits {
		b.Run(fmt.Sprintf("MaxDigits_%d", digits), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				// goos: windows
				// goarch: amd64
				// pkg: github.com/H0llyW00dzZ/fiber2fa/internal/otpverifier
				// cpu: AMD Ryzen 9 3900X 12-Core Processor
				// BenchmarkGenerateSecureRandomCounter/MaxDigits_6-24         	 8469748	       142.5 ns/op	       8 B/op	       1 allocs/op
				// BenchmarkGenerateSecureRandomCounter/MaxDigits_8-24         	 8226728	       143.9 ns/op	       8 B/op	       1 allocs/op
				// BenchmarkGenerateSecureRandomCounter/MaxDigits_30-24        	 6852162	       174.9 ns/op	       8 B/op	       1 allocs/op
				//
				// Note: 1 allocs/op it's cheap you poggers.
				config.GenerateSecureRandomCounter(digits)
			}
		})
	}
}
