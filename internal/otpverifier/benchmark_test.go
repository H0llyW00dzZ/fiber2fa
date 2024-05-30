// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package otpverifier_test

import (
	"testing"

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
				Secret: secret,
				Hash:   hashFunc,
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
