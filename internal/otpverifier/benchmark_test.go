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
				Hash:         hashFunc,
				TimeSource:   time.Now,
				UseSignature: true,
			}
			verifier := otpverifier.NewTOTPVerifier(config)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Note: This now each token are different
				token, signature := verifier.GenerateTokenWithSignature()
				// goos: windows
				// goarch: amd64
				// pkg: github.com/H0llyW00dzZ/fiber2fa/internal/otpverifier
				// cpu: AMD Ryzen 9 3900X 12-Core Processor (Best CPU Cryptographic)
				// BenchmarkTOTPVerify/SHA1-24         	  829972	      1316 ns/op	     536 B/op	      11 allocs/op
				// BenchmarkTOTPVerify/SHA1_WithSignature-24         	  459922	      2480 ns/op	    1121 B/op	      21 allocs/op
				// BenchmarkTOTPVerify/SHA224-24                     	 1000000	      1096 ns/op	     576 B/op	      11 allocs/op
				// BenchmarkTOTPVerify/SHA224_WithSignature-24       	  569559	      2074 ns/op	    1217 B/op	      21 allocs/op
				// BenchmarkTOTPVerify/SHA256-24                     	 1000000	      1105 ns/op	     576 B/op	      11 allocs/op
				// BenchmarkTOTPVerify/SHA256_WithSignature-24       	  563766	      2125 ns/op	    1217 B/op	      21 allocs/op
				// BenchmarkTOTPVerify/SHA384-24                     	  645525	      1937 ns/op	     912 B/op	      11 allocs/op
				// BenchmarkTOTPVerify/SHA384_WithSignature-24       	  308341	      3871 ns/op	    1922 B/op	      21 allocs/op
				// BenchmarkTOTPVerify/SHA512-24                     	  598796	      1953 ns/op	     928 B/op	      11 allocs/op
				// BenchmarkTOTPVerify/SHA512_WithSignature-24       	  309421	      3869 ns/op	    1986 B/op	      21 allocs/op
				// BenchmarkTOTPVerify/SHA512/224-24                 	  629589	      1929 ns/op	     896 B/op	      11 allocs/op
				// BenchmarkTOTPVerify/SHA512/224_WithSignature-24   	  331980	      3764 ns/op	    1858 B/op	      21 allocs/op
				// BenchmarkTOTPVerify/SHA512/256-24                 	  663730	      1945 ns/op	     896 B/op	      11 allocs/op
				// BenchmarkTOTPVerify/SHA512/256_WithSignature-24   	  319014	      3818 ns/op	    1858 B/op	      21 allocs/op
				// BenchmarkTOTPVerify/BLAKE2b256-24                 	  665155	      1831 ns/op	    1249 B/op	      13 allocs/op
				// BenchmarkTOTPVerify/BLAKE2b256_WithSignature-24   	  346964	      3662 ns/op	    2562 B/op	      25 allocs/op
				// BenchmarkTOTPVerify/BLAKE2b384-24                 	  645024	      1881 ns/op	    1265 B/op	      13 allocs/op
				// BenchmarkTOTPVerify/BLAKE2b384_WithSignature-24   	  335458	      3830 ns/op	    2627 B/op	      25 allocs/op
				// BenchmarkTOTPVerify/BLAKE2b512-24                 	  617192	      1912 ns/op	    1281 B/op	      13 allocs/op
				// BenchmarkTOTPVerify/BLAKE2b512_WithSignature-24   	  311072	      3865 ns/op	    2691 B/op	      25 allocs/op
				// BenchmarkTOTPVerify/BLAKE3256-24                  	  198057	      6827 ns/op	   22172 B/op	      14 allocs/op
				// BenchmarkTOTPVerify/BLAKE3256_WithSignature-24    	   84226	     15178 ns/op	   44411 B/op	      27 allocs/op
				// BenchmarkTOTPVerify/BLAKE3384-24                  	  166514	      7111 ns/op	   22252 B/op	      15 allocs/op
				// BenchmarkTOTPVerify/BLAKE3384_WithSignature-24    	   83710	     13974 ns/op	   44603 B/op	      29 allocs/op
				// BenchmarkTOTPVerify/BLAKE3512-24                  	  138141	      8103 ns/op	   22298 B/op	      15 allocs/op
				// BenchmarkTOTPVerify/BLAKE3512_WithSignature-24    	   83928	     15526 ns/op	   44729 B/op	      29 allocs/op
				//
				// Note: Using a synchronization window or Incorrect TimeSource Usage might increase the number of allocations.
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
