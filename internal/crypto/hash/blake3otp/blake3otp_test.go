// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package blake3otp_test

import (
	"hash"
	"testing"
	"time"

	blake3otp "github.com/H0llyW00dzZ/fiber2fa/internal/crypto/hash/blake3otp"
	"github.com/xlzd/gotp"
)

func TestBlake3otp_TOTP(t *testing.T) {
	secret := gotp.RandomSecret(16)
	digits := 6
	period := 30

	hashSizes := []int{256, 384, 512}

	for _, size := range hashSizes {
		hasher := &gotp.Hasher{
			HashName: "Blake3otp",
			Digest:   getBlake3otpHasherBySize(size),
		}

		totp := gotp.NewTOTP(secret, digits, period, hasher)
		timestamp := time.Now().Unix()
		otp := totp.At(timestamp)

		if len(otp) != digits {
			t.Errorf("Expected OTP length to be %d, but got %d (hash size: %d)", digits, len(otp), size)
		}

		if !totp.Verify(otp, timestamp) {
			t.Errorf("Generated OTP failed verification (hash size: %d)", size)
		}
	}
}

func TestBlake3otp_HOTP(t *testing.T) {
	secret := gotp.RandomSecret(16)
	digits := 6
	counter := uint64(1337)

	hashSizes := []int{256, 384, 512}

	for _, size := range hashSizes {
		hasher := &gotp.Hasher{
			HashName: "Blake3otp",
			Digest:   getBlake3otpHasherBySize(size),
		}

		hotp := gotp.NewHOTP(secret, digits, hasher)
		otp := hotp.At(int(counter))

		if len(otp) != digits {
			t.Errorf("Expected OTP length to be %d, but got %d (hash size: %d)", digits, len(otp), size)
		}

		if !hotp.Verify(otp, int(counter)) {
			t.Errorf("Generated OTP failed verification (hash size: %d)", size)
		}
	}
}

func getBlake3otpHasherBySize(size int) func() hash.Hash {
	switch size {
	case 256:
		return blake3otp.New256
	case 384:
		return blake3otp.New384
	case 512:
		return blake3otp.New512
	default:
		panic("Invalid hash size")
	}
}
