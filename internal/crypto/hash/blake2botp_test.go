// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package blake2botp_test

import (
	"hash"
	"testing"
	"time"

	blake2botp "github.com/H0llyW00dzZ/fiber2fa/internal/crypto/hash"
	"github.com/xlzd/gotp"
)

func TestBlake2botp_TOTP(t *testing.T) {
	secret := gotp.RandomSecret(16)
	digits := 6
	period := 30

	hashSizes := []int{256, 384, 512}

	for _, size := range hashSizes {
		hasher := &gotp.Hasher{
			HashName: "Blake2botp",
			Digest:   getBlake2botpHasherBySize(size),
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

func TestBlake2botp_HOTP(t *testing.T) {
	secret := gotp.RandomSecret(16)
	digits := 6
	counter := uint64(1337)

	hashSizes := []int{256, 384, 512}

	for _, size := range hashSizes {
		hasher := &gotp.Hasher{
			HashName: "Blake2botp",
			Digest:   getBlake2botpHasherBySize(size),
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

func getBlake2botpHasherBySize(size int) func() hash.Hash {
	switch size {
	case 256:
		return blake2botp.New256
	case 384:
		return blake2botp.New384
	case 512:
		return blake2botp.New512
	default:
		panic("Invalid hash size")
	}
}
