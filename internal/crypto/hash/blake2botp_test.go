// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package blake2botp_test

import (
	"testing"
	"time"

	blake2botp "github.com/H0llyW00dzZ/fiber2fa/internal/crypto/hash"
	"github.com/xlzd/gotp"
)

func TestBlake2botpbotp_TOTP(t *testing.T) {
	secret := gotp.RandomSecret(16)
	digits := 6
	period := 30
	hasher := &gotp.Hasher{
		HashName: "Blake2botp",
		Digest:   blake2botp.New512,
	}

	totp := gotp.NewTOTP(secret, digits, period, hasher)
	timestamp := time.Now().Unix()
	otp := totp.At(timestamp)

	if len(otp) != digits {
		t.Errorf("Expected OTP length to be %d, but got %d", digits, len(otp))
	}

	if !totp.Verify(otp, timestamp) {
		t.Error("Generated OTP failed verification")
	}
}

func TestBlake2botp_HOTP(t *testing.T) {
	secret := gotp.RandomSecret(16)
	digits := 6
	counter := uint64(1337)
	hasher := &gotp.Hasher{
		HashName: "Blake2botp",
		Digest:   blake2botp.New512,
	}

	hotp := gotp.NewHOTP(secret, digits, hasher)
	otp := hotp.At(int(counter))

	if len(otp) != digits {
		t.Errorf("Expected OTP length to be %d, but got %d", digits, len(otp))
	}

	if !hotp.Verify(otp, int(counter)) {
		t.Error("Generated OTP failed verification")
	}
}
