// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

// Package otpverifier provides a simple and flexible way to verify and generate one-time passwords (OTPs)
// using time-based (TOTP) or counter-based (HOTP) algorithms. It supports optional signature generation
// and verification for enhanced security.
//
// The package offers an [otpverifier.OTPVerifier] interface that defines the behavior of an OTP verifier. It includes
// methods for verifying tokens and signatures and generating tokens and signatures.
//
// The package provides two implementations of the [otpverifier.OTPVerifier] interface: [otpverifier.TOTPVerifier] and [otpverifier.HOTPVerifier].
// [otpverifier.TOTPVerifier] is used for time-based OTPs, while [otpverifier.HOTPVerifier] is used for counter-based OTPs.
//
// The package also includes an [otpverifier.OTPFactory] function that creates an appropriate [otpverifier.OTPVerifier] based on the
// provided configuration. The configuration is defined using the Config struct, which holds options such
// as the secret key, counter value, signature usage, and time source.
//
// Example usage:
//
//	// Create a configuration for TOTP
//	totpConfig := otpverifier.Config{
//		Secret:       "your-secret-key",
//		UseSignature: true,
//	}
//
//	// Create a TOTP verifier using the factory function
//	totpVerifier := otpverifier.OTPFactory(totpConfig)
//
//	// Generate a token and signature
//	token, signature := totpVerifier.GenerateToken()
//
//	// Verify the token and signature
//	isValid := totpVerifier.Verify(token, signature)
//
//	// Create a configuration for HOTP
//	hotpConfig := otpverifier.Config{
//		Secret:       "your-secret-key",
//		Counter:      1000,
//		UseSignature: true,
//	}
//
//	// Create an HOTP verifier using the factory function
//	hotpVerifier := otpverifier.OTPFactory(hotpConfig)
//
//	// Generate a token and signature
//	token, signature := hotpVerifier.GenerateToken()
//
//	// Verify the token and signature
//	isValid := hotpVerifier.Verify(token, signature)
//
// The package uses the [github.com/xlzd/gotp] library for generating and verifying OTPs and the
// [crypto/hmac] and [crypto/sha256] packages for generating and verifying signatures.
//
// Note: Some 2FA Mobile Apps might not support this hash function, so it is recommended to build your own 2FA Mobile apps.
package otpverifier
