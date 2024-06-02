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
// The package uses the [github.com/xlzd/gotp] library for generating and verifying OTPs,
// and the [crypto/hmac], [crypto/sha256], [crypto/sha512], [github.com/H0llyW00dzZ/fiber2fa/internal/crypto/hash/blake2botp], and
// [github.com/H0llyW00dzZ/fiber2fa/internal/crypto/hash/blake3otp] packages for generating and verifying signatures
// using HMAC with SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, BLAKE2b, and BLAKE3.
//
// # Configuration
//
// The OTP verifier can be configured using the [otpverifier.Config] struct. The available options are:
//
//   - Secret: The shared secret key used for generating and verifying OTPs. This field is required.
//   - Digits: The number of digits in the generated OTP. Default is 6.
//   - Period: The time step size in seconds for TOTP. Default is 30 seconds.
//   - UseSignature: Determines whether to generate and verify signatures. Default is false.
//   - TimeSource: The time source function used for TOTP. Default is [time.Now].
//   - Counter: The initial counter value for HOTP. Default is to use [otpverifier.Config.GenerateSecureRandomCounter]
//     with the default number of digits specified in [otpverifier.DefaultConfig.Digits].
//   - CounterMismatch: The counter mismatch threshold for adjusting the synchronization window size. Available options are:
//   - [otpverifier.CounterMismatchThreshold1x]: Adjust the sync window size if the counter mismatch exceeds 1.
//   - [otpverifier.CounterMismatchThreshold3x]: Adjust the sync window size if the counter mismatch exceeds 3.
//   - [otpverifier.CounterMismatchThreshold5x]: Adjust the sync window size if the counter mismatch exceeds 5.
//   - SyncWindow: The number of time steps (for TOTP) or counter values (for HOTP) to check before and after the current value when verifying OTPs.
//     The synchronization window size can be adjusted based on the counter mismatch threshold. Available options are:
//   - [otpverifier.NoneStrict]: No strictness, the synchronization window size is not enforced.
//   - [otpverifier.HighStrict]: Highest strictness, the synchronization window size is fixed at 1.
//   - [otpverifier.MediumStrict]: Medium strictness, the synchronization window size is determined by the corresponding range in [otpverifier.SyncWindowRanges].
//   - [otpverifier.LowStrict]: Low strictness, the synchronization window size is determined by the corresponding range in [otpverifier.SyncWindowRanges].
//   - ResyncWindowDelay: The delay duration for resynchronizing the synchronization window. Default is 30 minutes.
//   - URITemplate: The URI template used for generating OTP URLs. Default is "otpauth://%s/%s:%s?secret=%s&issuer=%s&digits=%d&algorithm=%s".
//   - CustomURITemplateParams: A map of custom parameters to include in the OTP URL. Default is nil.
//   - Hash: The name of the hashing algorithm to use. This field is required. List values are:
//   - [SHA1]
//   - [SHA224]
//   - [SHA256]
//   - [SHA384]
//   - [SHA512]
//   - [SHA512S224]
//   - [SHA512S256]
//   - [BLAKE2b256]
//   - [BLAKE2b384]
//   - [BLAKE2b512]
//   - [BLAKE3256]
//   - [BLAKE3384]
//   - [BLAKE3512]
//
// # QR Code Configuration
//
// The QR code generation can be configured using the [otpverifier.QRCodeConfig] struct. The available options are:
//
//   - Level: The error correction level for the QR code. Default is [qrcode.Medium].
//   - Size: The size of the QR code image in pixels. Default is 256.
//   - ForegroundColor: The color of the QR code foreground. Default is [color.Black].
//   - BackgroundColor: The color of the QR code background. Default is [color.White].
//   - DisableBorder: Determines whether to disable the QR code border. Default is false.
//   - TopText: The text to display above the QR code. Default is an empty string.
//   - BottomText: The text to display below the QR code. Default is an empty string.
//   - Font: The font to use for the top and bottom text. Default is [basicfont.Face7x13].
//   - TopTextPosition: The position of the top text. Default is calculated dynamically.
//   - BottomTextPosition: The position of the bottom text. Default is calculated dynamically.
//
// The default QR code configuration can be accessed using [otpverifier.DefaultQRCodeConfig].
//
// # Compatible and Supported Devices
//
// This package aims to provide compatibility with a wide range of devices and 2FA apps. However, it's important to note
// that not all 2FA apps, especially mobile apps, are fully supported by this package. The reasons for this include:
//
//  1. Poor Ecosystems: Some mobile 2FA apps have limited support for certain hashing algorithms, such as SHA-512/224,
//     SHA-512/256, BLAKE2b, and BLAKE3. These apps may not be able to generate or verify tokens using these algorithms.
//
//  2. Incorrect Entropy in Token Generation: This issue is more prevalent with HOTP when setting the counter to a random value
//     for initialization. Some 2FA apps may generate tokens using a different entropy source or algorithm, which literally
//     breaks the cryptographic principles related to hash functions. This can lead to incompatibility with the tokens
//     generated by this package. For example, while some 2FA apps may be able to generate tokens, when verified using this
//     package, they may be considered "invalid".
//
//  3. Time Synchronization Issues (for TOTP): TOTP relies on a synchronized time value between the server and the client.
//     If the client's device has an incorrect time or if there are significant delays in communication, it can cause issues
//     with token verification. This is because this package uses [crypto/subtle], which provides strict and strong synchronization
//     requirements related to time to prevent timing attacks. As a result, even small discrepancies in time synchronization can
//     lead to token verification failures.
//
// To ensure the best compatibility and support, consider the following recommendations:
//
//   - Use widely supported hashing algorithms, such as SHA-1, SHA-256, or SHA-512, when configuring the package.
//   - For HOTP, consider starting the counter from a well-known value (e.g., 1) and incrementing it consistently on both
//     the server and the client side. Alternatively, use [otpverifier.Config.GenerateSecureRandomCounter] to generate a
//     secure random counter value.
//   - Implement proper time synchronization mechanisms to minimize time-related issues with TOTP.
//   - If using less common hashing algorithms or advanced features, consider building custom 2FA mobile apps to ensure
//     full compatibility with the package.
//
// By following these guidelines and being aware of the potential limitations, it is possible to maximize the compatibility
// and support for various devices and 2FA apps when using this package.
package otpverifier
