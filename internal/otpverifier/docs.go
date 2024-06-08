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
// Example usage with custom time zone (Antarctica):
//
//	// Custom time source function for Antarctica time zone
//	antarcticaTimeSource := func() time.Time {
//		location, _ := time.LoadLocation("Antarctica/South_Pole")
//		return time.Now().In(location)
//	}
//
//	// Create a configuration for TOTP with custom time source
//	totpConfig := otpverifier.Config{
//		Secret:       "your-secret-key",
//		UseSignature: true,
//		TimeSource:   antarcticaTimeSource,
//	}
//
//	// Create a TOTP verifier using the factory function
//	totpVerifier := otpverifier.OTPFactory(totpConfig)
//
//	// Generate a token and signature using Antarctica time zone
//	token, signature := totpVerifier.GenerateToken()
//
//	// Verify the token and signature using Antarctica time zone
//	isValid := totpVerifier.Verify(token, signature)
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
//   - TimeSource: The time source function used for TOTP. This field is required. The time source function should return
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
//   - CustomURITemplateParams (Advanced Cryptographic OTP Use Cases, e.g., Customize Character Set instead of numbers in client device, callback to the server, etc.): A map of custom parameters to include in the OTP URL. Default is nil.
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
//   - [CleanupIntervals]: The interval at which the cleanup process runs to remove expired tokens in the TOTP verifier. Available options are:
//   - [FastCleanup]
//   - [MediumCleanup]
//   - [SlowCleanup]
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
//     for initialization (e.g, use [otpverifier.Config.GenerateSecureRandomCounter] to generate a
//     secure random counter value). Some 2FA apps may generate tokens using a different entropy source or algorithm, which literally
//     breaks the cryptographic principles related to hash functions. This can lead to incompatibility with the tokens
//     generated by this package. For example, while some 2FA apps may be able to generate tokens, when verified using this
//     package, they may be considered "invalid".
//
//  3. Time Synchronization Issues (for TOTP): TOTP relies on a synchronized time value between the server and the client.
//     If the client's device has an incorrect time or if there are significant delays in communication, it can cause issues
//     with token verification. This is because this package uses [crypto/subtle], which provides strict and strong synchronization
//     requirements related to time to prevent brute-force and timing attacks. As a result, even small discrepancies in time synchronization can
//     lead to token verification failures.
//
//  4. MFA Not Supported: Multi-Factor Authentication (MFA) is not supported within this package due to the high risks associated with it.
//     MFA often relies on hash functions like MD5, SHA-1, SHA-256, or SHA-512, which are basically the same. However, the use cases for MFA are not guaranteed
//     since it is linked to many sensitive data points, such as user accounts, unlike 2FA (e.g., TOTP) which is typically used for a specific purpose.
//
// To ensure the best compatibility and support, consider the following recommendations:
//
//   - Use widely supported hashing algorithms, such as SHA-1, SHA-256, or SHA-512, when configuring the package.
//   - For HOTP, consider starting the counter from a well-known value (e.g., 1) and incrementing it consistently on both
//     the server and the client side. Alternatively, use [otpverifier.Config.GenerateSecureRandomCounter] to generate a
//     secure random counter value.
//   - Set the correct time synchronization to ensure that the server and client (e.g., mobile devices or other devices)
//     have the same time reference. This minimizes time-related issues with TOTP and ensures accurate token verification.
//     It is important to use Unix time (POSIX time/Epoch time) with a 64-bit integer for time synchronization to maintain compatibility and avoid issues related to time zones and daylight saving time.
//   - If using less common hashing algorithms or advanced features, consider building custom 2FA mobile apps to ensure
//     full compatibility with the package.
//
// By following these guidelines and being aware of the potential limitations, it is possible to maximize the compatibility
// and support for various devices and 2FA apps when using this package.
//
// # Synchronization and Resynchronization for HOTP
//
// This package provides standard basic mathematical synchronization and resynchronization mechanisms for HOTP (HMAC-based One-Time Password) to achieve a perfect balance between server, client, security, and system.
// The synchronization and resynchronization features are designed to handle scenarios where the server and client counters may become out of sync.
//
//  1. Synchronization
//
// Synchronization in HOTP refers to the process of ensuring that the server and client counters are in sync. The package uses a synchronization window ([otpverifier.SyncWindow]) to allow for a certain degree of tolerance when verifying HOTP tokens.
// The synchronization window determines the number of counter values to check before and after the current server counter value.
//
// The synchronization window size can be configured using the [otpverifier.SyncWindow] field in the [otpverifier.Config] struct. The available options are:
//
//   - [otpverifier.NoneStrict]: No strictness, the synchronization window size is not enforced.
//   - [otpverifier.HighStrict]: Highest strictness, the synchronization window size is fixed at 1.
//   - [otpverifier.MediumStrict]: Medium strictness, the synchronization window size is determined by the corresponding range in [otpverifier.SyncWindowRanges].
//   - [otpverifier.LowStrict]: Low strictness, the synchronization window size is determined by the corresponding range in [otpverifier.SyncWindowRanges].
//
// The [otpverifier.SyncWindowRanges] map defines the ranges of synchronization window sizes for different strictness levels. For example, [otpverifier.MediumStrict] corresponds to a range of 2 to 5, while [otpverifier.LowStrict] corresponds to a range of 5 to 10.
//
// During the HOTP token verification process, the package checks the provided token against the server counter value and the counter values within the synchronization window. If a match is found, the token is considered valid, and the server counter is updated to the next expected value.
//
//  2. Resynchronization
//
// Resynchronization in HOTP is the process of automatically adjusting the server counter value when it becomes significantly out of sync with the client counter. The package implements a resynchronization mechanism based on the number of counter mismatches.
//
// The resynchronization behavior can be configured using the [otpverifier.CounterMismatch] field in the [otpverifier.Config] struct. The available options are:
//
//   - [otpverifier.CounterMismatchThreshold1x]: Adjust the synchronization window size if the counter mismatch exceeds 1.
//   - [otpverifier.CounterMismatchThreshold3x]: Adjust the synchronization window size if the counter mismatch exceeds 3.
//   - [otpverifier.CounterMismatchThreshold5x]: Adjust the synchronization window size if the counter mismatch exceeds 5.
//
// When the number of counter mismatches exceeds the configured threshold, the package automatically adjusts the synchronization window size based on the [otpverifier.SyncWindow] configuration. This adjustment helps to accommodate larger discrepancies between the server and client counters.
//
// The resynchronization process is triggered after a specified delay ([otpverifier.ResyncWindowDelay]) to prevent excessive adjustments. The default delay is 30 minutes, but it can be customized in the [otpverifier.Config] struct.
//
// By providing synchronization and resynchronization mechanisms, this package aims to maintain a balanced and secure HOTP implementation that can handle various scenarios of counter mismatches between the server and client.
//
// # Synchronization for TOTP
//
// This package provides a synchronization mechanism for TOTP (Time-based One-Time Password) to handle scenarios where the server and client clocks may be slightly out of sync.
// The synchronization feature is designed to accommodate minor time differences while maintaining the security of the TOTP verification process.
//
//  1. Synchronization Window
//
// Synchronization in TOTP refers to the process of allowing a certain degree of tolerance when verifying TOTP tokens. The package uses a synchronization window ([otpverifier.SyncWindow]) to account for small time differences between the server and client clocks.
//
// The synchronization window determines the number of time steps before and after the current time step to consider when verifying a TOTP token. It allows for a token to be valid within a specific range of time steps, rather than requiring an exact match.
//
// The synchronization window size can be configured using the [otpverifier.SyncWindow] field in the [otpverifier.Config] struct. It accepts an integer value representing the number of time steps to include in the synchronization window.
//
// For example, if the synchronization window size is set to 1, the package will consider tokens valid within a range of ±1 time step from the current time step. If the synchronization window size is set to 2, the range will be ±2 time steps, and so on.
//
// The appropriate synchronization window size depends on the specific requirements of your application and the expected time drift between the server and client clocks. A larger synchronization window allows for greater tolerance but may also increase the window of opportunity for token reuse.
//
// It's important to strike a balance between usability and security when determining the synchronization window size. A smaller window size provides stricter security but may lead to more frequent token rejections due to clock drift. Conversely, a larger window size accommodates more significant time differences but may weaken the security guarantees.
//
//  2. Time Source and Period
//
// The synchronization mechanism in TOTP relies on a synchronized time source between the server and client. The package requires you to specify a time source function ([otpverifier.Config.TimeSource]) to ensure accurate time synchronization.
//
// The time source function should return the current time in the desired location or time zone. It is the responsibility of the user to provide a suitable time source function that meets their specific requirements.
//
// In addition to the time source, the TOTP verification process also depends on the time step size, known as the period ([otpverifier.Config.Period]). The period determines the duration of each time step in seconds. The default period is 30 seconds, as specified in the TOTP standard (RFC 6238).
//
// It's important to note that the synchronization window and the period are closely related. The synchronization window size is expressed in terms of the number of time steps, while the period determines the actual duration of each time step.
//
// For example, if the period is set to 30 seconds and the synchronization window size is set to 1, the package will consider tokens valid within a range of ±30 seconds from the current time.
//
// By providing a synchronization mechanism for TOTP, this package aims to accommodate minor time differences between the server and client clocks while maintaining the security and integrity of the TOTP verification process. It allows for a configurable degree of tolerance, ensuring that valid tokens are accepted even in the presence of slight time discrepancies.
//
// Note: The synchronization mechanism for TOTP is not explicitly defined in the TOTP standard (RFC 6238). It is an additional feature provided by this package to enhance the usability and reliability of TOTP implementations. The effectiveness of the synchronization depends on the accuracy of the time source and the appropriate configuration of the synchronization window and period.
package otpverifier
