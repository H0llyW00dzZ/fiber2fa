// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

// Package blake3otp provides BLAKE3-based hash implementations for use with one-time passwords (OTP).
//
// The package defines hash functions ([blake3otp.New256], [blake3otp.New384], [blake3otp.New512]) that wrap the BLAKE3 hash function from the [github.com/zeebo/blake3] package.
// These functions return hash instances that implement the [hash.Hash] interface, allowing them to be used as drop-in replacements for other hash functions in OTP implementations.
//
// Usage:
//
//	hasher := blake3otp.New512()
//	// Use the hasher with the OTP implementation
//
// The package provides the following functions:
//
//   - [blake3otp.New256]: Returns a new instance of the BLAKE3 hash with a 256-bit output size.
//   - [blake3otp.New384]: Returns a new instance of the BLAKE3 hash with a 384-bit output size.
//   - [blake3otp.New512]: Returns a new instance of the BLAKE3 hash with a 512-bit output size.
//
// The returned hash instances implement the [hash.Hash] interface, so they can be used directly with OTP libraries that expect a hash function.
//
// Note: The BLAKE3 hash functions provided by this package are secure and efficient hashing algorithms.
// However, it's important to ensure that the secret key used with the OTP implementation is kept secure and not disclosed to unauthorized parties.
// Also, note that some 2FA mobile apps might not support these hash functions, so it is recommended to build your own 2FA mobile apps for compatibility.
package blake3otp
