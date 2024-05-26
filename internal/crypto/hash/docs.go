// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

// Package blake2botp provides a BLAKE2b-based hash implementation for use with one-time passwords (OTP).
//
// The package defines a Blake2botp struct that wraps the BLAKE2b hash function from the [golang.org/x/crypto/blake2b] package.
// It implements the [hash.Hash] interface, allowing it to be used as a drop-in replacement for other hash functions in OTP implementations.
//
// Usage:
//
//	hasher := blake2botp.New512()
//	// Use the hasher with the OTP implementation
//
// The package provides a New512 function that returns a new instance of the Blake2botp hash with a 512-bit output size.
// The returned hash implements the [hash.Hash] interface, so it can be used directly with OTP libraries that expect a hash function.
//
// Note: The Blake2botp hash is based on the BLAKE2b hash function, which provides a secure and efficient hashing algorithm.
// However, it's important to ensure that the secret key used with the OTP implementation is kept secure and not disclosed to unauthorized parties.
// Also, note that some 2FA mobile apps might not support this hash function, so it is recommended to build your own 2FA mobile apps.
package blake2botp
