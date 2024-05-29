// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package blake3otp

import (
	"hash"

	"github.com/zeebo/blake3"
)

// New256 returns a new instance of the Blake3otp hash with a 256-bit output size.
// The returned hash implements the [hash.Hash] interface.
func New256() hash.Hash {
	return &Blake3otp{
		hash: blake3.New(),
	}
}

// New384 returns a new instance of the Blake3otp hash with a 384-bit output size.
// The returned hash implements the [hash.Hash] interface.
func New384() hash.Hash {
	return &Blake3otp{
		hash:       blake3.New(),
		digestSize: 48, // 48 bytes = 384 bits
	}
}

// New512 returns a new instance of the Blake3otp hash with a 512-bit output size.
// The returned hash implements the [hash.Hash] interface.
func New512() hash.Hash {
	return &Blake3otp{
		hash:       blake3.New(),
		digestSize: 64, // 64 bytes = 512 bits
	}
}

// Blake3otp is a struct that wraps the BLAKE3 hash function.
// It implements the [hash.Hash] interface.
type Blake3otp struct {
	hash       *blake3.Hasher
	digestSize int
}

// Write writes the given bytes to the hash.
func (h *Blake3otp) Write(p []byte) (n int, err error) {
	return h.hash.Write(p)
}

// Sum appends the current hash to b and returns the resulting slice.
func (h *Blake3otp) Sum(b []byte) []byte {
	if h.digestSize == 0 {
		return h.hash.Sum(b)
	}
	digest := h.hash.Digest()
	result := make([]byte, h.digestSize)
	digest.Read(result)
	return append(b, result...)
}

// Reset resets the hash to its initial state.
func (h *Blake3otp) Reset() {
	h.hash.Reset()
}

// Size returns the number of bytes Sum will return.
func (h *Blake3otp) Size() int {
	if h.digestSize == 0 {
		return h.hash.Size()
	}
	return h.digestSize
}

// BlockSize returns the hash's underlying block size.
func (h *Blake3otp) BlockSize() int {
	return h.hash.BlockSize()
}
