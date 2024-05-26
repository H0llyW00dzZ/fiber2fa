// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package blake2botp

import (
	"hash"

	"golang.org/x/crypto/blake2b"
)

// New256 returns a new instance of the Blake2botp hash with a 256-bit output size.
// The returned hash implements the [hash.Hash] interface.
func New256() hash.Hash {
	h, _ := blake2b.New256(nil)
	return &Blake2botp{
		hash: h,
	}
}

// New384 returns a new instance of the Blake2botp hash with a 384-bit output size.
// The returned hash implements the [hash.Hash] interface.
func New384() hash.Hash {
	h, _ := blake2b.New384(nil)
	return &Blake2botp{
		hash: h,
	}
}

// New512 returns a new instance of the Blake2botp hash with a 512-bit output size.
// The returned hash implements the [hash.Hash] interface.
func New512() hash.Hash {
	h, _ := blake2b.New512(nil)
	return &Blake2botp{
		hash: h,
	}
}

// Blake2botp is a struct that wraps the BLAKE2b hash function.
// It implements the [hash.Hash] interface.
type Blake2botp struct {
	hash hash.Hash
}

// Write writes the given bytes to the hash.
func (h *Blake2botp) Write(p []byte) (n int, err error) {
	return h.hash.Write(p)
}

// Sum appends the current hash to b and returns the resulting slice.
func (h *Blake2botp) Sum(b []byte) []byte {
	return h.hash.Sum(b)
}

// Reset resets the hash to its initial state.
func (h *Blake2botp) Reset() {
	h.hash.Reset()
}

// Size returns the number of bytes Sum will return.
func (h *Blake2botp) Size() int {
	return h.hash.Size()
}

// BlockSize returns the hash's underlying block size.
func (h *Blake2botp) BlockSize() int {
	return h.hash.BlockSize()
}
