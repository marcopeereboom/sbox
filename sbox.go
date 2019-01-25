package sbox

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/nacl/secretbox"
)

const (
	versionLen = 4  // size of a uint32
	nonceLen   = 24 // nonce is 24 bytes
)

var (
	magic    = []byte{'s', 'b', 'o', 'x'} // magic prefix for packed blobs
	magicLen = len(magic)                 // length of the magix prefix

	ErrInvalidHeader   = errors.New("invalid sboz header")
	ErrInvalidMagic    = errors.New("invalid magic")
	ErrCouldNotDecrypt = errors.New("could not decrypt")
)

// NewKey generates a new secret key for a NACL secret box. This key must not
// be disclosed.
func NewKey() (*[32]byte, error) {
	var k [32]byte

	_, err := io.ReadFull(rand.Reader, k[:])
	if err != nil {
		return nil, err
	}

	return &k, nil
}

// Decrypt decrypts the packed blob using provided key. It unpacks the sbox
// header and returns the version and unencrypted data if successful.
func Decrypt(key *[32]byte, packed []byte) ([]byte, uint32, error) {
	if len(packed) < magicLen+versionLen+nonceLen {
		return nil, 0, ErrInvalidHeader
	}

	// verify magic
	if !bytes.Equal(packed[0:magicLen], magic) {
		return nil, 0, ErrInvalidMagic
	}

	// unpack version
	version := binary.BigEndian.Uint32(packed[magicLen : magicLen+versionLen])

	var nonce [24]byte
	offset := magicLen + versionLen
	copy(nonce[:], packed[offset:offset+nonceLen])

	decrypted, ok := secretbox.Open(nil, packed[offset+nonceLen:],
		&nonce, key)
	if !ok {
		return nil, 0, ErrCouldNotDecrypt
	}

	return decrypted, version, nil
}

// Encrypt encrypts provided data with key. It prefixes the encrypted blob with
// an sbox header which encodes the provided version. The version user provided
// and can be used as a hint to identify or version the packed blob. Version is
// not inspected or used by Encrypt and Decrypt.
func Encrypt(version uint32, key *[32]byte, data []byte) ([]byte, error) {
	// version
	v := make([]byte, 4)
	binary.BigEndian.PutUint32(v, version)

	// random nonce
	var nonce [24]byte
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return nil, err
	}

	// encrypt data
	blob := secretbox.Seal(nil, data, &nonce, key)

	// pack all the things
	packed := make([]byte, len(magic)+len(v)+len(nonce)+len(blob))
	copy(packed[0:], magic)
	copy(packed[len(magic):], v)
	copy(packed[len(magic)+len(v):], nonce[:])
	copy(packed[len(magic)+len(v)+len(nonce):], blob)

	return packed, nil
}
