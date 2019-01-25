package sbox

import (
	"bytes"
	"testing"

	"github.com/davecgh/go-spew/spew"
)

func TestEncryptDecrypt(t *testing.T) {
	secret := []byte("This is a secret message!")

	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := Encrypt(1, key, secret)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, version, err := Decrypt(key, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(spew.Sdump(encrypted))
	t.Log(spew.Sdump(decrypted))

	if !bytes.Equal(secret, decrypted) {
		t.Fatalf("decryption failed")
	}
	if version != 1 {
		t.Fatalf("invalid version")
	}
}

func TestEncryptDecryptCorruptHeader(t *testing.T) {
	secret := []byte("This is a secret message!")

	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := Encrypt(1, key, secret)
	if err != nil {
		t.Fatal(err)
	}

	// corrupt version
	encrypted[magicLen+3] = 2
	decrypted, version, err := Decrypt(key, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secret, decrypted) {
		t.Fatalf("decryption failed")
	}
	if version == 1 {
		t.Fatalf("invalid version")
	}
	encrypted[magicLen+3] = 1

	// corrupt magic
	encrypted[0] = 0
	decrypted, version, err = Decrypt(key, encrypted)
	if err != ErrInvalidMagic {
		t.Fatal(err)
	}
	encrypted[0] = 's' // fix sbox magic

	// corrupt nonce
	offset := magicLen + versionLen + 2
	t.Logf("offset: 0x%x\n%v", offset, spew.Sdump(encrypted))
	x := encrypted[offset]
	encrypted[offset]++
	t.Logf("offset: 0x%x\n%v", offset, spew.Sdump(encrypted))
	decrypted, version, err = Decrypt(key, encrypted)
	if err != ErrCouldNotDecrypt {
		t.Fatal(err)
	}
	encrypted[offset] = x

	// corrupt data
	offset = magicLen + versionLen + nonceLen + 7
	t.Logf("offset: 0x%x\n%v", offset, spew.Sdump(encrypted))
	x = encrypted[offset]
	encrypted[offset]++
	t.Logf("offset: 0x%x\n%v", offset, spew.Sdump(encrypted))
	decrypted, version, err = Decrypt(key, encrypted)
	if err != ErrCouldNotDecrypt {
		t.Fatal(err)
	}
	encrypted[offset] = x

	// verify we are still cool after fixups
	decrypted, version, err = Decrypt(key, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secret, decrypted) {
		t.Fatalf("decryption failed")
	}
	if version != 1 {
		t.Fatalf("invalid version")
	}

	// short header
	size := magicLen + versionLen + nonceLen
	decrypted, version, err = Decrypt(key, encrypted[0:size-1])
	if err != ErrInvalidHeader {
		t.Fatal(err)
	}

	// short data
	size = len(encrypted)
	decrypted, version, err = Decrypt(key, encrypted[0:size-1])
	if err != ErrCouldNotDecrypt {
		t.Fatal(err)
	}
}
