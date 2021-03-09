package sbox

import (
	"bytes"
	"math/big"
	"sync"
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

func TestNonceEncryptDecrypt(t *testing.T) {
	secret := []byte("This is a secret message!")

	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}

	nonce := [24]byte{}
	encrypted, err := EncryptN(1, key, nonce, secret)
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
	_, _, err = Decrypt(key, encrypted)
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
	_, _, err = Decrypt(key, encrypted)
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
	_, _, err = Decrypt(key, encrypted)
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
	_, _, err = Decrypt(key, encrypted[0:size-1])
	if err != ErrInvalidHeader {
		t.Fatal(err)
	}

	// short data
	size = len(encrypted)
	_, _, err = Decrypt(key, encrypted[0:size-1])
	if err != ErrCouldNotDecrypt {
		t.Fatal(err)
	}
}

func TestNonce(t *testing.T) {
	n := NewNonce()
	for i := int64(0); i < 1337; i++ {
		if n.n.Cmp(big.NewInt(i)) != 0 {
			t.Fatalf("invalid nonce got %v want %v", n.n, i)
		}
		n.Next()
	}
	nn, err := NewNonceFromBytes([]byte{0x05, 0x39})
	if err != nil {
		t.Fatal(err)
	}
	n1 := n.Current()
	n2 := nn.Current()
	if !bytes.Equal(n1[:], n2[:]) {
		t.Fatalf("want %v got %v", n1, n2)
	}
}

func TestNegativeNonce(t *testing.T) {
	b := make([]byte, 25)
	nn, err := NewNonceFromBytes(b)
	if err == nil {
		t.Fatalf("invalid length %v", len(b))
	}
	_ = nn
}

func TestConcurrentNonce(t *testing.T) {
	var wg sync.WaitGroup
	n := NewNonce()
	x := 1337
	for i := 0; i < x; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n.Next()
		}()
	}
	wg.Wait()
	if n.n.Cmp(big.NewInt(int64(x))) != 0 {
		t.Fatal("invalid nonce")
	}
}
