// Package kyber_test tests the implementation of Kyber + ECDH encryption, suitable for OpenPGP, experimental.
package kyber_test

import (
	"bytes"
	"crypto/rand"
	"github.com/ProtonMail/go-crypto/openpgp/internal/algorithm"
	"github.com/ProtonMail/go-crypto/openpgp/kyber"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	testFingerprint := make([]byte, 32)
	rand.Read(testFingerprint)

	asymmAlgos := map[string] packet.PublicKeyAlgorithm {
		"Kyber512_X25519": packet.PubKeyAlgoKyber512X25519,
		"Kyber1024_X448": packet.PubKeyAlgoKyber1024X448,
		"Kyber768_p384": packet.PubKeyAlgoKyber768P384,
		"Kyber1024_P521":packet.PubKeyAlgoKyber1024P521,
	}

	symmAlgos := map[string] algorithm.Cipher {
		"AES-128": algorithm.AES128,
		"AES-192": algorithm.AES192,
		"AES-256": algorithm.AES256,
	}

	for asymmName, asymmAlgo := range asymmAlgos {
		t.Run(asymmName, func(t *testing.T) {
			for symmName, symmAlgo := range symmAlgos {
				t.Run(symmName, func(t *testing.T) {
					testEncryptDecryptAlgo(t, testFingerprint, asymmAlgo, symmAlgo)
				})
			}
		})
	}
}

func testEncryptDecryptAlgo(t *testing.T, testFingerprint []byte, algId packet.PublicKeyAlgorithm, kdfCipher algorithm.Cipher) {
	curveObj, err := packet.GetCurveFromAlgID(algId)
	if err != nil {
		t.Errorf("error getting curve: %s", err)
	}

	kyberObj, err := packet.GetKyberFromAlgID(algId)
	if err != nil {
		t.Errorf("error getting kyber: %s", err)
	}

	priv, err := kyber.GenerateKey(rand.Reader, uint8(algId), curveObj, kyberObj)
	if err != nil {
		t.Fatal(err)
	}

	expectedMessage := make([]byte, kdfCipher.KeySize() + 3) // encryption algo + checksum
	rand.Read(expectedMessage)

	kE, ecE, c, err := kyber.Encrypt(rand.Reader, &priv.PublicKey, expectedMessage, testFingerprint)
	if err != nil {
		t.Errorf("error encrypting: %s", err)
	}

	decryptedMessage, err := kyber.Decrypt(priv, kE, ecE, c, testFingerprint)
	if err != nil {
		t.Errorf("error decrypting: %s", err)
	}
	if !bytes.Equal(decryptedMessage, expectedMessage) {
		t.Errorf("decryption failed, got: %x, want: %x", decryptedMessage, expectedMessage)
	}
}
