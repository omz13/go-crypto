// Package curves implements hybrid ECDH encryption to mix with a PQC algorithm, experimental.
package curves

import (
	"crypto/subtle"
	"errors"
	"golang.org/x/crypto/curve25519"
	"io"
)

type x25519 struct {}

func NewX25519() *x25519 {
	return &x25519{}
}

func (*x25519) Generate(rand io.Reader) (publicPoint, secret []byte, err error) {
	secret = make([]byte, curve25519.ScalarSize)
	if _, err = rand.Read(secret[:]); err != nil {
		return nil, nil, err
	}

	// Clamping
	secret[0] &= 248
	secret[31] &= 127
	secret[31] |= 64

	if publicPoint, err = curve25519.X25519(secret, curve25519.Basepoint); err != nil {
		return nil, nil, err
	}

	return publicPoint, secret, nil
}

func (*x25519) Encaps(publicPoint []byte, rand io.Reader) (ephemeral, sharedSecret []byte, err error) {
	var seed []byte
	seed = make([]byte, curve25519.ScalarSize)

	if _, err = rand.Read(seed[:]); err != nil {
		return nil, nil, err
	}

	if ephemeral, err = curve25519.X25519(seed, curve25519.Basepoint); err != nil {
		return nil, nil, err
	}

	if sharedSecret, err = curve25519.X25519(seed[:], publicPoint); err != nil {
		return nil, nil, err
	}

	return
}

func (*x25519) Decaps(ephemeral, secret []byte) (sharedSecret []byte, err error) {
	if sharedSecret, err = curve25519.X25519(secret, ephemeral); err != nil {
		return nil, err
	}

	return
}

func (c *x25519) Validate(publicPoint, secret []byte) (err error) {
	var pk []byte

	if pk, err = curve25519.X25519(secret, curve25519.Basepoint); err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(publicPoint, pk[:]) == 0 {
		return errors.New("curves: invalid x25519 public key")
	}

	return nil
}