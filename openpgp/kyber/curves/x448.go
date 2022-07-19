// Package curves implements hybrid ECDH encryption to mix with a PQC algorithm, experimental.
package curves

import (
	"crypto/subtle"
	"errors"
	"io"

	x448lib "github.com/cloudflare/circl/dh/x448"
)

type x448 struct {}

func NewX448() *x448 {
	return &x448{}
}

func (*x448) Generate(rand io.Reader) (publicPoint, secret []byte, err error) {
	var sk, pk x448lib.Key
	if _, err = rand.Read(sk[:]); err != nil {
		return nil, nil, err
	}

	x448lib.KeyGen(&pk, &sk)

	return pk[:], sk[:], nil
}

func (*x448) Encaps(publicPoint []byte, rand io.Reader) (ephemeral, sharedSecret []byte, err error) {
	var ss, pk, seed, e x448lib.Key
	if _, err = rand.Read(seed[:]); err != nil {
		return nil, nil, err
	}

	x448lib.KeyGen(&e, &seed)

	copy(pk[:], publicPoint)
	x448lib.Shared(&ss, &seed, &pk)

	return e[:], ss[:], nil
}

func (*x448) Decaps(ephemeral, secret []byte) (sharedSecret []byte, err error) {
	var ss, sk, e x448lib.Key

	copy(sk[:], secret)
	copy(e[:], ephemeral)
	x448lib.Shared(&ss, &sk, &e)

	return ss[:], nil
}

func (c *x448) Validate(publicPoint, secret []byte) error {
	var sk, pk x448lib.Key
	copy(sk[:], secret)

	x448lib.KeyGen(&pk, &sk)

	if subtle.ConstantTimeCompare(publicPoint, pk[:]) == 0 {
		return errors.New("curves: invalid x448 public key")
	}

	return nil
}