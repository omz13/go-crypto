// Package curves implements hybrid ECDH encryption to mix with a PQC algorithm, experimental.
package curves

import (
	"crypto/elliptic"
	"fmt"
	"github.com/ProtonMail/go-crypto/openpgp/errors"
	"io"
	"math/big"
)

type nistCurve struct {
	Curve elliptic.Curve
}

func NewNistCurve(c elliptic.Curve) *nistCurve {
	return &nistCurve{Curve: c}
}

func (c *nistCurve) Generate(rand io.Reader) ([]byte, []byte, error) {
	secret, x, y, err := elliptic.GenerateKey(c.Curve, rand)
	if err != nil {
		return nil, nil, err
	}

	return elliptic.Marshal(c.Curve, x, y), secret, err
}

func (c *nistCurve) Encaps(publicPoint []byte, rand io.Reader) (ephemeral, sharedSecret []byte, err error) {
	d, x, y, err := elliptic.GenerateKey(c.Curve, rand)
	if err != nil {
		return nil, nil, err
	}

	xP, yP := elliptic.Unmarshal(c.Curve, publicPoint)

	vsG := elliptic.Marshal(c.Curve, x, y)
	zbBig, _ := c.Curve.ScalarMult(xP, yP, d)

	byteLen := (c.Curve.Params().BitSize + 7) >> 3
	zb := make([]byte, byteLen)
	zbBytes := zbBig.Bytes()
	copy(zb[byteLen-len(zbBytes):], zbBytes)

	return vsG, zb, nil
}

func (c *nistCurve) Decaps(ephemeral, secret []byte) (sharedSecret []byte, err error) {
	x, y := elliptic.Unmarshal(c.Curve, ephemeral)
	zbBig, _ := c.Curve.ScalarMult(x, y, secret)
	byteLen := (c.Curve.Params().BitSize + 7) >> 3
	zb := make([]byte, byteLen)
	zbBytes := zbBig.Bytes()
	copy(zb[byteLen-len(zbBytes):], zbBytes)

	return zb, nil
}

func (c *nistCurve) Validate(publicPoint, secret []byte) error {
	xP, yP := elliptic.Unmarshal(c.Curve, publicPoint)

	// the public point should not be at infinity (0,0)
	zero := new(big.Int)
	if xP.Cmp(zero) == 0 && yP.Cmp(zero) == 0 {
		return errors.KeyInvalidError(fmt.Sprintf("ecc (%s): infinity point", c.Curve.Params().Name))
	}

	// re-derive the public point Q' = (X,Y) = dG
	// to compare to declared Q in public key
	expectedX, expectedY := c.Curve.ScalarBaseMult(secret)
	if xP.Cmp(expectedX) != 0 || yP.Cmp(expectedY) != 0 {
		return errors.KeyInvalidError(fmt.Sprintf("ecc (%s): invalid point", c.Curve.Params().Name))
	}

	return nil
}