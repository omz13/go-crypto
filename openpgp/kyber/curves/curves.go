// Package curves implements hybrid ECDH encryption to mix with a PQC algorithm, experimental.
package curves

import (
	"io"
)

type Curve interface {
	Generate(rand io.Reader) (publicPoint, secret []byte, err error)
	Encaps(publicPoint []byte, rand io.Reader) (ephemeral, sharedSecret []byte, err error)
	Decaps(ephemeral, secret []byte) (sharedSecret []byte, err error)
	Validate(public, secret []byte) error
}
