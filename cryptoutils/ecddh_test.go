package cryptoutils_test

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/helicarrierstudio/tss-lib/cryptoutils"
	"github.com/stretchr/testify/assert"
)

func TestEcddhProof(t *testing.T) {
	curve := elliptic.P256()
	x, _ := rand.Int(rand.Reader, curve.Params().N)

	// Q_x, Q_y := curve.ScalarMult(curve.Params().Gx, curve.Params().Gy, x.Bytes())
	base := cryptoutils.BasePoint(curve)
	basePoint2 := cryptoutils.BasePoint2(curve)

	h1_x, h1_y := curve.ScalarBaseMult(x.Bytes())
	h2_x, h2_y := curve.ScalarMult(basePoint2.X, basePoint2.Y, x.Bytes())

	delta := cryptoutils.ECDDHStatement{
		G1: base,
		G2: basePoint2,
		H1: cryptoutils.NewPoint(h1_x, h1_y),
		H2: cryptoutils.NewPoint(h2_x, h2_y),
	}

	witness := cryptoutils.ECDDHWitness{
		X: x.Bytes(),
	}

	proof, err := cryptoutils.NewEcddhProof(curve, &witness, &delta)
	assert.Nil(t, err)

	ok, err := proof.Verify(curve, &delta)
	assert.Nil(t, err)
	assert.True(t, ok)
}

func TestWrongEcddhProof(t *testing.T) {
	curve := elliptic.P256()
	x, _ := rand.Int(rand.Reader, curve.Params().N)
	x2, _ := rand.Int(rand.Reader, curve.Params().N)

	assert.NotEqual(t, x, x2)

	base := cryptoutils.BasePoint(curve)

	randx, _ := rand.Int(rand.Reader, big.NewInt(63))

	basePoint2 := cryptoutils.BasePoint2(curve)

	m, n := curve.ScalarMult(basePoint2.X, basePoint2.Y, randx.Bytes())

	h1_x, h1_y := curve.ScalarMult(base.X, base.Y, x.Bytes())

	h2_x, h2_y := curve.ScalarMult(m, n, x2.Bytes())

	delta := cryptoutils.ECDDHStatement{
		G1: base,
		G2: basePoint2,
		H1: cryptoutils.Point{X: h1_x, Y: h1_y},
		H2: cryptoutils.Point{X: h2_x, Y: h2_y},
	}

	witness := cryptoutils.ECDDHWitness{
		X: x.Bytes(),
	}

	proof, err := cryptoutils.NewEcddhProof(curve, &witness, &delta)
	assert.Nil(t, err)

	ok, err := proof.Verify(curve, &delta)
	assert.NotNil(t, err)
	assert.False(t, ok)
}
