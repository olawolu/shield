package cryptoutils_test

import (
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/olawolu/shield/cryptoutils"
	"github.com/stretchr/testify/assert"
)

func TestDlogProof(t *testing.T) {
	curve := elliptic.P256()
	x, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		t.Fatalf("%v\n", err)
	}

	Q_x, Q_y := curve.ScalarMult(curve.Params().Gx, curve.Params().Gy, x.Bytes())
	// base := cryptoutils.Point{X: curve.Params().Gx, Y: curve.Params().Gy}
	QPoint := cryptoutils.Point{X: Q_x, Y: Q_y}

	testProof, err := cryptoutils.NewDlogProof(curve, Q_x, Q_y, x)
	if err != nil {
		t.Fatalf("%v\n", err)
	}

	// Q := elliptic.Marshal(curve, Q_x, Q_y)
	status, err := testProof.Verify(curve, QPoint)
	if err != nil {
		t.Fatalf("err : %v\n", err)
	}
	if !status && err == nil {
		t.Logf("x : %v\n", x)
		t.Logf("randPoint : {%v, %v}\n", Q_x, Q_y)
		t.Logf("testProof : %v\n", testProof)
		t.Fatalf("DlogProof did not generate properly - 1\n")
	}
}

func TestPoints(t *testing.T) {
	base1_1 := cryptoutils.BasePoint(elliptic.P256())
	base1_2 := cryptoutils.BasePoint(elliptic.P256())
	assert.Equal(t, base1_1, base1_2)

	base2 := cryptoutils.BasePoint2(elliptic.P256())
	assert.NotEqual(t, base2, base1_2)
}
