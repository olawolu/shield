package cryptoutils_test

import (
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/helicarrierstudio/tss-lib/cryptoutils"
)

func TestDlogProof(t *testing.T) {
	curve := elliptic.P256()
	x, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		t.Fatalf("%v\n", err)
	}

	Q_x, Q_y := curve.ScalarMult(curve.Params().Gx, curve.Params().Gy, x.Bytes())
	base := cryptoutils.Point{X: curve.Params().Gx, Y: curve.Params().Gy}
	QPoint := cryptoutils.Point{X: Q_x, Y: Q_y}

	testProof, err := cryptoutils.NewDlogProof(curve, base, QPoint, x)
	if err != nil {
		t.Fatalf("%v\n", err)
	}

	// Q := elliptic.Marshal(curve, Q_x, Q_y)
	status, tot, err := testProof.Verify(curve, cryptoutils.Point{Q_x, Q_y})
	if err != nil {
		t.Fatalf("err : %v\n tot : %v\n", err, tot)
	}
	if !status && err == nil {
		t.Logf("x : %v\n", x)
		t.Logf("randPoint : {%v, %v}\n", Q_x, Q_y)
		t.Logf("testProof : %v\n", testProof)
		t.Logf("tot : %v\n", tot)
		t.Fatalf("DlogProof did not generate properly - 1\n")
	}
}
