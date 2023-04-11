package cryptoutils

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
)

type ECDDHProof struct {
	A1         Point
	A2         Point
	Z          []byte
	HashChoice []byte
}

type ECDDHStatement struct {
	G1 Point
	H1 Point
	G2 Point
	H2 Point
}

type ECDDHWitness struct {
	X []byte
}

func NewEcddhProof(curve elliptic.Curve, w ECDDHWitness, delta ECDDHStatement) (*ECDDHProof, error) {
	s, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		return nil, fmt.Errorf("error generating random number: %s", err)
	}

	a1_x, a1_y := curve.ScalarMult(delta.G1.X, delta.G1.Y, s.Bytes())
	a2_x, a2_y := curve.ScalarMult(delta.G2.X, delta.G2.Y, s.Bytes())

	challenge := hashChallenge(elliptic.Marshal(curve, delta.G1.X, delta.G1.Y), elliptic.Marshal(curve, delta.H1.X, delta.H1.Y), elliptic.Marshal(curve, delta.G2.X, delta.G2.Y), elliptic.Marshal(curve, delta.H2.X, delta.H2.Y), elliptic.Marshal(curve, a1_x, a1_y), elliptic.Marshal(curve, a2_x, a2_y))

	z := new(big.Int).Add(s, new(big.Int).Mul(challenge, new(big.Int).SetBytes(w.X)))
	proof := &ECDDHProof{
		A1: Point{a1_x, a1_y},
		A2: Point{a2_x, a2_y},
		Z:  z.Bytes(),
	}

	return proof, nil
}

func Verify(curve elliptic.Curve, proof ECDDHProof, delta ECDDHStatement) (bool, error) {
	var valid bool
	var err error

	challenge := hashChallenge(elliptic.Marshal(curve, delta.G1.X, delta.G1.Y), elliptic.Marshal(curve, delta.H1.X, delta.H1.Y), elliptic.Marshal(curve, delta.G2.X, delta.G2.Y), elliptic.Marshal(curve, delta.H2.X, delta.H2.Y), elliptic.Marshal(curve, proof.A1.X, proof.A1.Y), elliptic.Marshal(curve, proof.A2.X, proof.A2.Y))

	z := new(big.Int).SetBytes(proof.Z)
	z1_x, z1_y := curve.ScalarMult(delta.G1.X, delta.G1.Y, z.Bytes())
	z2_x, z2_y := curve.ScalarMult(delta.G2.X, delta.G2.Y, z.Bytes())
	z1 := Point{z1_x, z1_y}
	z2 := Point{z2_x, z2_y}

	d1_x, d1_y := curve.ScalarMult(delta.H1.X, delta.H1.Y, challenge.Bytes())
	d2_x, d2_y := curve.ScalarMult(delta.H2.X, delta.H2.Y, challenge.Bytes())

	j1_x, j1_y := curve.Add(proof.A1.X, proof.A1.Y, d1_x, d1_y)
	j2_x, j2_y := curve.Add(proof.A2.X, proof.A2.Y, d2_x, d2_y)
	j1 := Point{j1_x, j1_y}
	j2 := Point{j2_x, j2_y}

	if z1.Equal(j1) && z2.Equal(j2) {
		valid = true
	} else {
		valid = false
		err = fmt.Errorf("ECDDH proof verification failed")
	}

	return valid, err
}
