package cryptoutils

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
)

// This is an implementation of Schnorr's identification protocl for elliptic
// curve groups for proof of knowledge of discrete logarithm of an elliptic curve point.
// Adapted from https://github.com/ZenGo-X/curv/blob/master/src/cryptographic_primitives/proofs/sigma_dlog.rs

type curveParams *elliptic.CurveParams
type Point struct {
	X, Y *big.Int
}

// Equal returns true if points p (self) and p2 (arg) are the same.
func (p Point) Equal(p2 Point) bool {
	if p.X.Cmp(p2.X) == 0 && p2.Y.Cmp(p2.Y) == 0 {
		return true
	}
	return false
}

func (p Point) Marshal(curve elliptic.Curve) []byte {
	return elliptic.Marshal(curve, p.X, p.Y)
}

type DlogProof struct {
	Base        Point
	RandCommit  Point
	HiddenValue *big.Int
	Challenge   *big.Int
}

func NewDlogProof(curve elliptic.Curve, base, Q Point, sk *big.Int) (*DlogProof, error) {
	// curve := elliptic.P256()
	modValue := new(big.Int).Mod(sk, curve.Params().N)

	// Q = xG where Q{Q_x, Q_y} is the public key
	Q_x, Q_y := curve.ScalarMult(base.X, base.Y, modValue.Bytes())
	C := Point{Q_x, Q_y}
	if !C.Equal(Q) {
		return nil, errors.New("Q is not equal to xG")
	}

	// generates a randam point uG,
	// where u => sk_rand and G => curve generator
	// uG{pk_rand_x, pk_rand_y} is a random point on the curve
	sk_rand, _ := rand.Int(rand.Reader, curve.Params().N)
	pk_rand_x, pk_rand_y := curve.ScalarMult(base.X, base.Y, sk_rand.Bytes())
	pk_rand_commitment := elliptic.Marshal(curve, pk_rand_x, pk_rand_y)
	pk_rand := Point{pk_rand_x, pk_rand_y}

	// A = xG where A{pk_x, pk_y} is the public key
	// pk_x, pk_y := curve.ScalarMult(base.X, base.Y, sk.Bytes())
	// pk_commitment := elliptic.Marshal(curve, pk_x, pk_y)

	q_bytes := elliptic.Marshal(curve, Q.X, Q.Y)

	challenge := generateChallenge(curve.Params(), q_bytes, pk_rand_commitment)

	// v = u - c * x
	v := new(big.Int).Sub(sk_rand, new(big.Int).Mul(challenge, modValue))
	v = v.Mod(v, curve.Params().N)

	dlp := &DlogProof{
		Base:        base,
		RandCommit:  pk_rand,
		HiddenValue: v,
		Challenge:   challenge,
	}
	return dlp, nil
}

func generateChallenge(curveParams curveParams, arr ...[]byte) *big.Int {
	hasher := sha256.New()
	for _, v := range arr {
		hasher.Write(v)
	}
	challenge := new(big.Int).SetBytes(hasher.Sum(nil))
	challenge = new(big.Int).Mod(challenge, curveParams.N)
	return challenge
}

func (proof *DlogProof) Verify(curve elliptic.Curve, Q Point) (bool, []byte, error) {
	rand_commit := elliptic.Marshal(curve, proof.RandCommit.X, proof.RandCommit.Y)
	q_bytes := elliptic.Marshal(curve, Q.X, Q.Y)
	// Q = xG where Q{pk_x, pk_y} is the public key, RandCommit = uG
	testChallenge := generateChallenge(curve.Params(), q_bytes, rand_commit)

	if testChallenge.Cmp(proof.Challenge) != 0 {
		return false, nil, errors.New("challenge is not equal to the generated challenge")
	}

	// look at hiddenValue as u from the proof (u - c * x)G
	// baseBytes := elliptic.Marshal(curve, proof.Base.X, proof.Base.Y)
	x, y := proof.Base.X, proof.Base.Y
	uG_x, uG_y := curve.ScalarMult(x, y, proof.HiddenValue.Bytes())

	cx, cy := curve.ScalarMult(Q.X, Q.Y, proof.Challenge.Bytes())

	tot_x, tot_y := curve.Add(uG_x, uG_y, cx, cy)
	tot := elliptic.Marshal(curve, tot_x, tot_y)

	if !bytes.Equal(tot, rand_commit) {
		return false, nil, errors.New("proof's final value and verification value do not agree")
	}

	return true, tot, nil
}
