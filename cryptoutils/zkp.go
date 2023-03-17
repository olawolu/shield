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

func NewPoint(x, y *big.Int) Point {
	return Point{X: x, Y: y}
}

func BasePoint(curve elliptic.Curve) Point {
	return Point{X: curve.Params().Gx, Y: curve.Params().Gy}
}

// BasePoint2 returns a random point on the curve with unknown discrete log
func BasePoint2(curve elliptic.Curve) Point {
	hasher := sha256.New()
	x := new(big.Int).SetBytes([]byte{0x08, 0xd1, 0x32, 0x21, 0xe3, 0xa7, 0x32, 0x6a, 0x34, 0xdd, 0x45, 0x21, 0x4b, 0xa8, 0x01, 0x16,
		0xdd, 0x14, 0x2e, 0x4b, 0x5f, 0xf3, 0xce, 0x66, 0xa8, 0xdc, 0x7b, 0xfa, 0x03, 0x78, 0xb7, 0x95,
	})
	hashedString := hasher.Sum(x.Bytes())
	hashedString = hasher.Sum(hashedString)
	Hx, Hy := curve.ScalarMult(curve.Params().Gx, curve.Params().Gy, hashedString)
	if !curve.IsOnCurve(Hx, Hy) {
		panic("not on curve")
	}
	return Point{X: Hx, Y: Hy}
}

// Equal returns true if points p (self) and p2 (arg) are the same.
func (p *Point) Equal(p2 Point) bool {
	if p.X.Cmp(p2.X) == 0 && p2.Y.Cmp(p2.Y) == 0 {
		return true
	}
	return false
}

func (p *Point) Marshal(curve elliptic.Curve) []byte {
	return elliptic.Marshal(curve, p.X, p.Y)
}

func (p *Point) Unmarshal(curve elliptic.Curve, data []byte) error {
	// curve.ScalarBaseMult(data)
	x, y := elliptic.Unmarshal(curve, data)
	if x == nil {
		return errors.New("invalid point")
	}
	p.X = x
	p.Y = y
	return nil
}

func (p Point) Chain(curve elliptic.Curve, p2 Point) []byte {
	buf := new(bytes.Buffer)
	buf.Write(p.Marshal(curve))
	buf.Write(p2.Marshal(curve))
	hash := sha256.New().Sum(buf.Bytes())

	return hash
}

type DlogProof struct {
	Base        Point
	Challenge   *big.Int
	RandCommit  Point
	PublicShare Point
	HiddenValue *big.Int
}

func NewDlogProof(curve elliptic.Curve, x, y, sk *big.Int) (*DlogProof, error) {
	modValue := new(big.Int).Mod(sk, curve.Params().N)

	// Q = sk * G where Q{Q_x, Q_y} is the public key,
	// G => curve generator, sk => secret key
	Q_x, Q_y := curve.ScalarBaseMult(modValue.Bytes())
	if Q_x.Cmp(x) != 0 || Q_y.Cmp(y) != 0 {
		return nil, errors.New("Q is not equal to xG")
	}

	// generates a randam point uG,
	// where u => random integer in the field and G => curve generator
	// uG{pk_rand_x, pk_rand_y} is a random point on the curve
	u, _ := rand.Int(rand.Reader, curve.Params().N)
	pk_rand_x, pk_rand_y := curve.ScalarBaseMult(u.Bytes())
	pk_rand_commitment := elliptic.Marshal(curve, pk_rand_x, pk_rand_y)
	pk_rand := Point{pk_rand_x, pk_rand_y}

	q_bytes := elliptic.Marshal(curve, x, y)
	challenge := generateChallenge(curve.Params(), q_bytes, pk_rand_commitment)

	// v = u - c * x
	v := new(big.Int).Sub(u, new(big.Int).Mul(challenge, modValue))
	v = v.Mod(v, curve.Params().N)

	dlp := &DlogProof{
		Base:        Point{curve.Params().Gx, curve.Params().Gy},
		RandCommit:  pk_rand,
		HiddenValue: v,
		PublicShare: Point{x, y},
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

func hashChallenge(arr ...[]byte) *big.Int {
	hasher := sha256.New()
	for _, v := range arr {
		hasher.Write(v)
	}
	challenge := new(big.Int).SetBytes(hasher.Sum(nil))
	return challenge
}

// Verify verifies the proof of knowledge of discrete logarithm of an elliptic curve point. Q is the public key.
func (proof *DlogProof) Verify(curve elliptic.Curve, Q Point) (bool, error) {
	rand_commit := elliptic.Marshal(curve, proof.RandCommit.X, proof.RandCommit.Y)
	q_bytes := elliptic.Marshal(curve, Q.X, Q.Y)
	// Q = xG where Q{pk_x, pk_y} is the public key, RandCommit = uG
	testChallenge := generateChallenge(curve.Params(), q_bytes, rand_commit)

	if testChallenge.Cmp(proof.Challenge) != 0 {
		return false, errors.New("challenge is not equal to the generated challenge")
	}

	// look at hiddenValue as u from the proof (u - c * x)G
	// baseBytes := elliptic.Marshal(curve, proof.Base.X, proof.Base.Y)
	x, y := proof.Base.X, proof.Base.Y
	uG_x, uG_y := curve.ScalarMult(x, y, proof.HiddenValue.Bytes())

	cx, cy := curve.ScalarMult(Q.X, Q.Y, proof.Challenge.Bytes())

	tot_x, tot_y := curve.Add(uG_x, uG_y, cx, cy)
	tot := elliptic.Marshal(curve, tot_x, tot_y)

	if !bytes.Equal(tot, rand_commit) {
		return false, errors.New("proof's final value and verification value do not agree")
	}

	return true, nil
}
