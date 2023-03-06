package ecdsa

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/getamis/alice/crypto/homo/cl"
	"github.com/golang/protobuf/proto"
	"github.com/helicarrierstudio/tss-lib/cryptoutils"
)

var (
	curve = elliptic.P256()
)

type CommWitness struct {
	PkCommitmentBlindFactor *big.Int
	ZkBlindfactor           *big.Int
	PublicShare             cryptoutils.Point
	DlogProof               cryptoutils.DlogProof
}

type PartyOne struct{}

func NewPartyOne() *PartyOne {
	return &PartyOne{}
}

func (p *PartyOne) CreatePartyOneCommitment() (fm P1KeyGenFirstMsg, commitWitness CommWitness, ecKeyPair EcKeyPair, err error) {
	basePoint := cryptoutils.Point{X: curve.Params().Gx, Y: curve.Params().Gy}

	priv, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		err = fmt.Errorf("cannot generate key pair: %w", err)
		return
	}

	publicShare := cryptoutils.Point{X: x, Y: y}
	dLogProof, err := cryptoutils.NewDlogProof(curve, basePoint, publicShare, new(big.Int).SetBytes(priv))
	if err != nil {
		err = fmt.Errorf("cannot generate dlog proof: %w", err)
		return
	}

	// create commitment to the public key share
	pk := new(big.Int).SetBytes(publicShare.Marshal(curve))
	pk_commitment_blind := cryptoutils.RandomBig(cryptoutils.SECURITY_BITS)
	pk_commitment, err := cryptoutils.CreateCommitmentWithDefinedRandomness(pk, pk_commitment_blind)
	if err != nil {
		err = fmt.Errorf("cannot create commitment: %w", err)
		return
	}

	// create a commitment to the zero-knowledge proof
	zk_commitment_blind := cryptoutils.RandomBig(cryptoutils.SECURITY_BITS)
	pk_rand_commitment := new(big.Int).SetBytes(dLogProof.RandCommit.Marshal(curve))
	zk_commitment, err := cryptoutils.CreateCommitmentWithDefinedRandomness(pk_rand_commitment, zk_commitment_blind)
	if err != nil {
		err = fmt.Errorf("cannot create commitment: %w", err)
		return
	}

	ecKeyPair = EcKeyPair{
		PublicShare: &publicShare,
		secretShare: priv,
	}

	fm = P1KeyGenFirstMsg{
		Commitment:    pk_commitment,
		CommitmentZkp: zk_commitment,
	}

	commitWitness = CommWitness{
		PkCommitmentBlindFactor: pk_commitment_blind,
		ZkBlindfactor:           zk_commitment_blind,
		PublicShare:             publicShare,
		DlogProof:               *dLogProof,
	}
	return
}

func (p *PartyOne) PartyOneVerifyAndDecommit(commitWitness CommWitness, proof cryptoutils.DlogProof) (sm P1KeyGenSecondMsg, err error) {
	status, err := proof.Verify(elliptic.P256(), proof.PublicShare)
	if err != nil {
		return
	}
	if !status {
		err = fmt.Errorf("cannot verify dlog proof")
		return
	}
	sm = P1KeyGenSecondMsg{
		Witness: commitWitness,
	}
	return
}

// GenerateHSMCLKeyPair generates an HSMCL key pair
func (p *PartyOne) GenerateHSMCL(ecKeyPair EcKeyPair, seed *big.Int) (hsmcl HSMCL, hsmclPublic HSMCLPublic, err error) {
	safeParameter := 1348
	c, err := cl.NewCL(big.NewInt(1024), 40, seed, safeParameter, 40)
	if err != nil {
		err = fmt.Errorf("cannot create CL: %w", err)
		return
	}

	// encrypt the secret share with a defined randomness
	ciphertext, err := c.Encrypt(ecKeyPair.secretShare)
	if err != nil {
		err = fmt.Errorf("cannot encrypt: %w", err)
		return
	}

	enryptedMessage := &cl.EncryptedMessage{}
	err = proto.Unmarshal(ciphertext, enryptedMessage)

	proof := enryptedMessage.Proof

	hsmcl = HSMCL{
		Cl:             c,
		EncryptedShare: ciphertext,
	}

	hsmclPublic = HSMCLPublic{
		Proof:          proof,
		CLPublicKey:    c.PublicKey,
		EncryptedShare: ciphertext,
	}

	return
}

// SetPartyOnePrivateKeys sets the private keys for party 1
func (p *PartyOne) SetPartyOnePrivateKeys(p1KeyPair EcKeyPair, pk HSMCL) Party1Private {
	return Party1Private{
		x1:    p1KeyPair.secretShare,
		hsmcl: pk.Cl,
	}
}

func (p *PartyOne) ComputePubKey(p1 Party1Private, p2PublicShare cryptoutils.Point) cryptoutils.Point {
	// compute the public key
	x, y := elliptic.P256().ScalarMult(p2PublicShare.X, p2PublicShare.Y, p1.x1)
	pk := cryptoutils.Point{
		X: x,
		Y: y,
	}
	return pk
}
