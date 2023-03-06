package ecdsa

import (
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/helicarrierstudio/tss-lib/cryptoutils"
)

type PartyTwo struct{}

func NewPartyTwo() *PartyTwo {
	return &PartyTwo{}
}

func (p *PartyTwo) PartyTwoCreate() (fm P2KeyGenFirstMsg, ecKeyPair EcKeyPair, err error) {
	curve := elliptic.P256()
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

	ecKeyPair = EcKeyPair{
		PublicShare: &publicShare,
		secretShare: priv,
	}

	fm = P2KeyGenFirstMsg{
		DlogProof:   *dLogProof,
		PublicShare: publicShare,
	}
	return
}

func (p *PartyTwo) PartyTwoVerifyCommitmentAndDlogProof(p1FirstMsg P1KeyGenFirstMsg, p1SecondMsg P1KeyGenSecondMsg) (sm P2KeyGenSecondMsg, err error) {
	p1_pk_commitment := p1FirstMsg.Commitment
	p1_pk_commitment_zkp := p1FirstMsg.CommitmentZkp
	p1_zk_blind_factor := p1SecondMsg.Witness.ZkBlindfactor
	p1_pub_share := p1SecondMsg.Witness.PublicShare
	p1_pk_commitment_bf := p1SecondMsg.Witness.PkCommitmentBlindFactor
	p1_dlog_proof := p1SecondMsg.Witness.DlogProof

	flag := true

	p1_pub_share_commit, err := cryptoutils.CreateCommitmentWithDefinedRandomness(new(big.Int).SetBytes(p1_pub_share.Marshal(curve)), p1_pk_commitment_bf)
	if err != nil {
		err = fmt.Errorf("cannot verify commitment: %w", err)
		return
	}

	if p1_pk_commitment.Cmp(p1_pub_share_commit) != 0 {
		flag = false
	}

	fmt.Printf("flag: %v\n", flag)

	p1_zk_commit, err := cryptoutils.CreateCommitmentWithDefinedRandomness(new(big.Int).SetBytes(p1_dlog_proof.RandCommit.Marshal(curve)), p1_zk_blind_factor)
	if err != nil {
		err = fmt.Errorf("cannot verify commitment: %w", err)
		return
	}

	if p1_pk_commitment_zkp.Cmp(p1_zk_commit) != 0 {
		fmt.Println("p1_pk_commitment_zkp: ", p1_pk_commitment_zkp)
		fmt.Println("p1_zk_commit: ", p1_zk_commit)
		flag = false
	}

	fmt.Printf("flag: %v\n", flag)

	if !flag {
		err = errors.New("cannot verify proof")
		return
	}

	ok, err := p1_dlog_proof.Verify(curve, p1_pub_share)
	if err != nil || !ok {
		err = fmt.Errorf("cannot verify dlog proof, err: %w", err)

	}

	return
}

// VerifySetupAndZkcldlProof verifies the setup and the zero-knowledge proof
func (p *PartyTwo) VerifySetupAndZkcldlProof(hsmclPublic HSMCLPublic, seed *big.Int, p1PublicKey cryptoutils.Point) (p2hsmcl *PartyTwoHSMCLPublic, err error) {
	// verify the public key setup
	if err = hsmclPublic.CLPublicKey.Verify(); err != nil {
		err = fmt.Errorf("cannot verify the public key setup: %w", err)
		return
	}

	if err = hsmclPublic.CLPublicKey.VerifyEnc(hsmclPublic.EncryptedShare); err != nil {
		err = fmt.Errorf("cannot verify proof: %w", err)
		return
	}

	p2hsmcl = &PartyTwoHSMCLPublic{
		EncryptionKey:  hsmclPublic.CLPublicKey,
		EncryptedShare: hsmclPublic.EncryptedShare,
	}

	return
}


// SetPartyOnePrivateKeys sets the private keys for party 1
func (p *PartyTwo) SetPartyTwoPrivateKeys(ecKey EcKeyPair) Party2Private {
	return Party2Private{
		x1:    ecKey.secretShare,
	}
}

func (p *PartyTwo) ComputePubKey(local EcKeyPair, otherPartyPublicShare cryptoutils.Point) cryptoutils.Point {
	// compute the public key
	x, y := elliptic.P256().ScalarMult(otherPartyPublicShare.X, otherPartyPublicShare.Y, local.secretShare)
	pk := cryptoutils.Point{
		X: x,
		Y: y,
	}
	return pk
}