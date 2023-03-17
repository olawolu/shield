package ecdsamobile

import (
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/helicarrierstudio/tss-lib/cryptoutils"
	"github.com/helicarrierstudio/tss-lib/ecdsa"
	"google.golang.org/protobuf/proto"
)

func proofFromProto(protoProof []byte) (p *cryptoutils.DlogProof, err error) {
	var proof DlogProof
	var base, randCommit, publicShare *cryptoutils.Point

	curve := secp256k1.S256()

	err = proto.Unmarshal(protoProof, &proof)
	if err != nil {
		return
	}

	err = base.Unmarshal(curve, proof.Base)
	if err != nil {
		return
	}

	err = randCommit.Unmarshal(curve, proof.Randcommit)
	if err != nil {
		return
	}

	err = publicShare.Unmarshal(curve, proof.Publicshare)
	if err != nil {
		return
	}

	p.Base = *base
	p.Challenge = new(big.Int).SetBytes(proof.Challenge)
	p.HiddenValue = new(big.Int).SetBytes(proof.Hiddenvalue)
	p.RandCommit = *randCommit
	p.PublicShare = *publicShare
	return
}

func proofToProto(p *cryptoutils.DlogProof) (protoProof []byte, err error) {
	var proof DlogProof
	curve := secp256k1.S256()

	proof.Base = p.Base.Marshal(curve)
	proof.Challenge = p.Challenge.Bytes()
	proof.Hiddenvalue = p.HiddenValue.Bytes()
	proof.Randcommit = p.RandCommit.Marshal(curve)
	proof.Publicshare = p.PublicShare.Marshal(curve)

	protoProof, err = proto.Marshal(&proof)
	return
}

func ecddhProofFromProto(protoProof []byte) (p *cryptoutils.ECDDHProof, err error) {
	var proof EcddhProof
	var a1, a2 *cryptoutils.Point

	curve := secp256k1.S256()

	err = proto.Unmarshal(protoProof, &proof)
	if err != nil {
		return
	}

	err = a1.Unmarshal(curve, proof.A1)
	if err != nil {
		return
	}

	err = a2.Unmarshal(curve, proof.A2)
	if err != nil {
		return
	}

	p.A1 = *a1
	p.A2 = *a2
	p.Z = proof.GetZ()
	p.HashChoice = proof.GetHashcoice()
	return
}

func p1FirstMessageFromProto(p1FirstMsg *P1KeyGenFirstMessage) ecdsa.P1KeyGenFirstMsg {
	p1_pk_commitment := p1FirstMsg.Commitment
	p1_pk_commitment_zkp := p1FirstMsg.GetCommitmentzkp()

	return ecdsa.P1KeyGenFirstMsg{
		Commitment:    new(big.Int).SetBytes(p1_pk_commitment),
		CommitmentZkp: new(big.Int).SetBytes(p1_pk_commitment_zkp),
	}
}

func p1SecondMessageFromProto(p1SecondMsg *P1KeyGenSecondMessage) (*ecdsa.P1KeyGenSecondMsg, error) {
	witness := p1SecondMsg.GetWitness()
	blindFactor := witness.GetPkcommitmentblindfactor()
	zkBlindFactor := witness.GetZkblindfactor()
	publicShare := witness.GetPublicshare()
	dLogProof := witness.GetDlogproof()

	proof, err := proofFromProto(dLogProof)
	if err != nil {
		return nil, err
	}

	ecdsaWitness := ecdsa.CommitWitness{
		PkCommitmentBlindFactor: new(big.Int).SetBytes(blindFactor),
		ZkBlindfactor:           new(big.Int).SetBytes(zkBlindFactor),
		PublicShare:             publicShare,
		DlogProof:               *proof,
	}

	return &ecdsa.P1KeyGenSecondMsg{
		Witness: ecdsaWitness,
	}, nil
}
