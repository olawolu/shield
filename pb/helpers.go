package pb

import (
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/helicarrierstudio/tss-lib/cryptoutils"
	"github.com/helicarrierstudio/tss-lib/ecdsa"
	"google.golang.org/protobuf/proto"
)

func ProofFromProto(protoProof []byte) (p *cryptoutils.DlogProof, err error) {
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

func ProofToProto(p *cryptoutils.DlogProof) (protoProof []byte, err error) {
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

func EcddhProofFromProto(protoProof []byte) (p *cryptoutils.ECDDHProof, err error) {
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

func P1FirstMessageFromProto(p1FirstMsg *P1KeyGenFirstMessage) ecdsa.P1KeyGenFirstMsg {
	p1_pk_commitment := p1FirstMsg.Commitment
	p1_pk_commitment_zkp := p1FirstMsg.GetCommitmentzkp()

	return ecdsa.P1KeyGenFirstMsg{
		Commitment:    new(big.Int).SetBytes(p1_pk_commitment),
		CommitmentZkp: new(big.Int).SetBytes(p1_pk_commitment_zkp),
	}
}

func P1SecondMessageFromProto(p1SecondMsg *P1KeyGenSecondMessage) (*ecdsa.P1KeyGenSecondMsg, error) {
	witnessBytes := p1SecondMsg.GetWitness()
	var witness CommitWitness
	err := proto.Unmarshal(witnessBytes, &witness)
	if err != nil {
		return nil, err
	}
	blindFactor := witness.GetPkcommitmentblindfactor()
	zkBlindFactor := witness.GetZkblindfactor()
	publicShare := witness.GetPublicshare()
	dLogProof := witness.GetDlogproof()

	proof, err := ProofFromProto(dLogProof)
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

func ParsePartyOneFirstMessage(msg ecdsa.P1KeyGenFirstMsg) ([]byte, error) {
	protoMsg := partyOneFirstMessageToProtoMessage(msg)
	return proto.Marshal(protoMsg)
}

func partyOneFirstMessageToProtoMessage(msg ecdsa.P1KeyGenFirstMsg) *P1KeyGenFirstMessage {
	return &P1KeyGenFirstMessage{
		Commitment:    msg.Commitment.Bytes(),
		Commitmentzkp: msg.CommitmentZkp.Bytes(),
	}
}

func ParsePartyOneSecondMessage(msg ecdsa.P1KeyGenSecondMsg) ([]byte, error) {
	protoWitness := commitWitnessToProto(msg.Witness)
	return proto.Marshal(protoWitness)
}

func commitWitnessToProto(witness ecdsa.CommitWitness) *CommitWitness {
	protoWitness := &CommitWitness{
		Pkcommitmentblindfactor: witness.PkCommitmentBlindFactor.Bytes(),
		Zkblindfactor:           witness.ZkBlindfactor.Bytes(),
		Publicshare:             witness.PublicShare,
	}

	protoDlogProof, err := ProofToProto(&witness.DlogProof)
	if err != nil {
		panic(err)
	}
	protoWitness.Dlogproof = protoDlogProof

	return protoWitness
}
