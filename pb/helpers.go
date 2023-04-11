package pb

import (
	"math/big"

	"github.com/helicarrierstudio/tss-lib/cryptoutils"
	"github.com/helicarrierstudio/tss-lib/ecdsa"
	"google.golang.org/protobuf/proto"
)

func ProofFromProto(protoProof []byte) (cryptoutils.DlogProof, error) {
	var proof DlogProof
	var dlogProof cryptoutils.DlogProof
	err := proto.Unmarshal(protoProof, &proof)
	if err != nil {
		return dlogProof, err
	}

	base := cryptoutils.Unmarshal(proof.Base)

	randCommit := cryptoutils.Unmarshal(proof.Randcommit)
	publicShare := cryptoutils.Unmarshal(proof.Publicshare)
	dlogProof.Base = base
	dlogProof.Challenge = new(big.Int).SetBytes(proof.Challenge)
	dlogProof.HiddenValue = new(big.Int).SetBytes(proof.Hiddenvalue)
	dlogProof.RandCommit = randCommit
	dlogProof.PublicShare = publicShare
	return dlogProof, nil
}

func ProofToProto(p *cryptoutils.DlogProof) (protoProof []byte, err error) {
	var proof DlogProof
	base := cryptoutils.Marshal(p.Base)
	randCommit := cryptoutils.Marshal(p.RandCommit)
	publicShare := cryptoutils.Marshal(p.PublicShare)

	proof.Base = base
	proof.Challenge = p.Challenge.Bytes()
	proof.Hiddenvalue = p.HiddenValue.Bytes()
	proof.Randcommit = randCommit
	proof.Publicshare = publicShare

	protoProof, err = proto.Marshal(&proof)
	return
}

func EcddhProofFromProto(protoProof []byte) (p *cryptoutils.ECDDHProof, err error) {
	proof := &EcddhProof{}
	err = proto.Unmarshal(protoProof, proof)
	if err != nil {
		return
	}

	a1 := cryptoutils.Unmarshal(proof.A1)
	a2 := cryptoutils.Unmarshal(proof.A2)

	p = &cryptoutils.ECDDHProof{
		A1: a1,
		A2: a2,
		Z:  proof.Z,
	}
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
		DlogProof:               proof,
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
	protoWitness, err := partyOneSecondMessageToProtoMessage(msg)
	if err != nil {
		return nil, err
	}
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

func partyOneSecondMessageToProtoMessage(msg ecdsa.P1KeyGenSecondMsg) (*P1KeyGenSecondMessage, error) {
	protoWitness := commitWitnessToProto(msg.Witness)
	protoWitnessBytes, err := proto.Marshal(protoWitness)
	if err != nil {
		return nil, err
	}
	return &P1KeyGenSecondMessage{
		Witness: protoWitnessBytes,
	}, nil
}

func PartyTwoEphemeralFirstMessageFromProto(p2EphemeralFirstMsg *P2EphemeralKeyGenFirstMessage) ecdsa.P2EphemeralKeyGenFirstMsg {
	return ecdsa.P2EphemeralKeyGenFirstMsg{
		PkCommitment:    new(big.Int).SetBytes(p2EphemeralFirstMsg.Commitment),
		ZkPokCommitment: new(big.Int).SetBytes(p2EphemeralFirstMsg.Commitmentzkp),
	}
}

func PartyTwoEphemeralSecondMessageFromProto(p2EphemeralSecondMsg *P2EphemeralKeyGenSecondMessage) (ecdsa.P2EphemeralKeyGenSecondMsg, error) {
	msg := ecdsa.P2EphemeralKeyGenSecondMsg{}

	witnessBytes := p2EphemeralSecondMsg.GetCommitwitness()
	var witness EphemeralCommitWitness
	err := proto.Unmarshal(witnessBytes, &witness)
	if err != nil {
		return msg, err
	}
	blindFactor := witness.GetPkcommitmentblindfactor()
	zkBlindFactor := witness.GetZkproofblindfactor()
	publicShare := witness.GetPublicshare()
	dLogProof := witness.GetDlogproof()
	proof, err := EcddhProofFromProto(dLogProof)
	if err != nil {
		return msg, err
	}

	c := witness.GetC()
	cPoint := cryptoutils.Unmarshal(c)
	ecdsaWitness := ecdsa.EphemeralCommitWitness{
		PkCommitmentBlindFactor: new(big.Int).SetBytes(blindFactor),
		ZkPokBlindfactor:        new(big.Int).SetBytes(zkBlindFactor),
		PublicShare:             publicShare,
		DlogProof:               *proof,
		C:                       cPoint,
	}
	msg.CommitWitness = ecdsaWitness
	return msg, nil
}
