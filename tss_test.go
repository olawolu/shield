package tss_test

import (
	"testing"

	"github.com/helicarrierstudio/tss-lib/ecdsa"
)

func TestDlogProof(t *testing.T) {
	p1FirstMsg, commitWitness, _, err := ecdsa.CreatePartyOneCommitment()
	if err != nil {
		t.Errorf("CreateCommitment() failed with error: %s", err)
	}

	p2FirstMsg, _, err := ecdsa.PartyTwoCreate()
	if err != nil {
		t.Errorf("Create() failed with error: %s", err)
	}

	p1SecondMsg, err := ecdsa.PartyOneVerifyAndDecommit(commitWitness, p2FirstMsg.DlogProof)
	if err != nil {
		t.Errorf("VerifyAndDecommit() failed with error: %s", err)
	}

	_, err = ecdsa.PartyTwoVerifyCommitmentAndDlogProof(p1FirstMsg, p1SecondMsg)
	if err != nil {
		t.Errorf("VerifyCommitmentAndDlogProof() failed with error: %s", err)
	}
}

func TestFullKeyGeneration(t *testing.T) {
	// p1Firstmessage, commWitness, ecKeyPairParty1, err := ecdsa.CreateCommitment()
	// p2Firstmessage, ecKeyPairParty2, err := ecdsa.Create()
	// p1SecondMessage, err := ecdsa.VerifyAndDecommit(commWitness, p2Firstmessage.DlogProof)
	// if err != nil {
	// 	t.Errorf("FullKeyGeneration() failed with error: %s", err)
	// }
	// p2SecondMessage, err := ecdsa.VerifyCommitmentAndDlogProof(p1Firstmessage, p1SecondMessage)
	// if err != nil {
	// 	t.Errorf("FullKeyGeneration() failed with error: %s", err)
	// }

	// // init paillier keypair
	// paillierKeyPairParty1, err := ecdsa.GeneratePaillierKeyPair(ecKeyPairParty1)
}
