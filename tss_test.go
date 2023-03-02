package tss_test

import (
	"testing"

	"github.com/helicarrierstudio/tss-lib/ecdsa"
)

func TestDlogProof(t *testing.T) {
	p1FirstMsg, commitWitness, _, err := ecdsa.CreateCommitment()
	if err != nil {
		t.Errorf("CreateCommitment() failed with error: %s", err)
	}

	p2FirstMsg, _, err := ecdsa.Create()
	if err != nil {
		t.Errorf("Create() failed with error: %s", err)
	}

	p1SecondMsg, err := ecdsa.VerifyAndDecommit(commitWitness, p2FirstMsg.DlogProof)
	if err != nil {
		t.Errorf("VerifyAndDecommit() failed with error: %s", err)
	}

	_, err = ecdsa.VerifyCommitmentAndDlogProof(p1FirstMsg, p1SecondMsg)
	if err != nil {
		t.Errorf("VerifyCommitmentAndDlogProof() failed with error: %s", err)
	}
}

