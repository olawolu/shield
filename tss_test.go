package tss_test

import (
	"math/big"
	"testing"

	"github.com/helicarrierstudio/tss-lib/ecdsa"
	"github.com/stretchr/testify/assert"
)

func TestDlogProof(t *testing.T) {
	p1 := ecdsa.NewPartyOne()
	p2 := ecdsa.NewPartyTwo()

	p1FirstMsg, commitWitness, _, err := p1.CreatePartyOneCommitment()
	assert.NoError(t, err)

	p2FirstMsg, _, err := p2.PartyTwoCreate()
	assert.NoError(t, err)

	p1SecondMsg, err := p1.PartyOneVerifyAndDecommit(commitWitness, p2FirstMsg.DlogProof)
	assert.NoError(t, err)

	_, err = p2.PartyTwoVerifyCommitmentAndDlogProof(p1FirstMsg, p1SecondMsg)
	assert.NoError(t, err)
}

func TestFullKeyGeneration(t *testing.T) {
	p1 := ecdsa.NewPartyOne()
	p2 := ecdsa.NewPartyTwo()

	p1Firstmessage, commWitness, ecKeyPairParty1, err := p1.CreatePartyOneCommitment()
	assert.NoError(t, err)

	p2Firstmessage, ecKeyPairParty2, err := p2.PartyTwoCreate()
	assert.NoError(t, err)

	p1SecondMessage, err := p1.PartyOneVerifyAndDecommit(commWitness, p2Firstmessage.DlogProof)
	assert.NoError(t, err)

	_, err = p2.PartyTwoVerifyCommitmentAndDlogProof(p1Firstmessage, p1SecondMessage)
	assert.NoError(t, err)

	// init HSMCL keypair
	str := "115792089237316195423570985008687907852837564279074904382605163141518161494337"
	seed, ok := new(big.Int).SetString(str, 10)
	if !ok {
		t.Error("FullKeyGeneration() bad seed")
	}
	hsmcl, hsmclPublic, err := p1.GenerateHSMCL(ecKeyPairParty1, seed)
	if err != nil {
		t.Errorf("FullKeyGeneration() failed with error: %s", err)
	}

	// p1 sends p2 hsmcl_public
	p1Private := p1.SetPartyOnePrivateKeys(ecKeyPairParty1, hsmcl)
	_, err = p2.VerifySetupAndZkcldlProof(hsmclPublic, seed, p1SecondMessage.Witness.PublicShare)
	assert.NoError(t, err)

	// p2Private := p2.SetPartyTwoPrivateKeys(ecKeyPairParty2)
	assert.NotEqual(t, p2Firstmessage.PublicShare, p1SecondMessage.Witness.PublicShare)

	pk1 := p1.ComputePubKey(p1Private, p2Firstmessage.PublicShare)
	pk2 := p2.ComputePubKey(ecKeyPairParty2, p1SecondMessage.Witness.PublicShare)

	assert.Equal(t, pk1, pk2)
}
