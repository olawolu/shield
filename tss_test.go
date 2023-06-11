package shield_test

import (
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/olawolu/shield"
	"github.com/olawolu/shield/pb"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func TestDlogProof(t *testing.T) {
	p1FirstMsg, witness, secret, err := shield.CreatePartyOneCommitment()
	assert.NoError(t, err)
	assert.NotEmpty(t, p1FirstMsg)
	assert.NotEmpty(t, secret)
	assert.NotEmpty(t, witness)

	p2FirstMsg, _, err := shield.CreatePartyTwoShares()
	assert.NoError(t, err)

	p1SecondMsg, err := shield.PartyOneVerifyAndDecommit(p2FirstMsg.DlogProof, witness)
	assert.NoError(t, err)

	err = shield.PartyTwoVerifyCommitmentAndDlogProof(p1FirstMsg, p1SecondMsg)
	assert.NoError(t, err)
}

func TestFullKeyGeneration(t *testing.T) {
	// Round 1
	p1FirstMsg, witness, p1_secret, err := shield.CreatePartyOneCommitment()
	assert.NoError(t, err)

	p2Firstmessage, p2_secret, err := shield.CreatePartyTwoShares()
	assert.NoError(t, err)

	p1SecondMessage, err := shield.PartyOneVerifyAndDecommit(p2Firstmessage.DlogProof, witness)
	assert.NoError(t, err)
	assert.NotEmpty(t, p1SecondMessage.Witness.PublicShare)
	elliptic.P256()

	// Round 2 - party 1 sends party 2 its decomitted value
	err = shield.PartyTwoVerifyCommitmentAndDlogProof(p1FirstMsg, p1SecondMessage)
	assert.NoError(t, err)
	assert.NotEqual(t, p2Firstmessage.PublicShare, p1SecondMessage.Witness.PublicShare)

	// Round 3 - party 1 generates a paillier key pair and encrypts its secret share
	// party 1 sends its encrypted share to party 2 together with the paillier public key

	// Round 4 - both parties compute the public key and party 2 stores party 1's paillier public key and encrypted share
	p2_public_share, err := secp256k1.ParsePubKey(p2Firstmessage.PublicShare)
	assert.NoError(t, err)
	pk1, err := shield.ComputePubKey(p2_public_share, p1_secret)
	assert.NoError(t, err)

	p1_public_share, err := secp256k1.ParsePubKey(p1SecondMessage.Witness.PublicShare)
	assert.NoError(t, err)
	pk2, err := shield.ComputePubKey(p1_public_share, p2_secret)
	assert.NoError(t, err)

	fmt.Println("pk1: ", pk1)
	fmt.Println("pk2: ", pk2)

	assert.Equal(t, pk1, pk2)
}

func TestTwoPartySign(t *testing.T) {
	_, witness, p1_secret, err := shield.CreatePartyOneCommitment()
	assert.NoError(t, err)

	p2_private_share_gen, p2_secret, err := shield.CreatePartyTwoShares()
	assert.NoError(t, err)

	p1SecondMessage, err := shield.PartyOneVerifyAndDecommit(p2_private_share_gen.DlogProof, witness)
	assert.NoError(t, err)

	// Party 1 generates the Paillier key pair and encrypts it's secret share
	paillier_key_pair, err := shield.GeneratePaillierKeyPairAndEncryptedShare(p1_secret)
	assert.NoError(t, err)
	assert.NotNil(t, paillier_key_pair)

	// start signing
	// create ephemeral private shares for party 2
	// The goal is to generate a common random number for both parties to generate the r field of the signature
	p2_eph_first_msg, eph_comm_witness, eph_ec_key_pair_p2, err := shield.CreateEphemeralCommitments()
	assert.NoError(t, err)

	// create ephemeral private shares for party 1
	eph_p1_first_msg, eph_ec_key_pair_p1, err := shield.CreateEphemeralKey()
	assert.NoError(t, err)

	eph_p2_secondMsg, err := shield.VerifyEphemeralKeyAndDecommit(eph_p1_first_msg, eph_comm_witness)
	assert.NoError(t, err)
	assert.NotEmpty(t, eph_p2_secondMsg)

	_, err = shield.VerifyEphemeralCommitmentAndProof(p2_eph_first_msg, eph_p2_secondMsg)
	assert.NoError(t, err)

	// public key computed by party 1
	p2_public_share, err := secp256k1.ParsePubKey(p2_private_share_gen.PublicShare)
	assert.NoError(t, err)
	pubKey, err := shield.ComputePubKey(p2_public_share, p1_secret)
	assert.NoError(t, err)

	// public key computed by party 2
	p1_public_share, err := secp256k1.ParsePubKey(p1SecondMessage.Witness.PublicShare)
	assert.NoError(t, err)
	pubKey2, err := shield.ComputePubKey(p1_public_share, p2_secret)
	assert.NoError(t, err)

	assert.Equal(t, pubKey, pubKey2)

	// message := big.NewInt(1234567890)
	destination, _ := hex.DecodeString("0x43B7D573c88BB0c4165f7831d9A14657906F689A")
	msg := pb.Transaction{
		ChainId:     []byte{byte(1)},
		Nonce:       []byte{byte(1)},
		Destination: destination,
		Amount:      []byte{byte(100)},
		GasLimit:    []byte{byte(100)},
	}

	message, _ := proto.Marshal(&msg)

	// fmt.Println("key", paillier_key_pair.EncryptionKey)
	partial_sig, err := shield.ComputePartialSignature(paillier_key_pair, paillier_key_pair.EncryptionKey, paillier_key_pair.EncryptedShare, eph_ec_key_pair_p2, eph_p1_first_msg.PublicShare, message, p2_secret)
	assert.NoError(t, err)
	assert.NotEmpty(t, partial_sig)

	signature, err := shield.ComputeSignature(partial_sig, eph_ec_key_pair_p1, eph_p2_secondMsg.CommitWitness.PublicShare, paillier_key_pair.DecryptionKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, signature)

	ok := shield.VerifySignature(signature, pubKey, message)
	assert.True(t, ok)
}
