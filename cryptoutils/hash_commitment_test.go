package cryptoutils

import (
	"crypto"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBitLength_CreateCommitment(t *testing.T) {
	var commit_len, blind_len int
	hex_len := crypto.SHA256.Size() * 8
	sample_size := 10000

	for i := 1; i < sample_size; i++ {
		message := RandomBig(hex_len)
		commitment, blind_factor, err := CreateCommitment(message)
		if err != nil {
			t.Fatalf("Error creating commitment: %v", err)
		}
		if commitment == nil || blind_factor == nil {
			t.Fatalf("Commitment or blinding factor is nil")
		}
		if commitment.BitLen() == int(hex_len) {
			commit_len++
		}
		if len(blind_factor.Bytes()) == 256 {
			blind_len++
		}
	}

	assert.Greater(t, float32(commit_len)/float32(sample_size), float32(0.3))
	assert.Greater(t, float32(blind_len)/float32(sample_size), float32(0.3))
}

func TestBitLength_CreateCommitmentWithDefinedRandomness(t *testing.T) {
	sec_bits := crypto.SHA256.Size() * 8
	message := RandomBig(sec_bits)

	_, blind_factor, _ := CreateCommitment(message)

	if blind_factor == nil {
		t.Fatalf("blinding factor is nil")
	}

	commitment, err := CreateCommitmentWithDefinedRandomness(message, blind_factor)
	if err != nil {
		t.Fatalf("Error creating commitment: %v", err)
	}
	if commitment == nil {
		t.Fatalf("Commitment is nil")
	}

	assert.LessOrEqual(t, len(commitment.Bytes())/2, sec_bits/8)
}

func TestRandomNumGen_CreateCommitmentWithDefinedRandomness(t *testing.T) {
	message := RandomBig(256)

	commitment1, blind_factor, err := CreateCommitment(message)
	if err != nil {
		t.Fatalf("Error creating commitment: %v", err)
	}

	commitment2, err := CreateCommitmentWithDefinedRandomness(message, blind_factor)
	if err != nil {
		t.Fatalf("Error creating commitment: %v", err)
	}
	assert.Equal(t, commitment1, commitment2)
}

func TestHashing_CreateCommitmentWithDefinedRandomness(t *testing.T) {
	digest := crypto.SHA256.New()
	message := big.NewInt(1)

	commitment, err := CreateCommitmentWithDefinedRandomness(message, big.NewInt(0))
	if err != nil {
		t.Fatalf("Error creating commitment: %v", err)
	}

	if commitment == nil {
		t.Fatalf("Commitment is nil")
	}

	message2 := message.Bytes()
	digest.Write(message2)

	bytes_blinding_factor := big.NewInt(0).Bytes()
	digest.Write(bytes_blinding_factor)

	hash_result := new(big.Int).SetBytes(digest.Sum(nil))

	assert.Equal(t, commitment, hash_result)
}
