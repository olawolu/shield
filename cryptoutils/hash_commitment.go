package cryptoutils

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

type HashCommitment struct{}

const SECURITY_BITS int = 256

func CreateCommitment(message *big.Int) (commitment, blind_factor *big.Int, err error) {
	blind_factor = RandomBig(SECURITY_BITS)
	commitment, err = CreateCommitmentWithDefinedRandomness(message, blind_factor)
	return
}

func CreateCommitmentWithDefinedRandomness(message, randomness *big.Int) (*big.Int, error) {
	digest := sha256.New()
	_, err := digest.Write(message.Bytes())
	if err != nil {
		return nil, err
	}
	_, err = digest.Write(randomness.Bytes())
	if err != nil {
		return nil, err
	}
	comm := new(big.Int).SetBytes(digest.Sum(nil))
	return comm, nil
}

func RandomBig(size int) *big.Int {
	token := make([]byte, size)
	rand.Read(token)
	return new(big.Int).SetBytes(token)
}
