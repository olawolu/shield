package ecdsa

import (
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/didiercrunch/paillier"
	"github.com/helicarrierstudio/tss-lib/cryptoutils"
)

// KeyGenFirstMsg is the first message sent during key generation.
type P1KeyGenFirstMsg struct {
	Commitment    *big.Int
	CommitmentZkp *big.Int
}

// KeyGenSecondMsg is the second message sent during key generation.
type P1KeyGenSecondMsg struct {
	Witness CommitWitness
}

type P2KeyGenFirstMsg struct {
	DlogProof   cryptoutils.DlogProof
	PublicShare []byte
}

type P2KeyGenSecondMsg struct{}

type PaillierKeyPair struct {
	EncryptionKey  *paillier.PublicKey
	DecryptionKey  *paillier.PrivateKey
	EncryptedShare *paillier.Cypher
	Randomness     *big.Int
}

type EphemeralCommitWitness struct {
	PkCommitmentBlindFactor *big.Int
	ZkPokBlindfactor        *big.Int
	PublicShare             []byte
	DlogProof               cryptoutils.ECDDHProof
	C                       cryptoutils.Point // C= secretShare*basePoint2
}

type P1EphemeralKeyGenFirstMsg struct {
	DlogProof   cryptoutils.ECDDHProof
	PublicShare secp256k1.PublicKey
	C           cryptoutils.Point
}

type P1EphemeralKeyGenSecondMsg struct{}

type P2EphemeralKeyGenFirstMsg struct {
	PkCommitment    *big.Int
	ZkPokCommitment *big.Int
}

type P2EphemeralKeyGenSecondMsg struct {
	CommitWitness EphemeralCommitWitness
}

type EphEcKeyPair struct {
	PublicShare []byte
	SecretShare []byte
}

type PartialSignature struct {
	C3 *paillier.Cypher
}
