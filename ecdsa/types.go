package ecdsa

import (
	"math/big"

	"github.com/getamis/alice/crypto/homo/cl"
	"github.com/helicarrierstudio/tss-lib/cryptoutils"
)

type EcKeyPair struct {
	PublicShare *cryptoutils.Point
	secretShare []byte
}

// KeyGenFirstMsg is the first message sent during key generation.
type P1KeyGenFirstMsg struct {
	Commitment    *big.Int
	CommitmentZkp *big.Int
}

// KeyGenSecondMsg is the second message sent during key generation.
type P1KeyGenSecondMsg struct {
	Witness CommWitness
}

type P2KeyGenFirstMsg struct {
	DlogProof   cryptoutils.DlogProof
	PublicShare cryptoutils.Point
}

type P2KeyGenSecondMsg struct{}

type HSMCL struct {
	Cl             *cl.CL
	EncryptedShare []byte
}

type HSMCLPublic struct {
	CLPublicKey    *cl.PublicKey
	Proof          *cl.ProofMessage
	EncryptedShare []byte
}

type PartyTwoHSMCLPublic struct {
	EncryptionKey  *cl.PublicKey
	EncryptedShare []byte
}

type Party1Private struct {
	x1    []byte
	hsmcl *cl.CL
}

type Party2Private struct {
	x1 []byte
}
