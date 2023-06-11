package shield

import (
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/olawolu/shield/cryptoutils"
)

func NewKeyWithProof() (*secp256k1.PrivateKey, *cryptoutils.DlogProof, error) {
	privateKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		err = fmt.Errorf("cannot generate key pair: %w", err)
		return nil, nil, err
	}

	privateShare := privateKey.Serialize()
	publicShare := privateKey.PubKey()

	proof, err := cryptoutils.NewDlogProof(curve, publicShare.X(), publicShare.Y(), new(big.Int).SetBytes(privateShare))
	if err != nil {
		err = fmt.Errorf("cannot generate dlog proof: %w", err)
		return nil, nil, err
	}

	return privateKey, proof, nil
}

func ComputePubKey(otherPartyPublicShare *secp256k1.PublicKey, secretShare []byte) ([]byte, error) {
	// compute the public key
	x, y := curve.ScalarMult(otherPartyPublicShare.X(), otherPartyPublicShare.Y(), secretShare)
	if !secp256k1.S256().IsOnCurve(x, y) {
		return nil, fmt.Errorf("invalid public key: points not on the curve")
	}
	return elliptic.Marshal(curve, x, y), nil
}
