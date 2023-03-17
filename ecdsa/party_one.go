package ecdsa

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/didiercrunch/paillier"
	"github.com/helicarrierstudio/tss-lib/cryptoutils"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

var (
	curve = secp256k1.S256()
)

type CommitWitness struct {
	PkCommitmentBlindFactor *big.Int
	ZkBlindfactor           *big.Int
	PublicShare             []byte
	DlogProof               cryptoutils.DlogProof
}

func CreatePartyOneCommitment() (fm P1KeyGenFirstMsg, witness CommitWitness, secret []byte, err error) {
	secretShare, dLogProof, err := NewKeyWithProof()
	if err != nil {
		err = fmt.Errorf("cannot generate key pair: %w", err)
		return
	}
	publicShare := secretShare.PubKey()

	// create commitment to the public key share
	pk := new(big.Int).SetBytes(publicShare.SerializeUncompressed())
	pk_commitment_blind := cryptoutils.RandomBig(cryptoutils.SECURITY_BITS)
	pk_commitment, err := cryptoutils.CreateCommitmentWithDefinedRandomness(pk, pk_commitment_blind)
	if err != nil {
		err = fmt.Errorf("cannot create commitment: %w", err)
		return
	}

	// create a commitment to the zero-knowledge proof
	zk_commitment_blind := cryptoutils.RandomBig(cryptoutils.SECURITY_BITS)
	pk_rand_commitment := new(big.Int).SetBytes(dLogProof.RandCommit.Marshal(curve))
	zk_commitment, err := cryptoutils.CreateCommitmentWithDefinedRandomness(pk_rand_commitment, zk_commitment_blind)
	if err != nil {
		err = fmt.Errorf("cannot create commitment: %w", err)
		return
	}

	fm = P1KeyGenFirstMsg{
		Commitment:    pk_commitment,
		CommitmentZkp: zk_commitment,
	}

	witness = CommitWitness{
		PkCommitmentBlindFactor: pk_commitment_blind,
		ZkBlindfactor:           zk_commitment_blind,
		PublicShare:             publicShare.SerializeUncompressed(),
		DlogProof:               *dLogProof,
	}

	secret = secretShare.Serialize()
	return
}

func PartyOneVerifyAndDecommit(proof cryptoutils.DlogProof, witness CommitWitness) (sm P1KeyGenSecondMsg, err error) {
	status, err := proof.Verify(curve, proof.PublicShare)
	if err != nil {
		return
	}
	if !status {
		err = fmt.Errorf("cannot verify dlog proof")
		return
	}
	sm = P1KeyGenSecondMsg{
		Witness: witness,
	}
	return
}

func GeneratePaillierKeyPairAndEncryptedShare(secret []byte) (paillierPublic *PaillierKeyPair, err error) {
	p, _ := rand.Prime(rand.Reader, 512)
	q, _ := rand.Prime(rand.Reader, 512)
	decryptionKey := paillier.CreatePrivateKey(p, q)
	encryptionKey := decryptionKey.PublicKey
	randomness, err := paillier.GetRandomNumberInMultiplicativeGroup(encryptionKey.N, rand.Reader)
	if err != nil {
		err = fmt.Errorf("cannot generate random number: %w", err)
		return
	}

	// encrypt the secret share with a defined randomness
	secretShare := new(big.Int).SetBytes(secret)
	cypher, err := encryptionKey.EncryptWithR(secretShare, randomness)

	paillierPublic = &PaillierKeyPair{
		DecryptionKey:  decryptionKey,
		EncryptionKey:  &encryptionKey,
		EncryptedShare: cypher,
		Randomness:     randomness,
	}
	// p1.paillierEncryption = *paillierPublic
	return
}

func GenerateEncyptedShareFromFixedPaillierKeyPair(ek paillier.PublicKey, dk paillier.PrivateKey, secretShare []byte) (paillierPublic PaillierKeyPair, err error) {
	randomness, err := paillier.GetRandomNumberInMultiplicativeGroup(ek.N, rand.Reader)
	if err != nil {
		err = fmt.Errorf("cannot generate random number: %w", err)
		return
	}

	// encrypt the secret share with a defined randomness
	secretShareInt := new(big.Int).SetBytes(secretShare)
	cypher, err := ek.EncryptWithR(randomness, secretShareInt)

	paillierPublic = PaillierKeyPair{
		DecryptionKey:  &dk,
		EncryptionKey:  &ek,
		EncryptedShare: cypher,
		Randomness:     randomness,
	}
	return

}

func CreateEphemeralKey() (ephMsg P1EphemeralKeyGenFirstMsg, ephKey EphEcKeyPair, err error) {
	base := cryptoutils.BasePoint(curve)

	k, err := rand.Prime(rand.Reader, 256)
	if err != nil {
		err = fmt.Errorf("cannot generate key pair: %w", err)
		return
	}
	k_bytes := k.Bytes()
	x, y := curve.ScalarBaseMult(k_bytes)

	publicShare := cryptoutils.Point{X: x, Y: y}
	secpPubShare, err := secp256k1.ParsePubKey(publicShare.Marshal(curve))
	if err != nil {
		err = fmt.Errorf("cannot parse public key: %w", err)
		return
	}

	h := cryptoutils.BasePoint2(curve)
	w := &cryptoutils.ECDDHWitness{
		X: k_bytes,
	}
	c_x, c_y := curve.ScalarMult(h.X, h.Y, k_bytes)
	delta := &cryptoutils.ECDDHStatement{
		G1: base,
		G2: h,
		H1: publicShare,
		H2: cryptoutils.Point{X: c_x, Y: c_y},
	}

	dLogProof, err := cryptoutils.NewEcddhProof(curve, w, delta)
	if err != nil {
		err = fmt.Errorf("cannot generate dlog proof: %w", err)
		return
	}

	ephKey = EphEcKeyPair{
		PublicShare: secpPubShare.SerializeUncompressed(),
		SecretShare: k_bytes,
	}
	ephMsg = P1EphemeralKeyGenFirstMsg{
		DlogProof:   *dLogProof,
		PublicShare: *secpPubShare,
		C:           cryptoutils.Point{X: c_x, Y: c_y},
	}
	return
}

func VerifyEphemeralCommitmentAndProof(ephMsg1 P2EphemeralKeyGenFirstMsg, ephMsg2 P2EphemeralKeyGenSecondMsg) (msg P1EphemeralKeyGenSecondMsg, err error) {
	p2_pk_commitment := ephMsg1.PkCommitment
	p2_zk_pok_commitment := ephMsg1.ZkPokCommitment
	p2_zk_pok_commitment_bf := ephMsg2.CommitWitness.ZkPokBlindfactor
	p2_public_share := ephMsg2.CommitWitness.PublicShare
	p2_pk_commitment_bf := ephMsg2.CommitWitness.PkCommitmentBlindFactor
	p2_dlog_proof := ephMsg2.CommitWitness.DlogProof
	flag := true

	// verify the commitment
	p2_pub_share_commit, err := cryptoutils.CreateCommitmentWithDefinedRandomness(new(big.Int).SetBytes(p2_public_share), p2_pk_commitment_bf)
	if err != nil {
		err = fmt.Errorf("cannot create commitment: %w", err)
		return
	}
	if p2_pk_commitment.Cmp(p2_pub_share_commit) != 0 {
		flag = false
	}

	points := p2_dlog_proof.A1.Chain(curve, p2_dlog_proof.A2)
	xp, err := cryptoutils.CreateCommitmentWithDefinedRandomness(new(big.Int).SetBytes(points), p2_zk_pok_commitment_bf)
	if err != nil {
		err = fmt.Errorf("cannot create commitment: %w", err)
		return
	}
	if p2_zk_pok_commitment.Cmp(xp) != 0 {
		flag = false
	}

	if !flag {
		err = fmt.Errorf("cannot verify commitment")
		return
	}

	key, err := secp256k1.ParsePubKey(p2_public_share)
	if err != nil {
		err = fmt.Errorf("cannot parse public key: %w", err)
		return
	}

	pubShare := cryptoutils.Point{X: key.X(), Y: key.Y()}
	delta := &cryptoutils.ECDDHStatement{
		G1: cryptoutils.BasePoint(curve),
		H1: pubShare,
		G2: cryptoutils.BasePoint2(curve),
		H2: ephMsg2.CommitWitness.C,
	}
	ok, err := p2_dlog_proof.Verify(curve, delta)
	if err != nil {
		err = fmt.Errorf("cannot verify dlog proof: %w", err)
		return
	}
	if ok {
		msg = P1EphemeralKeyGenSecondMsg{}
	} else {
		err = fmt.Errorf("cannot verify dlog proof")
	}
	return
}

func ComputeSignature(partialSig PartialSignature, localShare EphEcKeyPair, remoteShare []byte, decryptionKey *paillier.PrivateKey, msg *big.Int) (sig []byte, err error) {
	q := curve.Params().N
	k1 := new(big.Int).SetBytes(localShare.SecretShare)

	remoteKey, err := secp256k1.ParsePubKey(remoteShare)
	if err != nil {
		err = fmt.Errorf("cannot parse public key: %w", err)
		return
	}
	// compute r = k2 * R1
	r_x, _ := curve.ScalarMult(remoteKey.X(), remoteKey.Y(), k1.Bytes())
	r := new(big.Int).Mod(r_x, q)

	k1_inv := new(big.Int).ModInverse(k1, q)

	var s *big.Int

	s_tag := decryptionKey.Decrypt(partialSig.C3)
	s_tag_tag := new(big.Int).Mul(s_tag, k1_inv)
	s = new(big.Int).Mod(s_tag_tag, q)

	/*
	   Calculate recovery id - it is not possible to compute the public key out of the signature
	   itself. Recovery id is used to enable extracting the public key uniquely.
	   1. id = R.y & 1
	   2. if (s > curve.q / 2) id = id ^ 1
	*/
	// not so sure about this
	// id := r_y.Bit(0)
	// fmt.Println("id: ", id)
	// if s_tag_tag.Cmp(new(big.Int).Sub(q, s)) > 0 {
	// 	id ^= 1
	// }
	// fmt.Println("id: ", id)

	sig, err = encodeSignature(r.Bytes(), s.Bytes())
	if err != nil {
		err = fmt.Errorf("cannot encode signature: %w", err)
		return
	}
	return
}

func VerifySignature(signature, publicKey, message []byte) bool {
	key, err := secp256k1.ParsePubKey(publicKey)
	if err != nil {
		fmt.Println("invalid key err: ", err)
		return false
	}
	z := sha256.Sum256(message)
	return ecdsa.VerifyASN1(key.ToECDSA(), z[:], signature[:])

}

func encodeSignature(r, s []byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		addASN1IntBytes(b, r)
		addASN1IntBytes(b, s)
	})
	return b.Bytes()
}

// addASN1IntBytes encodes in ASN.1 a positive integer represented as
// a big-endian byte slice with zero or more leading zeroes.
func addASN1IntBytes(b *cryptobyte.Builder, bytes []byte) {
	for len(bytes) > 0 && bytes[0] == 0 {
		bytes = bytes[1:]
	}
	if len(bytes) == 0 {
		b.SetError(errors.New("invalid integer"))
		return
	}
	b.AddASN1(asn1.INTEGER, func(c *cryptobyte.Builder) {
		if bytes[0]&0x80 != 0 {
			c.AddUint8(0)
		}
		c.AddBytes(bytes)
	})
}
