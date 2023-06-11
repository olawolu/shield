package shield

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/didiercrunch/paillier"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/olawolu/shield/cryptoutils"
)

func CreatePartyTwoShares() (fm P2KeyGenFirstMsg, secret []byte, err error) {
	secretShare, dLogProof, err := NewKeyWithProof()
	publicShare := secretShare.PubKey().SerializeUncompressed()

	fm = P2KeyGenFirstMsg{
		DlogProof:   *dLogProof,
		PublicShare: publicShare,
	}
	secret = secretShare.Serialize()
	return
}

func PartyTwoVerifyCommitmentAndDlogProof(p1FirstMsg P1KeyGenFirstMsg, p1SecondMsg P1KeyGenSecondMsg) (err error) {
	p1_pk_commitment := p1FirstMsg.Commitment
	p1_pk_commitment_zkp := p1FirstMsg.CommitmentZkp
	p1_zk_blind_factor := p1SecondMsg.Witness.ZkBlindfactor
	p1_pub_share := p1SecondMsg.Witness.PublicShare
	p1_pk_commitment_bf := p1SecondMsg.Witness.PkCommitmentBlindFactor
	p1_dlog_proof := p1SecondMsg.Witness.DlogProof

	flag := true
	p1Public, err := secp256k1.ParsePubKey(p1_pub_share)
	if err != nil {
		err = fmt.Errorf("cannot parse public key: %w", err)
		return
	}
	qPoint := cryptoutils.Point{
		X: p1Public.X(),
		Y: p1Public.Y(),
	}

	qPointBytes := cryptoutils.Marshal(qPoint)
	p1_pub_share_commit, err := cryptoutils.CreateCommitmentWithDefinedRandomness(new(big.Int).SetBytes(qPointBytes), p1_pk_commitment_bf)
	if err != nil {
		err = fmt.Errorf("cannot verify commitment: %w", err)
		return
	}

	if p1_pk_commitment.Cmp(p1_pub_share_commit) != 0 {
		flag = false
	}

	randCommitBytes := cryptoutils.Marshal(p1_dlog_proof.RandCommit)
	p1_zk_commit, err := cryptoutils.CreateCommitmentWithDefinedRandomness(new(big.Int).SetBytes(randCommitBytes), p1_zk_blind_factor)
	if err != nil {
		err = fmt.Errorf("cannot verify commitment: %w", err)
		return
	}

	if p1_pk_commitment_zkp.Cmp(p1_zk_commit) != 0 {
		fmt.Println("p1_pk_commitment_zkp: ", p1_pk_commitment_zkp)
		fmt.Println("p1_zk_commit: ", p1_zk_commit)
		flag = false
	}

	if !flag {
		err = errors.New("cannot verify proof")
		return
	}

	ok, err := p1_dlog_proof.Verify(curve, qPoint)
	if err != nil || !ok {
		err = fmt.Errorf("cannot verify dlog proof, err: %w", err)

	}

	return
}

func CreateEphemeralCommitments() (ephMsg P2EphemeralKeyGenFirstMsg, ephCommit EphemeralCommitWitness, ephKey EphEcKeyPair, err error) {
	basePoint := cryptoutils.BasePoint(curve)

	k, err := rand.Prime(rand.Reader, 256)
	if err != nil {
		err = fmt.Errorf("cannot generate random number: %w", err)
		return
	}
	k_bytes := k.Bytes()

	x, y := curve.ScalarBaseMult(k_bytes)

	publicShare := cryptoutils.NewPoint(x, y)
	randomBase := cryptoutils.BasePoint2(curve)

	publicShareBytes := cryptoutils.Marshal(publicShare)
	sKey, err := secp256k1.ParsePubKey(publicShareBytes)
	if err != nil {
		err = fmt.Errorf("cannot parse public key: %w", err)
		return
	}

	c_x, c_y := curve.ScalarMult(randomBase.X, randomBase.Y, k_bytes)
	c := cryptoutils.NewPoint(c_x, c_y)

	delta := cryptoutils.ECDDHStatement{
		G1: basePoint,
		G2: randomBase,
		H1: publicShare,
		H2: c,
	}
	witness := cryptoutils.ECDDHWitness{
		X: k_bytes,
	}

	dLogProof, err := cryptoutils.NewEcddhProof(curve, witness, delta)
	if err != nil {
		err = fmt.Errorf("cannot generate ecddh dlog proof: %w", err)
		return
	}

	// use hash based commitment
	public_share_bytes := cryptoutils.Marshal(publicShare)
	pk_commitment_bf := cryptoutils.RandomBig(cryptoutils.SECURITY_BITS)
	pk_commitment, err := cryptoutils.CreateCommitmentWithDefinedRandomness(new(big.Int).SetBytes(public_share_bytes), pk_commitment_bf)
	if err != nil {
		err = fmt.Errorf("cannot create commitment: %w", err)
		return
	}

	zk_pok_commitment_bf := cryptoutils.RandomBig(cryptoutils.SECURITY_BITS)

	rand_commit := dLogProof.A1.Chain(curve, dLogProof.A2)
	zk_pok_commitment, err := cryptoutils.CreateCommitmentWithDefinedRandomness(new(big.Int).SetBytes(rand_commit), zk_pok_commitment_bf)

	ephKey = EphEcKeyPair{
		SecretShare: k_bytes,
		PublicShare: sKey.SerializeUncompressed(),
	}
	ephMsg = P2EphemeralKeyGenFirstMsg{
		PkCommitment:    pk_commitment,
		ZkPokCommitment: zk_pok_commitment,
	}
	ephCommit = EphemeralCommitWitness{
		PkCommitmentBlindFactor: pk_commitment_bf,
		ZkPokBlindfactor:        zk_pok_commitment_bf,
		PublicShare:             ephKey.PublicShare,
		DlogProof:               *dLogProof,
		C:                       cryptoutils.Point{X: c_x, Y: c_y},
	}

	return
}

func VerifyEphemeralKeyAndDecommit(msg P1EphemeralKeyGenFirstMsg, ephCommit EphemeralCommitWitness) (ephMsg P2EphemeralKeyGenSecondMsg, err error) {
	basePoint := cryptoutils.BasePoint(curve)
	basePoint2 := cryptoutils.BasePoint2(curve)
	publicShare := cryptoutils.NewPoint(msg.PublicShare.X(), msg.PublicShare.Y())
	delta := cryptoutils.ECDDHStatement{
		G1: basePoint,
		H1: publicShare,
		G2: basePoint2,
		H2: msg.C,
	}
	ok, err := cryptoutils.Verify(curve, msg.DlogProof, delta)
	if err != nil {
		err = fmt.Errorf("cannot verify ecddh dlog proof: %w", err)
		return
	}
	if ok {
		ephMsg = P2EphemeralKeyGenSecondMsg{
			CommitWitness: ephCommit,
		}
	} else {
		err = fmt.Errorf("cannot verify ecddh dlog proof")
		return
	}
	return
}

func ComputePartialSignature(paillierKey *PaillierKeyPair, encryptionKey *paillier.PublicKey, encryptedShare *paillier.Cypher, ephLocal EphEcKeyPair, ephExt secp256k1.PublicKey, msg []byte, secretShare []byte) (sig PartialSignature, err error) {
	q := curve.Params().N
	k2 := new(big.Int).SetBytes(ephLocal.SecretShare)

	r_x, _ := curve.ScalarMult(ephExt.X(), ephExt.Y(), k2.Bytes())
	r := new(big.Int).Mod(r_x, q)

	z := crypto.Keccak256(msg)
	z_int := new(big.Int).SetBytes(z[:])

	// compute k2^-1 * z
	k2_inv := new(big.Int).ModInverse(k2, q)
	k2_z := new(big.Int).Mul(k2_inv, z_int)
	k2_z_mod := new(big.Int).Mod(k2_z, q)

	// compute Enc(k2^-1 * z)
	c1, err := encryptionKey.Encrypt(k2_z_mod, rand.Reader)
	if err != nil {
		err = fmt.Errorf("cannot encrypt: %w", err)
		return
	}

	// compute k2^-1 * R_x * d2
	d2 := new(big.Int).SetBytes(secretShare)
	k2_inv_rx := new(big.Int).Mul(k2_inv, r)
	k2_inv_rx_d2 := new(big.Int).Mul(k2_inv_rx, d2)
	k2_inv_rx_d2_mod := new(big.Int).Mod(k2_inv_rx_d2, q)
	c2 := encryptionKey.Mul(encryptedShare, k2_inv_rx_d2_mod)

	// add c1 and c2
	c3 := encryptionKey.Add(c1, c2)
	sig = PartialSignature{
		C3: c3,
	}
	return
}
