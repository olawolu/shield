package ecdsamobile

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/didiercrunch/paillier"
	"github.com/helicarrierstudio/tss-lib/cryptoutils"
	"github.com/helicarrierstudio/tss-lib/ecdsa"
	"github.com/helicarrierstudio/tss-lib/pb"
	"google.golang.org/protobuf/proto"
)

// GenerateKeys wraps around ecdsa.CreatePartyTwoShares()
func GenerateKeys() (fmBytes []byte, err error) {
	curve := secp256k1.S256()
	basePoint := cryptoutils.Point{X: curve.Params().Gx, Y: curve.Params().Gy}

	kg, secretShare, err := ecdsa.CreatePartyTwoShares()
	if err != nil {
		return
	}

	proof := &pb.DlogProof{
		Base:        basePoint.Marshal(curve),
		Challenge:   kg.DlogProof.Challenge.Bytes(),
		Randcommit:  kg.DlogProof.RandCommit.Marshal(curve),
		Publicshare: kg.DlogProof.PublicShare.Marshal(curve),
		Hiddenvalue: kg.DlogProof.HiddenValue.Bytes(),
	}

	proofBytes, err := proto.Marshal(proof)
	if err != nil {
		return
	}

	fm := &pb.P2KeyGenFirstMessage{
		Dlnproof:   proofBytes,
		Publickey:  kg.PublicShare,
		Privatekey: secretShare, // figure out a way to hide this from the other party
	}

	fmBytes, err = proto.Marshal(fm)
	if err != nil {
		return
	}
	return
}

func VerifyCommitmentAndDlogProof(p1FirstMsgBytes []byte, p1SecondMsgBytes []byte) (err error) {
	p1FirstMsg := &pb.P1KeyGenFirstMessage{}
	if err = proto.Unmarshal(p1FirstMsgBytes, p1FirstMsg); err != nil {
		return err
	}

	p1SecondMsg := &pb.P1KeyGenSecondMessage{}
	if err = proto.Unmarshal(p1SecondMsgBytes, p1SecondMsg); err != nil {
		return err
	}

	p1_first_msg := pb.P1FirstMessageFromProto(p1FirstMsg)
	// proto.Unmarshal()
	p1_second_msg, err := pb.P1SecondMessageFromProto(p1SecondMsg)
	if err != nil {
		return err
	}

	err = ecdsa.PartyTwoVerifyCommitmentAndDlogProof(p1_first_msg, *p1_second_msg)
	return
}

func ComputePubKey(reqBytes []byte) ([]byte, error) {
	req := &pb.PublicKeyRequest{}

	if err := proto.Unmarshal(reqBytes, req); err != nil {
		return nil, err
	}

	// compute the public key
	// curve := secp256k1.S256()
	secret := req.GetSecretshare()
	otherPartyPublicShare := req.GetOtherpartypublicshare()

	secp256key, err := secp256k1.ParsePubKey(otherPartyPublicShare)
	if err != nil {
		return nil, err
	}

	key_bytes, err := ecdsa.ComputePubKey(secp256key, secret)
	if err != nil {
		return nil, err
	}

	return key_bytes, nil
}

func CreateEphemeralCommitments() (responseBytes []byte, err error) {
	curve := secp256k1.S256()
	msg, commit, key, err := ecdsa.CreateEphemeralCommitments()
	if err != nil {
		err = fmt.Errorf("cannot create ephemeral commitments: %w", err)
		return
	}

	keygen := &pb.P2EphemeralKeyGenFirstMessage{
		Commitment:    msg.PkCommitment.Bytes(),
		Commitmentzkp: msg.ZkPokCommitment.Bytes(),
	}

	keygenBytes, err := proto.Marshal(keygen)
	if err != nil {
		return
	}

	p := commit.DlogProof
	proof := &pb.EcddhProof{
		A1:        p.A1.Marshal(curve),
		A2:        p.A2.Marshal(curve),
		Z:         p.Z,
		Hashcoice: p.HashChoice,
	}

	proofBytes, err := proto.Marshal(proof)
	if err != nil {
		return
	}

	commitWitness := &pb.EphemeralCommitWitness{
		Pkcommitmentblindfactor: commit.PkCommitmentBlindFactor.Bytes(),
		Zkproofblindfactor:      commit.ZkPokBlindfactor.Bytes(),
		Publicshare:             commit.PublicShare,
		Dlogproof:               proofBytes,
		C:                       commit.C.Marshal(curve),
	}

	commitWitnessBytes, err := proto.Marshal(commitWitness)
	if err != nil {
		return
	}

	ephKey := &pb.EphemeralEcKeyPair{
		Publickey:  key.PublicShare,
		Privatekey: key.SecretShare,
	}

	ephKeyBytes, err := proto.Marshal(ephKey)
	if err != nil {
		return
	}

	response := &pb.P2EphemeralCommitmentsResponse{
		Keygenmsg:    keygenBytes,
		Witness:      commitWitnessBytes,
		Ephemeralkey: ephKeyBytes,
	}

	responseBytes, err = proto.Marshal(response)
	if err != nil {
		return
	}
	return
}

func VerifyEphemeralKeyAndDecommit(inputBytes []byte) (ephMsgBytes []byte, err error) {
	ephemeralKeyVerificationInput := &pb.EphemeralKeyVerificationInput{}
	proto.Unmarshal(inputBytes, ephemeralKeyVerificationInput)

	curve := secp256k1.S256()
	basePoint := cryptoutils.BasePoint(curve)
	basePoint2 := cryptoutils.BasePoint2(curve)

	var pubKeyPoint, cPoint *cryptoutils.Point

	var keygenmsg *pb.P1EphemeralKeyGenFirstMessage
	var witness *pb.EphemeralCommitWitness

	if err = proto.Unmarshal(ephemeralKeyVerificationInput.KeyGenMsg, keygenmsg); err != nil {
		err = fmt.Errorf("cannot unmarshal keygen message: %w", err)
		return
	}

	if err = proto.Unmarshal(ephemeralKeyVerificationInput.CommitWitness, witness); err != nil {
		err = fmt.Errorf("cannot unmarshal witness: %w", err)
		return
	}

	pubKey := keygenmsg.GetPublicshare()
	c := witness.GetC()

	if err = pubKeyPoint.Unmarshal(curve, pubKey); err != nil {
		err = fmt.Errorf("cannot unmarshal public key: %w", err)
		return
	}

	if err = cPoint.Unmarshal(curve, c); err != nil {
		err = fmt.Errorf("cannot unmarshal c: %w", err)
		return
	}

	proofBytes := keygenmsg.GetEcddhProof()

	proof, err := pb.EcddhProofFromProto(proofBytes)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal ecddh proof: %w", err)
		return
	}

	// publicShare := cryptoutils.NewPoint(msg.PublicShare.X(), msg.PublicShare.Y())
	delta := &cryptoutils.ECDDHStatement{
		G1: basePoint,
		H1: *pubKeyPoint,
		G2: basePoint2,
		H2: *cPoint,
	}
	ok, err := proof.Verify(curve, delta)
	if err != nil {
		err = fmt.Errorf("cannot verify ecddh dlog proof: %w", err)
		return
	}
	if ok {
		ephMsg := &pb.P2EphemeralKeyGenSecondMessage{
			Commitwitness: ephemeralKeyVerificationInput.GetCommitWitness(),
		}

		ephMsgBytes, err = proto.Marshal(ephMsg)
	} else {
		err = fmt.Errorf("cannot verify ecddh dlog proof")
		return
	}
	return
}

func PartialSignature(partialSigInputBytes []byte) (sigBytes []byte, err error) {
	partialSigInput := &pb.PartialSignatureInput{}
	err = proto.Unmarshal(partialSigInputBytes, partialSigInput)

	if err != nil {
		return nil, err
	}
	// z = hash(msg), e_pk_1 = encrypted share of party 1
	// Random point R_2 = k_2 * G
	// common point R = R_1 + k_2 * G
	// r = R_x
	curve := secp256k1.S256()
	q := curve.Params().P

	input, err := parseSignatureInput(partialSigInput)
	if err != nil {
		err = fmt.Errorf("cannot parse signature input: %w", err)
		return nil, err
	}

	p1_pk := input.remoteKey
	ephemeralSecret := input.ephemeralSecret
	localSecret := input.localSecret
	msg := input.msg
	encryptionKey := input.ek
	encryptedShare := input.es

	r_x, _ := curve.ScalarMult(p1_pk.X(), p1_pk.Y(), ephemeralSecret)
	// r = R_x mod q
	fmt.Println("r_x", r_x)
	fmt.Println("q", q)
	r := new(big.Int).Mod(r_x, q)
	fmt.Println("r", r)

	rho, _ := rand.Int(rand.Reader, new(big.Int).Exp(q, big.NewInt(2), nil))
	k := new(big.Int).SetBytes(ephemeralSecret)
	k_inv := new(big.Int).ModInverse(k, q)
	k_inv_m := new(big.Int).Mul(msg, k_inv)
	partialSig := new(big.Int).Add(new(big.Int).Mul(rho, q), k_inv_m.Mod(k_inv_m, q))

	c1, err := encryptionKey.Encrypt(partialSig, rand.Reader)
	pk_2 := new(big.Int).SetBytes(localSecret)
	rx_pk2 := new(big.Int).Mul(r_x, pk_2)
	rx_pk2_mod := new(big.Int).Mod(rx_pk2, q)
	// v = k_2^-1 * R_x * pk_2 mod q
	v := new(big.Int).Mod(new(big.Int).Mul(k_inv, rx_pk2_mod), q)

	// e_pk_1 := encryptedShare.C
	// fmt.Println("k_inv", k_inv)
	// fmt.Println("k", k)

	if err != nil {
		err = fmt.Errorf("cannot encrypt: %w", err)
		return
	}
	// stuff := new(big.Int).Add(new(big.Int).Mul(encryptedShare.C, v), partialSig)
	// fmt.Println("stuff", stuff)
	// fmt.Println("stuff length", stuff.BitLen())
	c2 := encryptionKey.Mul(encryptedShare, v)
	c3 := encryptionKey.Add(c1, c2)
	// fmt.Println("msg", msg)

	sig := &pb.PartialSignatureOutput{
		C3: c3.C.Bytes(),
	}

	sigBytes, err = proto.Marshal(sig)
	return
}

type parsedSigInput struct {
	ek              *paillier.PublicKey
	es              *paillier.Cypher
	msg             *big.Int
	localSecret     []byte
	remoteKey       *secp256k1.PublicKey
	ephemeralSecret []byte
}

func parseSignatureInput(input *pb.PartialSignatureInput) (*parsedSigInput, error) {
	p1_pk, err := secp256k1.ParsePubKey(input.GetEphemeralRemoteKey())
	if err != nil {
		err = fmt.Errorf("cannot parse public key: %w", err)
		return nil, err
	}

	ephemeralSecret := input.GetEphemeralSecret()
	localSecret := input.GetLocalShare()
	N := input.GetEncryptionKey()
	C := input.GetEncryptedShare()
	msg := input.GetMsg()

	encryptionKey := &paillier.PublicKey{
		N: new(big.Int).SetBytes(N),
	}
	encryptedSecret := &paillier.Cypher{
		C: new(big.Int).SetBytes(C),
	}

	return &parsedSigInput{
		ek:              encryptionKey,
		es:              encryptedSecret,
		localSecret:     localSecret,
		ephemeralSecret: ephemeralSecret,
		remoteKey:       p1_pk,
		msg:             new(big.Int).SetBytes(msg),
	}, nil
}
