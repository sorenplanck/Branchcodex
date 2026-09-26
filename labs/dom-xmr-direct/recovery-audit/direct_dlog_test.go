package main

import (
	"crypto/rand"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"filippo.io/edwards25519"
	"github.com/primefactor-io/lhtlp/pkg/params"
)

func TestDirectPointsRejectNoncanonicalTorsionAndMixedOrder(t *testing.T) {
	identity := edwards25519.NewIdentityPoint()
	var encodedIdentity [32]byte
	copy(encodedIdentity[:], identity.Bytes())
	if _, err := parseDirectPoint(encodedIdentity, false); err == nil {
		t.Fatal("identity key accepted")
	}
	if _, err := parseDirectPoint(encodedIdentity, true); err != nil {
		t.Fatal("identity masking commitment rejected", err)
	}
	negativeZero := encodedIdentity
	negativeZero[31] |= 128
	if _, err := parseDirectPoint(negativeZero, true); err == nil {
		t.Fatal("noncanonical sign bit accepted")
	}
	var orderFour [32]byte // y=0, nonidentity torsion point
	torsion, err := new(edwards25519.Point).SetBytes(orderFour[:])
	if err != nil {
		t.Fatal(err)
	}
	var mixed [32]byte
	copy(mixed[:], new(edwards25519.Point).Add(edwards25519.NewGeneratorPoint(), torsion).Bytes())
	for _, raw := range [][32]byte{orderFour, mixed} {
		if _, err := parseDirectPoint(raw, true); err == nil {
			t.Fatal("torsion accepted")
		}
	}
	for _, value := range []*big.Int{big.NewInt(1), big.NewInt(-1), new(big.Int).Sub(scalarOrder(), big.NewInt(1))} {
		if _, err := parseDirectPoint(directPoint(value), false); err != nil {
			t.Fatal("valid prime-order point rejected", err)
		}
	}
}

func TestDirectRealPuzzleProofOpeningAndAdversarialMutations(t *testing.T) {
	total := time.Now()
	p, err := params.GenerateParams(2048, 2, big.NewInt(200000))
	if err != nil {
		t.Fatal(err)
	}
	setup, err := verifyDirectPublicSetup(encode(publicSetup{p, 160, scalarOrder()}), directShortWork)
	if err != nil {
		t.Fatal(err)
	}
	setupSeconds := time.Since(total).Seconds()
	m, err := rand.Int(rand.Reader, new(big.Int).Sub(scalarOrder(), big.NewInt(1)))
	if err != nil {
		t.Fatal(err)
	}
	m.Add(m, big.NewInt(1))
	secret, err := scalarToLittleEndian(m, scalarOrder())
	if err != nil {
		t.Fatal(err)
	}
	context := [32]byte{7, 9, 31}
	if _, _, err := proveDirect(setup, context, [32]byte{}); err == nil {
		t.Fatal("zero secret accepted")
	}
	started := time.Now()
	statement, proof, err := proveDirect(setup, context, secret)
	if err != nil {
		t.Fatal(err)
	}
	generationSeconds := time.Since(started).Seconds()
	if statement.Public != directPoint(m) {
		t.Fatal("prover changed expected key")
	}
	started = time.Now()
	capsule, err := verifyDirect(setup, context, directPoint(m), statement, proof)
	if err != nil {
		t.Fatal(err)
	}
	verificationSeconds := time.Since(started).Seconds()
	opened, solveSeconds, err := capsule.open()
	if err != nil || opened != secret {
		t.Fatal("direct opening failed", err)
	}
	positiveSeconds := time.Since(total).Seconds()
	raw, err := json.Marshal(struct {
		Statement directStatement
		Proof     *directProof
	}{statement, proof})
	if err != nil {
		t.Fatal(err)
	}
	_, _, messageLimit, nonceLimit := directLimits(p)
	mutations := map[string]func(*directStatement, *directProof){
		"context":            func(s *directStatement, _ *directProof) { s.Context[0] ^= 1 },
		"public_key":         func(s *directStatement, _ *directProof) { s.Public = directPoint(big.NewInt(1)) },
		"setup_bytes":        func(s *directStatement, _ *directProof) { s.Setup = " " + s.Setup },
		"zero_u":             func(s *directStatement, _ *directProof) { s.Puzzle.U.SetInt64(0) },
		"zero_v":             func(s *directStatement, _ *directProof) { s.Puzzle.V.SetInt64(0) },
		"missing_ciphertext": func(s *directStatement, _ *directProof) { s.Puzzle = nil },
		"wrong_u":            func(s *directStatement, _ *directProof) { s.Puzzle.U.Mul(s.Puzzle.U, p.G).Mod(s.Puzzle.U, p.N) },
		"wrong_v": func(s *directStatement, _ *directProof) {
			s.Puzzle.V.Mul(s.Puzzle.V, new(big.Int).Add(p.N, big.NewInt(1))).Mod(s.Puzzle.V, p.NExpY)
		},
		"truncated_proof":    func(_ *directStatement, p *directProof) { p.Rounds = p.Rounds[:len(p.Rounds)-1] },
		"excess_proof":       func(_ *directStatement, p *directProof) { p.Rounds = append(p.Rounds, p.Rounds[0]) },
		"nil_commitment":     func(_ *directStatement, p *directProof) { p.Rounds[0].Commitment = nil },
		"nonunit_commitment": func(_ *directStatement, proof *directProof) { proof.Rounds[0].Commitment.U.Set(p.N) },
		"torsion_point":      func(_ *directStatement, p *directProof) { p.Rounds[0].Point = [32]byte{} },
		"nil_response":       func(_ *directStatement, p *directProof) { p.Rounds[0].MessageResponse = nil },
		"negative_response":  func(_ *directStatement, p *directProof) { p.Rounds[0].MessageResponse.SetInt64(-1) },
		"message_bound":      func(_ *directStatement, p *directProof) { p.Rounds[0].MessageResponse.Set(messageLimit) },
		"nonce_bound":        func(_ *directStatement, p *directProof) { p.Rounds[0].NonceResponse.Set(nonceLimit) },
		"wrong_message_response": func(_ *directStatement, p *directProof) {
			p.Rounds[0].MessageResponse.Add(p.Rounds[0].MessageResponse, big.NewInt(1))
		},
		"wrong_nonce_response": func(_ *directStatement, p *directProof) {
			p.Rounds[0].NonceResponse.Add(p.Rounds[0].NonceResponse, big.NewInt(1))
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var candidate struct {
				Statement directStatement
				Proof     *directProof
			}
			if err := json.Unmarshal(raw, &candidate); err != nil {
				t.Fatal(err)
			}
			mutate(&candidate.Statement, candidate.Proof)
			if _, err := verifyDirect(setup, context, statement.Public, candidate.Statement, candidate.Proof); err == nil {
				t.Fatal("accepted mutation")
			}
		})
	}
	wrongContext := context
	wrongContext[1] ^= 1
	if _, err := verifyDirect(setup, wrongContext, statement.Public, statement, proof); err == nil {
		t.Fatal("whole proof replayed into another caller context")
	}
	if _, err := verifyDirect(nil, context, statement.Public, statement, proof); err == nil {
		t.Fatal("accepted unverified setup")
	}
	if _, err := verifyDirect(setup, context, statement.Public, statement, nil); err == nil {
		t.Fatal("accepted missing proof")
	}
	// Snapshot independence is checked without another expensive solve: inspect
	// the verified copy after the caller overwrites the untrusted input object.
	expectedU, expectedV := new(big.Int).Set(capsule.ciphertext.U), new(big.Int).Set(capsule.ciphertext.V)
	statement.Puzzle.U.SetInt64(1)
	statement.Puzzle.V.SetInt64(1)
	if capsule.ciphertext.U.Cmp(expectedU) != 0 || capsule.ciphertext.V.Cmp(expectedV) != 0 {
		t.Fatal("verified ciphertext aliases input")
	}
	if capsule.public != directPoint(m) {
		t.Fatal("verified public key changed")
	}
	t.Logf("DIRECT_DLOG_RESULT=%s", encode(map[string]any{
		"experiment":   "single real puzzle with experimental Ed25519 relation proof",
		"proof_rounds": directRounds, "mask_bits": directMaskBits, "squarings": 200000,
		"setup_and_verification_seconds": setupSeconds, "proof_generation_seconds": generationSeconds,
		"proof_verification_seconds": verificationSeconds, "opening_seconds": solveSeconds,
		"positive_total_seconds": positiveSeconds, "json_bytes": len(raw),
		"adversarial_mutations_rejected": len(mutations), "secret_recovered": true,
		"funding_included": false, "process_ipc_included": false,
		"protocol_security_proven": false, "minimum_adversarial_delay_proven": false,
	}))
}

func TestDirectProverRejectsMissingSetupAndInvalidSecret(t *testing.T) {
	if _, _, err := proveDirect(nil, [32]byte{}, [32]byte{}); err == nil {
		t.Fatal("missing setup accepted")
	}
	// Decode checks themselves are also used by the existing bridge; this
	// small control ensures no canonical reduction is smuggled into the input.
	var out [32]byte
	for i := range out {
		out[i] = 255
	}
	if _, err := scalarFromLittleEndian(out, scalarOrder()); err == nil {
		t.Fatal("noncanonical secret accepted")
	}
}

func TestDirectIntegerBoundsCannotWrapTheMessageModulus(t *testing.T) {
	n := new(big.Int).Lsh(big.NewInt(1), 2047)
	_, _, messageLimit, _ := directLimits(&params.Params{NExpY: new(big.Int).Mul(n, n)})
	if new(big.Int).Lsh(messageLimit, 1).Cmp(n) >= 0 {
		t.Fatal("extracted representative can wrap N")
	}
	// A message shifted by N changes its Edwards representative in general.
	m := big.NewInt(3)
	shifted := new(big.Int).Add(m, n)
	if shifted.Cmp(messageLimit) < 0 || directPoint(m) == directPoint(shifted) {
		t.Fatal("CRT forgery is not excluded by the configured bound")
	}
}
