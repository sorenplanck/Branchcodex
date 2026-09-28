package main

// EXPERIMENT ONLY. This is an unaudited, repeated one-bit Sigma candidate.
// Used only by isolated local experiments, including testcoin refunds.
// It deliberately does not change the existing
// cut-and-choose decoder. math/big is variable-time; no erasure claim is made.

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"math/big"
	"sync"
	"time"

	"filippo.io/edwards25519"
	"github.com/primefactor-io/lhtlp/pkg/params"
	"github.com/primefactor-io/lhtlp/pkg/puzzle"
)

const directRounds = 256
const directMaskBits = 256

// Bound CPU use independently of peer input. This changes only scheduling of
// independent proof equations, never the sequential setup/opening work.
const directVerificationWorkers = 2

// Explicit, bounded laboratory profiles. Neither is a security/time guarantee.
const directShortWork int64 = 200000
const directLongWork int64 = 10000000

func directWorkAllowed(work int64) bool {
	return work == directShortWork || work == directLongWork
}

// This distinct type prevents the direct profile policy from extending the
// original cut-and-choose parser, which still accepts only 200000 squarings.
type verifiedDirectSetup struct{ raw string }

func parseDirectSetup(raw string) (*publicSetup, error) {
	if raw == "" || len(raw) > 65536 {
		return nil, fmt.Errorf("invalid direct setup size")
	}
	var setup publicSetup
	if err := json.Unmarshal([]byte(raw), &setup); err != nil {
		return nil, fmt.Errorf("invalid direct setup: %w", err)
	}
	p := setup.Parameters
	if p == nil || p.T == nil || !p.T.IsInt64() || !directWorkAllowed(p.T.Int64()) ||
		setup.ScalarOrder == nil || setup.ScalarOrder.Cmp(scalarOrder()) != 0 || setup.RangeBits != 160 {
		return nil, fmt.Errorf("unexpected direct setup parameters")
	}
	// Reuse all modulus/group checks without mutating the decoded parameters
	// or relaxing the fixed work policy in the legacy backend.
	shape := *p
	shape.T = big.NewInt(directShortWork)
	if err := validateParameters(&shape); err != nil {
		return nil, err
	}
	return &setup, nil
}

func verifyDirectPublicSetup(raw string, expectedWork int64) (*verifiedDirectSetup, error) {
	if !directWorkAllowed(expectedWork) {
		return nil, fmt.Errorf("unsupported requested direct work")
	}
	setup, err := parseDirectSetup(raw)
	if err != nil {
		return nil, err
	}
	p := setup.Parameters
	if p.T.Int64() != expectedWork {
		return nil, fmt.Errorf("direct work differs from local policy")
	}
	w := new(big.Int).Set(p.G)
	for i := int64(0); i < expectedWork; i++ {
		w.Mul(w, w).Mod(w, p.N)
	}
	if w.Cmp(p.H) != 0 {
		return nil, fmt.Errorf("inconsistent delayed direct setup element")
	}
	return &verifiedDirectSetup{raw}, nil
}

type directStatement struct {
	Setup   string
	Context [32]byte
	Public  [32]byte
	Puzzle  *puzzle.Puzzle
}

type directRound struct {
	Commitment      *puzzle.Puzzle
	Point           [32]byte
	MessageResponse *big.Int
	NonceResponse   *big.Int
}

type directProof struct{ Rounds []directRound }

func directLimits(p *params.Params) (messageMask, nonceMask, messageLimit, nonceLimit *big.Int) {
	order := scalarOrder()
	messageMask = new(big.Int).Lsh(big.NewInt(1), uint(order.BitLen()+directMaskBits))
	nonceMask = new(big.Int).Lsh(new(big.Int).Set(p.NExpY), directMaskBits)
	messageLimit = new(big.Int).Add(messageMask, order)
	nonceLimit = new(big.Int).Add(nonceMask, p.NExpY)
	return
}

func directCurveScalar(value *big.Int) *edwards25519.Scalar {
	// Curve arithmetic alone reduces mod q. The RSA equations always use the
	// full integer responses; reducing those would destroy the relation.
	reduced := new(big.Int).Mod(value, scalarOrder())
	canonical, err := scalarToLittleEndian(reduced, scalarOrder())
	if err != nil {
		panic(err)
	}
	scalar, err := new(edwards25519.Scalar).SetCanonicalBytes(canonical[:])
	if err != nil {
		panic(err)
	}
	return scalar
}

func directPoint(value *big.Int) [32]byte {
	var raw [32]byte
	copy(raw[:], new(edwards25519.Point).ScalarBaseMult(directCurveScalar(value)).Bytes())
	return raw
}

func parseDirectPoint(raw [32]byte, allowIdentity bool) (*edwards25519.Point, error) {
	point, err := new(edwards25519.Point).SetBytes(raw[:])
	if err != nil || !bytes.Equal(point.Bytes(), raw[:]) {
		return nil, fmt.Errorf("invalid or noncanonical Edwards point")
	}
	identity := edwards25519.NewIdentityPoint()
	if !allowIdentity && point.Equal(identity) == 1 {
		return nil, fmt.Errorf("identity public key")
	}
	// Scalar APIs reduce q to zero; use the public integer q explicitly to
	// reject torsion and mixed-order points, not merely small-order points.
	product := edwards25519.NewIdentityPoint()
	order := scalarOrder()
	for bit := order.BitLen() - 1; bit >= 0; bit-- {
		product.Add(product, product)
		if order.Bit(bit) != 0 {
			product.Add(product, point)
		}
	}
	if product.Equal(identity) != 1 {
		return nil, fmt.Errorf("point outside prime-order subgroup")
	}
	return point, nil
}

func directFrame(h hash.Hash, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	h.Write(size[:])
	h.Write(value)
}

func directChallenge(statement directStatement, proof *directProof) [32]byte {
	h := sha512.New()
	directFrame(h, []byte("DXP1/EXPERIMENT/direct-dlog/one-bit-256/mask-256/v0"))
	directFrame(h, []byte(statement.Setup))
	directFrame(h, statement.Context[:])
	directFrame(h, scalarOrder().Bytes())
	directFrame(h, edwards25519.NewGeneratorPoint().Bytes())
	directFrame(h, statement.Public[:])
	directFrame(h, statement.Puzzle.U.Bytes())
	directFrame(h, statement.Puzzle.V.Bytes())
	for _, round := range proof.Rounds {
		directFrame(h, round.Commitment.U.Bytes())
		directFrame(h, round.Commitment.V.Bytes())
		directFrame(h, round.Point[:])
	}
	var challenge [32]byte
	copy(challenge[:], h.Sum(nil))
	return challenge
}

func proveDirect(setup *verifiedDirectSetup, context [32]byte, secret [32]byte) (directStatement, *directProof, error) {
	if setup == nil {
		return directStatement{}, nil, fmt.Errorf("setup must be verified before disclosure")
	}
	parsed, err := parseDirectSetup(setup.raw)
	if err != nil {
		return directStatement{}, nil, err
	}
	m, err := scalarFromLittleEndian(secret, scalarOrder())
	if err != nil || m.Sign() == 0 {
		return directStatement{}, nil, fmt.Errorf("invalid secret scalar")
	}
	p := parsed.Parameters
	ciphertext, nonce, err := puzzle.GeneratePuzzleAndReturnNonce(p, m)
	if err != nil {
		return directStatement{}, nil, err
	}
	statement := directStatement{setup.raw, context, directPoint(m), ciphertext}
	messageMask, nonceMask, _, _ := directLimits(p)
	proof := &directProof{Rounds: make([]directRound, directRounds)}
	for i := range proof.Rounds {
		a, err := rand.Int(rand.Reader, messageMask)
		if err != nil {
			return directStatement{}, nil, err
		}
		b, err := rand.Int(rand.Reader, nonceMask)
		if err != nil {
			return directStatement{}, nil, err
		}
		commitment, err := puzzle.GeneratePuzzleWithCustomNonce(p, b, a)
		if err != nil {
			return directStatement{}, nil, err
		}
		proof.Rounds[i] = directRound{commitment, directPoint(a), a, b}
	}
	challenge := directChallenge(statement, proof)
	for i := range proof.Rounds {
		if (challenge[i/8]>>uint(i%8))&1 == 1 {
			proof.Rounds[i].MessageResponse.Add(proof.Rounds[i].MessageResponse, m)
			proof.Rounds[i].NonceResponse.Add(proof.Rounds[i].NonceResponse, nonce)
		}
	}
	return statement, proof, nil
}

// A private parsed snapshot; the caller cannot substitute a different puzzle
// after verification by mutating the statement/proof passed to the verifier.
type verifiedDirectCapsule struct {
	parameters *params.Params
	ciphertext *puzzle.Puzzle
	public     [32]byte
}

func verifyDirect(setup *verifiedDirectSetup, expectedContext, expectedPublic [32]byte, statement directStatement, proof *directProof) (*verifiedDirectCapsule, error) {
	return verifyDirectWithWorkers(setup, expectedContext, expectedPublic, statement, proof, directVerificationWorkers)
}

// workers=1 retains a sequential control for equivalence/timing tests. Inputs
// belong to the caller and must not be concurrently mutated during this call.
func verifyDirectWithWorkers(setup *verifiedDirectSetup, expectedContext, expectedPublic [32]byte, statement directStatement, proof *directProof, workers int) (*verifiedDirectCapsule, error) {
	if workers < 1 || workers > directVerificationWorkers {
		return nil, fmt.Errorf("invalid direct verification worker count")
	}
	if setup == nil || setup.raw != statement.Setup || proof == nil || len(proof.Rounds) != directRounds {
		return nil, fmt.Errorf("unverified/replaced setup or wrong proof size")
	}
	if statement.Context != expectedContext || statement.Public != expectedPublic {
		return nil, fmt.Errorf("unexpected context or public key")
	}
	parsed, err := parseDirectSetup(setup.raw)
	if err != nil {
		return nil, err
	}
	p := parsed.Parameters
	if err := validatePuzzle(statement.Puzzle, p); err != nil {
		return nil, err
	}
	public, err := parseDirectPoint(statement.Public, false)
	if err != nil {
		return nil, err
	}
	_, _, messageLimit, nonceLimit := directLimits(p)
	if new(big.Int).Lsh(new(big.Int).Set(messageLimit), 1).Cmp(p.N) >= 0 {
		return nil, fmt.Errorf("ambiguous message representatives")
	}
	points := make([]*edwards25519.Point, directRounds)
	for i, round := range proof.Rounds {
		if err := validatePuzzle(round.Commitment, p); err != nil {
			return nil, err
		}
		if round.MessageResponse == nil || round.NonceResponse == nil ||
			round.MessageResponse.Sign() < 0 || round.MessageResponse.Cmp(messageLimit) >= 0 ||
			round.NonceResponse.Sign() < 0 || round.NonceResponse.Cmp(nonceLimit) >= 0 {
			return nil, fmt.Errorf("response outside integer bounds")
		}
		points[i], err = parseDirectPoint(round.Point, true)
		if err != nil {
			return nil, err
		}
	}
	challenge := directChallenge(statement, proof)
	verifyRound := func(i int) error {
		round := proof.Rounds[i]
		encoded, err := puzzle.GeneratePuzzleWithCustomNonce(p, round.NonceResponse, round.MessageResponse)
		if err != nil {
			return err
		}
		u := new(big.Int).Set(round.Commitment.U)
		v := new(big.Int).Set(round.Commitment.V)
		point := new(edwards25519.Point).Set(points[i])
		if (challenge[i/8]>>uint(i%8))&1 == 1 {
			u.Mul(u, statement.Puzzle.U).Mod(u, p.N)
			v.Mul(v, statement.Puzzle.V).Mod(v, p.NExpY)
			point.Add(point, public)
		}
		responsePoint := new(edwards25519.Point).ScalarBaseMult(directCurveScalar(round.MessageResponse))
		if encoded.U.Cmp(u) != 0 || encoded.V.Cmp(v) != 0 || responsePoint.Equal(point) != 1 {
			return fmt.Errorf("direct relation failed at round %d", i)
		}
		return nil
	}
	// Small ordered batches retain deterministic first-failure reporting and
	// bound work on invalid proofs to at most one extra equation. All operands
	// above are read-only; each round owns its arithmetic temporaries. The
	// pinned upstream GeneratePuzzleWithCustomNonce also uses fresh receivers.
	for start := 0; start < directRounds; start += workers {
		count := min(workers, directRounds-start)
		errors := make([]error, count)
		var pending sync.WaitGroup
		for offset := 1; offset < count; offset++ {
			pending.Add(1)
			go func(offset int) {
				defer pending.Done()
				errors[offset] = verifyRound(start + offset)
			}(offset)
		}
		errors[0] = verifyRound(start)
		pending.Wait()
		for _, err := range errors {
			if err != nil {
				return nil, err
			}
		}
	}
	return &verifiedDirectCapsule{
		p,
		puzzle.NewPuzzle(new(big.Int).Set(statement.Puzzle.U), new(big.Int).Set(statement.Puzzle.V)),
		statement.Public,
	}, nil
}

func (capsule *verifiedDirectCapsule) open() ([32]byte, float64, error) {
	started := time.Now()
	value := puzzle.SolvePuzzle(capsule.parameters, capsule.ciphertext)
	scalar, err := capsule.decodePlaintext(value)
	return scalar, time.Since(started).Seconds(), err
}

func (capsule *verifiedDirectCapsule) decodePlaintext(value *big.Int) ([32]byte, error) {
	_, _, limit, _ := directLimits(capsule.parameters)
	if value.Sign() < 0 || value.Cmp(capsule.parameters.N) >= 0 {
		return [32]byte{}, fmt.Errorf("noncanonical plaintext residue")
	}
	if value.Cmp(new(big.Int).Rsh(new(big.Int).Set(capsule.parameters.N), 1)) > 0 {
		value.Sub(value, capsule.parameters.N)
	}
	if new(big.Int).Abs(new(big.Int).Set(value)).Cmp(limit) >= 0 || directPoint(value) != capsule.public {
		return [32]byte{}, fmt.Errorf("opening outside range or wrong public point")
	}
	// This reduction is exclusive to a capsule with the DIRECT relation proof.
	// It must never be moved to the old range-only cut-and-choose decoder.
	return scalarToLittleEndian(new(big.Int).Mod(value, scalarOrder()), scalarOrder())
}
