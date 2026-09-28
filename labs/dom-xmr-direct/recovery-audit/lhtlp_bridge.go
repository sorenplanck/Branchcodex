// Lab-only process bridge. Receives newly generated test shares, encrypts them,
// and opens a selected delayed share. Public verification remains experimental;
// this is not an audited pre-funding verifier or a wallet service.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"

	"github.com/primefactor-io/lhtlp/pkg/params"
	"github.com/primefactor-io/lhtlp/pkg/proofs"
	"github.com/primefactor-io/lhtlp/pkg/puzzle"
)

type publicOffer struct {
	Setup   string   `json:"setup"`
	Puzzles []string `json:"puzzles"`
	Proof   string   `json:"proof"`
}

type opening struct {
	Index  uint16   `json:"index"`
	Scalar [32]byte `json:"scalar"`
	Nonce  string   `json:"nonce,omitempty"`
}

func encode(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(data)
}

func scalarOrder() *big.Int {
	order, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	return order
}

func scalarFromLittleEndian(bytes [32]byte, order *big.Int) (*big.Int, error) {
	for j := 0; j < 16; j++ {
		bytes[j], bytes[31-j] = bytes[31-j], bytes[j]
	}
	value := new(big.Int).SetBytes(bytes[:])
	if value.Sign() < 0 || value.Cmp(order) >= 0 {
		return nil, fmt.Errorf("noncanonical scalar")
	}
	return value, nil
}

var errNoncanonicalRecovered = errors.New("noncanonical recovered scalar")

func scalarToLittleEndian(value *big.Int, order *big.Int) ([32]byte, error) {
	var scalar [32]byte
	if value.Sign() < 0 || value.Cmp(order) >= 0 {
		return scalar, errNoncanonicalRecovered
	}
	value.FillBytes(scalar[:])
	for j := 0; j < 16; j++ {
		scalar[j], scalar[31-j] = scalar[31-j], scalar[j]
	}
	return scalar, nil
}

func unit(value, modulus *big.Int) bool {
	return value != nil && value.Sign() > 0 && value.Cmp(modulus) < 0 &&
		new(big.Int).GCD(nil, nil, value, modulus).Cmp(big.NewInt(1)) == 0
}

// Fixed lab profile, not a proof that nobody knows the RSA factors or that the
// group has the required order. Bound every field before upstream arithmetic.
func validateParameters(p *params.Params) error {
	if p == nil || p.Y != 2 || p.T == nil || p.T.Cmp(big.NewInt(200000)) != 0 ||
		p.N == nil || p.N.BitLen() != 2048 || p.N.Bit(0) != 1 ||
		p.NExpY == nil || p.NExpYMinusOne == nil {
		return fmt.Errorf("invalid lab parameter profile")
	}
	if p.NExpYMinusOne.Cmp(p.N) != 0 || p.NExpY.Cmp(new(big.Int).Mul(p.N, p.N)) != 0 {
		return fmt.Errorf("inconsistent modulus powers")
	}
	if !unit(p.G, p.N) || !unit(p.H, p.N) || p.G.Cmp(big.NewInt(1)) == 0 ||
		p.H.Cmp(big.NewInt(1)) == 0 ||
		p.G.Cmp(new(big.Int).Sub(p.N, big.NewInt(1))) == 0 ||
		p.H.Cmp(new(big.Int).Sub(p.N, big.NewInt(1))) == 0 {
		return fmt.Errorf("invalid setup group element")
	}
	root := new(big.Int).Sqrt(p.N)
	if new(big.Int).Mul(root, root).Cmp(p.N) == 0 || p.N.ProbablyPrime(32) {
		return fmt.Errorf("prime or square modulus")
	}
	return nil
}

// Public recomputation checks h = g^(2^T) mod N, without using RSA factors.
// It establishes setup consistency only, not a lower bound on solving time.
func verifySetupRelation(p *params.Params) error {
	if err := validateParameters(p); err != nil {
		return err
	}
	w := new(big.Int).Set(p.G)
	for i := int64(0); i < p.T.Int64(); i++ {
		w.Mul(w, w).Mod(w, p.N)
	}
	if w.Cmp(p.H) != 0 {
		return fmt.Errorf("inconsistent delayed setup element")
	}
	return nil
}

func validatePuzzle(z *puzzle.Puzzle, p *params.Params) error {
	if z == nil || !unit(z.U, p.N) || !unit(z.V, p.NExpY) {
		return fmt.Errorf("invalid puzzle group element")
	}
	return nil
}

type publicSetup struct {
	Parameters  *params.Params
	RangeBits   int
	ScalarOrder *big.Int
}

func parseSetup(raw string, order *big.Int) (*publicSetup, error) {
	if raw == "" || len(raw) > 65536 {
		return nil, fmt.Errorf("invalid setup size")
	}
	var setup publicSetup
	if err := json.Unmarshal([]byte(raw), &setup); err != nil {
		return nil, fmt.Errorf("invalid setup: %w", err)
	}
	if setup.Parameters == nil || setup.ScalarOrder == nil || setup.ScalarOrder.Cmp(order) != 0 || setup.RangeBits != 160 {
		return nil, fmt.Errorf("unexpected setup parameters")
	}
	if err := validateParameters(setup.Parameters); err != nil {
		return nil, err
	}
	return &setup, nil
}

func setupBinding(raw string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(raw))) }

type verifiedSetup struct{ raw string }

func verifyPublicSetup(raw string) (*verifiedSetup, error) {
	setup, err := parseSetup(raw, scalarOrder())
	if err != nil {
		return nil, err
	}
	if err := verifySetupRelation(setup.Parameters); err != nil {
		return nil, err
	}
	return &verifiedSetup{raw}, nil
}

func parsePublicOffer(offer publicOffer, order *big.Int) (*params.Params, []*puzzle.Puzzle, *proofs.RangeProof, int, error) {
	if len(offer.Puzzles) < 2 || len(offer.Puzzles) > 512 || len(offer.Puzzles)%2 != 0 || offer.Proof == "" {
		return nil, nil, nil, 0, fmt.Errorf("invalid public offer shape")
	}
	setup, err := parseSetup(offer.Setup, order)
	if err != nil {
		return nil, nil, nil, 0, err
	}
	puzzles := make([]*puzzle.Puzzle, len(offer.Puzzles))
	for i, raw := range offer.Puzzles {
		if raw == "" || len(raw) > 65536 {
			return nil, nil, nil, 0, fmt.Errorf("invalid puzzle bytes")
		}
		var parsed puzzle.Puzzle
		if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
			return nil, nil, nil, 0, fmt.Errorf("invalid puzzle %d: %w", i+1, err)
		}
		if err := validatePuzzle(&parsed, setup.Parameters); err != nil {
			return nil, nil, nil, 0, err
		}
		puzzles[i] = &parsed
	}
	var proof proofs.RangeProof
	if len(offer.Proof) > 4*1024*1024 {
		return nil, nil, nil, 0, fmt.Errorf("range proof too large")
	}
	if err := json.Unmarshal([]byte(offer.Proof), &proof); err != nil {
		return nil, nil, nil, 0, fmt.Errorf("invalid range proof: %w", err)
	}
	if len(proof.D) != setup.RangeBits || len(proof.Values) != setup.RangeBits {
		return nil, nil, nil, 0, fmt.Errorf("invalid range proof round count")
	}
	maxX := new(big.Int).Mul(new(big.Int).Div(new(big.Int).Set(order), big.NewInt(2)), big.NewInt(int64(4*len(puzzles))))
	nonceLimit := new(big.Int).Sub(setup.Parameters.NExpY, big.NewInt(1))
	responseLimit := new(big.Int).Mul(nonceLimit, big.NewInt(int64(len(puzzles)+1)))
	for i, value := range proof.Values {
		if err := validatePuzzle(proof.D[i], setup.Parameters); err != nil {
			return nil, nil, nil, 0, err
		}
		if value == nil || value.X == nil || value.R == nil || value.X.Sign() < 0 ||
			value.X.Cmp(maxX) > 0 || value.R.Sign() < 0 || value.R.Cmp(responseLimit) >= 0 {
			return nil, nil, nil, 0, fmt.Errorf("invalid range proof response")
		}
	}
	return setup.Parameters, puzzles, &proof, setup.RangeBits, nil
}

func verifyPublicOpenings(offer publicOffer, opened []opening) (int, bool, float64, float64, error) {
	order := scalarOrder()
	p, puzzles, rangeProof, rangeBits, err := parsePublicOffer(offer, order)
	if err != nil {
		return 0, false, 0, 0, err
	}
	if err := verifySetupRelation(p); err != nil {
		return 0, false, 0, 0, err
	}
	started := time.Now()
	valid, err := proofs.VerifyRangePoof(rangeProof, rangeBits, p, puzzles, order)
	if err != nil || !valid {
		return 0, false, 0, 0, fmt.Errorf("range verification failed: %v", err)
	}
	proofVerification := time.Since(started).Seconds()
	checked, wrongRejected, openingSeconds, err := checkPublicOpenings(p, puzzles, opened, order)
	return checked, wrongRejected, proofVerification, openingSeconds, err
}

// Uses parameters/puzzles already checked by a public verifier. This only
// verifies the explicit opening witnesses, never repeats the timed setup work.
func checkPublicOpenings(p *params.Params, puzzles []*puzzle.Puzzle, opened []opening, order *big.Int) (int, bool, float64, error) {
	if len(opened) != len(puzzles)/2 {
		return 0, false, 0, fmt.Errorf("wrong opened count")
	}
	seen := make(map[uint16]bool)
	started := time.Now()
	for _, opening := range opened {
		if opening.Index == 0 || int(opening.Index) > len(puzzles) || seen[opening.Index] {
			return 0, false, 0, fmt.Errorf("invalid opened index")
		}
		seen[opening.Index] = true
		scalar, err := scalarFromLittleEndian(opening.Scalar, order)
		if err != nil {
			return 0, false, 0, fmt.Errorf("invalid opened scalar")
		}
		if len(opening.Nonce) > 1234 {
			return 0, false, 0, fmt.Errorf("opening nonce too large")
		}
		nonce, ok := new(big.Int).SetString(opening.Nonce, 10)
		if !ok || nonce.Sign() < 0 || nonce.Cmp(new(big.Int).Sub(p.NExpY, big.NewInt(1))) >= 0 {
			return 0, false, 0, fmt.Errorf("invalid opening nonce")
		}
		regenerated, err := puzzle.GeneratePuzzleWithCustomNonce(p, nonce, scalar)
		if err != nil || !regenerated.Equal(puzzles[opening.Index-1]) {
			return 0, false, 0, fmt.Errorf("opened puzzle mismatch")
		}
	}
	wrongRejected := false
	if len(opened) > 0 {
		first := opened[0]
		scalar, err := scalarFromLittleEndian(first.Scalar, order)
		if err != nil {
			return 0, false, 0, err
		}
		nonce, _ := new(big.Int).SetString(first.Nonce, 10)
		wrong, err := puzzle.GeneratePuzzleWithCustomNonce(p, new(big.Int).Add(nonce, big.NewInt(1)), scalar)
		if err == nil && !wrong.Equal(puzzles[first.Index-1]) {
			wrongRejected = true
		}
	}
	return len(opened), wrongRejected, time.Since(started).Seconds(), nil
}

func verifyMode() error {
	var input struct {
		Offer  publicOffer `json:"offer"`
		Opened []opening   `json:"opened"`
	}
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 5*1024*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return err
	}
	checked, rejectedWrongNonce, proofVerification, openingVerification, err := verifyPublicOpenings(input.Offer, input.Opened)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		Result                string  `json:"result"`
		CheckedOpenings       int     `json:"checked_openings"`
		RejectedWrongNonce    bool    `json:"rejected_wrong_nonce"`
		ProofVerification     float64 `json:"proof_verification_seconds"`
		OpeningVerification   float64 `json:"opening_verification_seconds"`
		PublicVerifierNoShare bool    `json:"public_verifier_no_share_secret"`
		SetupRelationVerified bool    `json:"setup_relation_verified"`
	}{"verified", checked, rejectedWrongNonce, proofVerification, openingVerification, true, true})
}

// Private parsed snapshot. The session cannot replace its offer after this
// constructor verifies it. No dealer secrets or opening nonces are required.
type verifiedPublicSolver struct {
	parameters *params.Params
	puzzles    []*puzzle.Puzzle
	order      *big.Int
}

func newPublicSolver(offer publicOffer) (*verifiedPublicSolver, error) {
	setup, err := verifyPublicSetup(offer.Setup)
	if err != nil {
		return nil, err
	}
	return newPublicSolverWithSetup(setup, offer)
}

func newPublicSolverWithSetup(setup *verifiedSetup, offer publicOffer) (*verifiedPublicSolver, error) {
	if setup == nil || offer.Setup != setup.raw {
		return nil, fmt.Errorf("offer replaced verified setup")
	}
	order := scalarOrder()
	p, puzzles, proof, bits, err := parsePublicOffer(offer, order)
	if err != nil {
		return nil, err
	}
	valid, err := proofs.VerifyRangePoof(proof, bits, p, puzzles, order)
	if err != nil || !valid {
		return nil, fmt.Errorf("solver range verification failed: %v", err)
	}
	return &verifiedPublicSolver{p, puzzles, order}, nil
}

func (solver *verifiedPublicSolver) solve(index uint16) (opening, float64, error) {
	if index == 0 || int(index) > len(solver.puzzles) {
		return opening{}, 0, fmt.Errorf("invalid solver index")
	}
	started := time.Now()
	value := puzzle.SolvePuzzle(solver.parameters, solver.puzzles[index-1])
	scalar, err := scalarToLittleEndian(value, solver.order)
	if err != nil {
		return opening{}, time.Since(started).Seconds(), err
	}
	return opening{Index: index, Scalar: scalar}, time.Since(started).Seconds(), nil
}

// Independent one-shot mode retained as an audit/control path.
func solvePublic(offer publicOffer, index uint16) (opening, float64, error) {
	if index == 0 || int(index) > len(offer.Puzzles) {
		return opening{}, 0, fmt.Errorf("invalid solver index")
	}
	solver, err := newPublicSolver(offer)
	if err != nil {
		return opening{}, 0, err
	}
	return solver.solve(index)
}

// One bounded newline-delimited JSON value. EOF is only clean with no bytes;
// an unterminated frame, unknown field, trailing value or oversized line fails.
func strictFrame(reader *bufio.Reader, limit int, target any) error {
	line, err := reader.ReadSlice('\n')
	if err == io.EOF && len(line) == 0 {
		return io.EOF
	}
	if err != nil || len(line) > limit {
		return fmt.Errorf("invalid or oversized frame")
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		// A blank line is not the transport's clean EOF: do not silently
		// ignore subsequent requests after a whitespace-only JSON frame.
		return fmt.Errorf("invalid frame JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("trailing frame value")
	}
	return nil
}

func validateSolverIndexes(n int, indexes []uint16) error {
	if n < 2 || n > 512 || n%2 != 0 || len(indexes) != n/2 {
		return fmt.Errorf("invalid solver candidate count")
	}
	var previous uint16
	for _, index := range indexes {
		if index <= previous || int(index) > n {
			return fmt.Errorf("invalid solver candidate set")
		}
		previous = index
	}
	return nil
}

// Request-driven serial search: verify exactly once, solve only the next
// approved index on demand, and stop cleanly on EOF. The Rust caller verifies
// the exact challenge set and every Feldman opening. The Go side enforces
// a sorted unique half-set, request order, bounded frames and bounded work.
func serveSolveSession(input io.Reader, output io.Writer) error {
	const initialLimit = 5 * 1024 * 1024
	reader := bufio.NewReaderSize(input, initialLimit+1)
	var initial struct {
		Offer   publicOffer `json:"offer"`
		Indexes []uint16    `json:"indexes"`
	}
	if err := strictFrame(reader, initialLimit, &initial); err != nil {
		return err
	}
	if err := validateSolverIndexes(len(initial.Offer.Puzzles), initial.Indexes); err != nil {
		return err
	}
	started := time.Now()
	solver, err := newPublicSolver(initial.Offer)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	if err := encoder.Encode(struct {
		Result              string   `json:"result"`
		Indexes             []uint16 `json:"indexes"`
		Verifications       int      `json:"public_offer_verifications"`
		VerificationSeconds float64  `json:"public_verification_seconds"`
		PublicSolver        bool     `json:"public_solver_no_dealer_secrets"`
		SetupVerified       bool     `json:"setup_relation_verified"`
		ProofVerified       bool     `json:"range_proof_verified"`
	}{"ready", initial.Indexes, 1, time.Since(started).Seconds(), true, true, true}); err != nil {
		return err
	}
	return serveVerifiedSolver(reader, encoder, solver, initial.Indexes)
}

// The public verifier receives no puzzles in its first message. It verifies
// the sequential setup relation before acknowledging those exact setup bytes.
// Only then may an honest producer disclose its offer. Retaining this process
// avoids repeating the timed setup work after disclosure or funding.
func servePreparedSession(input io.Reader, output io.Writer) error {
	reader := bufio.NewReaderSize(input, 5*1024*1024+1)
	encoder := json.NewEncoder(output)
	var initial struct {
		Setup string `json:"setup"`
	}
	if err := strictFrame(reader, 128*1024, &initial); err != nil {
		return err
	}
	started := time.Now()
	setup, err := verifyPublicSetup(initial.Setup)
	if err != nil {
		return err
	}
	if err := encoder.Encode(struct {
		Result        string  `json:"result"`
		Binding       string  `json:"setup_binding"`
		Seconds       float64 `json:"setup_verification_seconds"`
		Verifications int     `json:"setup_verifications"`
	}{"setup_ready", setupBinding(setup.raw), time.Since(started).Seconds(), 1}); err != nil {
		return err
	}
	var offered struct {
		Offer   publicOffer `json:"offer"`
		Indexes []uint16    `json:"indexes"`
		Opened  []opening   `json:"opened"`
	}
	if err := strictFrame(reader, 5*1024*1024, &offered); err != nil {
		return err
	}
	if err := validateSolverIndexes(len(offered.Offer.Puzzles), offered.Indexes); err != nil {
		return err
	}
	started = time.Now()
	solver, err := newPublicSolverWithSetup(setup, offered.Offer)
	if err != nil {
		return err
	}
	checked, _, _, err := checkPublicOpenings(solver.parameters, solver.puzzles, offered.Opened, solver.order)
	if err != nil {
		return err
	}
	opened := make(map[uint16]bool)
	for _, item := range offered.Opened {
		opened[item.Index] = true
	}
	for _, index := range offered.Indexes {
		if opened[index] {
			return fmt.Errorf("opened and delayed sets overlap")
		}
	}
	if err := encoder.Encode(struct {
		Result           string   `json:"result"`
		Indexes          []uint16 `json:"indexes"`
		Checked          int      `json:"checked_openings"`
		Binding          string   `json:"setup_binding"`
		Verifications    int      `json:"public_offer_verifications"`
		Seconds          float64  `json:"public_verification_seconds"`
		SetupBeforeOffer bool     `json:"setup_verified_before_offer"`
		PublicSolver     bool     `json:"public_solver_no_dealer_secrets"`
		SetupVerified    bool     `json:"setup_relation_verified"`
		ProofVerified    bool     `json:"range_proof_verified"`
	}{"ready", offered.Indexes, checked, setupBinding(setup.raw), 1, time.Since(started).Seconds(), true, true, true, true}); err != nil {
		return err
	}
	return serveVerifiedSolver(reader, encoder, solver, offered.Indexes)
}

func serveVerifiedSolver(reader *bufio.Reader, encoder *json.Encoder, solver *verifiedPublicSolver, indexes []uint16) error {
	completed := 0
	for {
		var request struct {
			Index uint16 `json:"index"`
		}
		if err := strictFrame(reader, 1024, &request); err != nil {
			if err != io.EOF {
				return err
			}
			return encoder.Encode(struct {
				Result        string `json:"result"`
				Completed     int    `json:"completed"`
				Verifications int    `json:"public_offer_verifications"`
			}{"closed", completed, 1})
		}
		if completed == len(indexes) || request.Index != indexes[completed] {
			return fmt.Errorf("unexpected or exhausted solver index")
		}
		value, duration, err := solver.solve(request.Index)
		if err != nil && !errors.Is(err, errNoncanonicalRecovered) {
			return err
		}
		completed++
		if errors.Is(err, errNoncanonicalRecovered) {
			// Reject this puzzle without reducing its integer modulo the curve
			// order or abandoning other recoverable candidates in the same offer.
			if err := encoder.Encode(struct {
				Result string  `json:"result"`
				Index  uint16  `json:"index"`
				Reason string  `json:"reason"`
				Solve  float64 `json:"solve_seconds"`
			}{"invalid", request.Index, "noncanonical_plaintext", duration}); err != nil {
				return err
			}
			continue
		}
		if err := encoder.Encode(struct {
			Result  string  `json:"result"`
			Opening opening `json:"opening"`
			Solve   float64 `json:"solve_seconds"`
		}{"solved", value, duration}); err != nil {
			return err
		}
	}
}

func solveMode() error {
	var input struct {
		Offer publicOffer `json:"offer"`
		Index uint16      `json:"index"`
	}
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 5*1024*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("trailing solver input")
	}
	result, duration, err := solvePublic(input.Offer, input.Index)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		Result        string  `json:"result"`
		Opening       opening `json:"opening"`
		Solve         float64 `json:"solve_seconds"`
		PublicSolver  bool    `json:"public_solver_no_dealer_secrets"`
		SetupRelation bool    `json:"setup_relation_verified"`
		ProofVerified bool    `json:"range_proof_verified"`
	}{"solved", result, duration, true, true, true})
}

func run(openOnly bool, staged bool) error {
	var input struct {
		Shares [][32]byte `json:"shares"`
	}
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 65536))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return err
	}
	switch len(input.Shares) {
	case 6, 132, 166, 198:
	default:
		return fmt.Errorf("unsupported lab share count")
	}
	order := scalarOrder()
	started := time.Now()
	p, err := params.GenerateParams(2048, 2, big.NewInt(200000))
	if err != nil {
		return err
	}
	setup := time.Since(started).Seconds()
	const rangeBits = 160
	setupRaw := encode(publicSetup{p, rangeBits, order})
	encoder := json.NewEncoder(os.Stdout)
	if staged {
		if err := encoder.Encode(struct {
			Result string `json:"result"`
			Setup  string `json:"setup"`
		}{"setup", setupRaw}); err != nil {
			return err
		}
		var accepted struct {
			Binding string `json:"accepted_setup"`
		}
		if err := decoder.Decode(&accepted); err != nil {
			return err
		}
		if accepted.Binding != setupBinding(setupRaw) {
			return fmt.Errorf("wrong setup acknowledgement")
		}
	}
	started = time.Now()
	puzzles := make([]*puzzle.Puzzle, len(input.Shares))
	witnesses := make([]*proofs.PuzzleValues, len(input.Shares))
	for i, scalar := range input.Shares {
		value, err := scalarFromLittleEndian(scalar, order)
		if err != nil {
			return fmt.Errorf("%w at index %d", err, i+1)
		}
		var nonce *big.Int
		puzzles[i], nonce, err = puzzle.GeneratePuzzleAndReturnNonce(p, value)
		if err != nil {
			return err
		}
		witnesses[i] = proofs.NewPuzzleValues(value, nonce)
	}
	encryption := time.Since(started).Seconds()
	started = time.Now()
	rangeProof, err := proofs.GenerateRangeProof(rangeBits, p, puzzles, order, witnesses)
	if err != nil {
		return err
	}
	proofGeneration := time.Since(started).Seconds()
	started = time.Now()
	valid, err := proofs.VerifyRangePoof(rangeProof, rangeBits, p, puzzles, order)
	if err != nil || !valid {
		return fmt.Errorf("range verification failed: %v", err)
	}
	proofVerification := time.Since(started).Seconds()
	// Negative control, then restore the proof before committing its bytes.
	rangeProof.Values[0].X.Add(rangeProof.Values[0].X, big.NewInt(1))
	valid, err = proofs.VerifyRangePoof(rangeProof, rangeBits, p, puzzles, order)
	if err == nil && valid {
		return fmt.Errorf("mutated range proof accepted")
	}
	rangeProof.Values[0].X.Sub(rangeProof.Values[0].X, big.NewInt(1))
	var offer publicOffer
	offer.Setup = setupRaw
	for _, z := range puzzles {
		offer.Puzzles = append(offer.Puzzles, encode(z))
	}
	offer.Proof = encode(rangeProof)
	if err := encoder.Encode(offer); err != nil {
		return err
	}
	var selection struct {
		Opened  []uint16 `json:"opened"`
		Delayed uint16   `json:"delayed"`
	}
	if err := decoder.Decode(&selection); err != nil {
		return err
	}
	if len(selection.Opened) != len(puzzles)/2 {
		return fmt.Errorf("wrong selection size")
	}
	seen := make(map[uint16]bool)
	for _, index := range selection.Opened {
		if index == 0 || int(index) > len(puzzles) || seen[index] {
			return fmt.Errorf("invalid opened index")
		}
		seen[index] = true
	}
	if selection.Delayed == 0 || int(selection.Delayed) > len(puzzles) || seen[selection.Delayed] {
		return fmt.Errorf("invalid delayed index")
	}
	var output struct {
		Openings             []opening `json:"openings"`
		Setup                float64   `json:"setup_seconds"`
		Encryption           float64   `json:"encryption_seconds"`
		Solve                float64   `json:"solve_seconds"`
		RangeBits            int       `json:"range_bits"`
		ProofGeneration      float64   `json:"proof_generation_seconds"`
		ProofVerification    float64   `json:"proof_verification_seconds"`
		RejectedMutatedProof bool      `json:"rejected_mutated_proof"`
		Opened               []opening `json:"opened"`
		CheckedOpenings      int       `json:"checked_openings"`
		RejectedWrongNonce   bool      `json:"rejected_wrong_nonce"`
		PublicVerified       bool      `json:"public_verified_openings"`
		OpeningVerification  float64   `json:"opening_verification_seconds"`
	}
	started = time.Now()
	for _, index := range selection.Opened {
		w := witnesses[index-1]
		regenerated, err := puzzle.GeneratePuzzleWithCustomNonce(p, w.R, w.X)
		if err != nil || !regenerated.Equal(puzzles[index-1]) {
			return fmt.Errorf("opened puzzle mismatch")
		}
		output.Opened = append(output.Opened, opening{Index: index, Scalar: input.Shares[index-1], Nonce: w.R.String()})
	}
	w := witnesses[selection.Opened[0]-1]
	wrong, err := puzzle.GeneratePuzzleWithCustomNonce(p, new(big.Int).Add(w.R, big.NewInt(1)), w.X)
	if err != nil || wrong.Equal(puzzles[selection.Opened[0]-1]) {
		return fmt.Errorf("wrong nonce control failed")
	}
	output.OpeningVerification = time.Since(started).Seconds()
	output.CheckedOpenings, output.RejectedWrongNonce = len(selection.Opened), true
	started = time.Now()
	if !openOnly {
		for _, index := range []uint16{selection.Delayed} {
			value := puzzle.SolvePuzzle(p, puzzles[index-1])
			scalar, err := scalarToLittleEndian(value, order)
			if err != nil {
				return err
			}
			output.Openings = append(output.Openings, opening{Index: uint16(index), Scalar: scalar})
		}
	}
	output.Setup, output.Encryption, output.Solve = setup, encryption, time.Since(started).Seconds()
	output.RangeBits, output.ProofGeneration, output.ProofVerification = rangeBits, proofGeneration, proofVerification
	output.RejectedMutatedProof = true
	var checked int
	var wrongRejected bool
	if staged {
		checked, wrongRejected, _, err = checkPublicOpenings(p, puzzles, output.Opened, order)
	} else {
		checked, wrongRejected, _, _, err = verifyPublicOpenings(offer, output.Opened)
	}
	if err != nil || checked != len(output.Opened) || !wrongRejected {
		return fmt.Errorf("public verifier rejected producer output: %v", err)
	}
	output.PublicVerified = true
	return json.NewEncoder(os.Stdout).Encode(output)
}

// Optional experimental modes are registered only when their source files
// are explicitly included in the build. The standalone legacy bridge keeps
// its existing modes and dependency set.
var additionalLabModes = map[string]func() error{}

func main() {
	var err error
	if len(os.Args) == 2 && additionalLabModes[os.Args[1]] != nil {
		err = additionalLabModes[os.Args[1]]()
	} else if len(os.Args) == 2 && os.Args[1] == "verify-openings" {
		err = verifyMode()
	} else if len(os.Args) == 2 && os.Args[1] == "solve-public" {
		err = solveMode()
	} else if len(os.Args) == 2 && os.Args[1] == "solve-session" {
		err = serveSolveSession(os.Stdin, os.Stdout)
	} else if len(os.Args) == 2 && os.Args[1] == "prepare-session" {
		err = servePreparedSession(os.Stdin, os.Stdout)
	} else if len(os.Args) == 2 && os.Args[1] == "open-staged" {
		err = run(true, true)
	} else if len(os.Args) == 2 && os.Args[1] == "open-only" {
		err = run(true, false)
	} else if len(os.Args) == 1 {
		err = run(false, false)
	} else {
		err = fmt.Errorf("unknown bridge mode")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
