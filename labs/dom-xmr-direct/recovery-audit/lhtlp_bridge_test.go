package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/primefactor-io/lhtlp/pkg/params"
	"github.com/primefactor-io/lhtlp/pkg/proofs"
	"github.com/primefactor-io/lhtlp/pkg/puzzle"
)

func TestPublicSolverRejectsInvalidIndexesAndUnverifiedProof(t *testing.T) {
	for _, index := range []uint16{0, 1, 65535} {
		if _, _, err := solvePublic(publicOffer{}, index); err == nil {
			t.Fatal("accepted missing puzzle")
		}
	}
	p, proof, offer := publicShapeFixture(t)
	validShape := offerWithSetup(p, proof, offer)
	for _, index := range []uint16{0, 3, 65535} {
		if _, _, err := solvePublic(validShape, index); err == nil {
			t.Fatal("accepted out-of-range puzzle")
		}
	}
	// The all-identity fixture can satisfy the zero-message equations. Change
	// one response so this is an actually false relation, not just synthetic.
	proof.Values[0].X = big.NewInt(1)
	if _, _, err := solvePublic(offerWithSetup(p, proof, offer), 1); err == nil {
		t.Fatal("accepted an unverified public range proof")
	}
}

func sessionFixture(t *testing.T) publicOffer {
	t.Helper()
	p, proof, offer := publicShapeFixture(t)
	for len(offer.Puzzles) < 6 {
		offer.Puzzles = append(offer.Puzzles, offer.Puzzles[0])
	}
	return offerWithSetup(p, proof, offer)
}

func sessionInput(offer publicOffer, indexes []uint16, commands string) string {
	return encode(struct {
		Offer   publicOffer `json:"offer"`
		Indexes []uint16    `json:"indexes"`
	}{offer, indexes}) + "\n" + commands
}

func sessionFrames(t *testing.T, output *bytes.Buffer) []map[string]any {
	t.Helper()
	decoder := json.NewDecoder(output)
	var frames []map[string]any
	for {
		var frame map[string]any
		if err := decoder.Decode(&frame); err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal(err)
		}
		frames = append(frames, frame)
	}
	return frames
}

func TestPublicSessionVerifiesOnceAndStopsWithoutSolvingUnrequestedIndex(t *testing.T) {
	input := sessionInput(sessionFixture(t), []uint16{1, 3, 5}, "{\"index\":1}\n{\"index\":3}\n")
	var output bytes.Buffer
	if err := serveSolveSession(strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	frames := sessionFrames(t, &output)
	if len(frames) != 4 || frames[0]["result"] != "ready" || frames[3]["result"] != "closed" ||
		frames[0]["public_offer_verifications"] != float64(1) || frames[3]["public_offer_verifications"] != float64(1) ||
		frames[3]["completed"] != float64(2) {
		t.Fatalf("unexpected session frames: %v", frames)
	}
	for i, index := range []float64{1, 3} {
		if frames[i+1]["result"] != "solved" || frames[i+1]["opening"].(map[string]any)["index"] != index {
			t.Fatal("wrong solver result order")
		}
	}
}

func TestPublicSessionRejectsReplacementRepeatedAndExhaustedRequests(t *testing.T) {
	offer := sessionFixture(t)
	for _, commands := range []string{
		"{\"index\":3}\n",
		"{\"index\":1}\n{\"index\":1}\n",
		"{\"offer\":{}}\n",
		"{\"index\":1}\n{\"index\":3}\n{\"index\":5}\n{\"index\":5}\n",
		"{\"index\":1}",
		"\n{\"index\":1}\n",
	} {
		var output bytes.Buffer
		if err := serveSolveSession(strings.NewReader(sessionInput(offer, []uint16{1, 3, 5}, commands)), &output); err == nil {
			t.Fatalf("accepted hostile request %q", commands)
		}
		frames := sessionFrames(t, &output)
		if len(frames) == 0 || frames[0]["result"] != "ready" {
			t.Fatal("did not reach verified session")
		}
		for _, frame := range frames {
			if frame["result"] == "closed" {
				t.Fatal("reported successful closure after invalid request")
			}
		}
	}
	for _, indexes := range [][]uint16{{}, {1, 3}, {0, 3, 5}, {1, 1, 5}, {3, 1, 5}, {1, 3, 7}} {
		var output bytes.Buffer
		if err := serveSolveSession(strings.NewReader(sessionInput(offer, indexes, "")), &output); err == nil || output.Len() != 0 {
			t.Fatal("accepted invalid candidate set before verification")
		}
	}
}

func TestPublicSessionDoesNotReleaseReadyForInvalidProof(t *testing.T) {
	p, proof, offer := publicShapeFixture(t)
	proof.Values[0].X = big.NewInt(1)
	var output bytes.Buffer
	if err := serveSolveSession(strings.NewReader(sessionInput(offerWithSetup(p, proof, offer), []uint16{1}, "")), &output); err == nil || output.Len() != 0 {
		t.Fatal("unverified capsule reached ready state")
	}
}

func TestVerifiedSolverRetainsParsedSnapshot(t *testing.T) {
	offer := sessionFixture(t)
	solver, err := newPublicSolver(offer)
	if err != nil {
		t.Fatal(err)
	}
	offer.Setup = "null"
	offer.Proof = "null"
	offer.Puzzles[0] = "null"
	value, _, err := solver.solve(1)
	if err != nil || value.Index != 1 || value.Scalar != [32]byte{} {
		t.Fatal("verified snapshot changed with caller input")
	}
}

// A range proof is not a canonical-scalar decoder. Keep this counterexample
// explicit: an accepted public offer may contain a delayed integer >= q.
func TestAcceptedRangeProofCanContainNoncanonicalPlaintext(t *testing.T) {
	p, err := params.GenerateParams(2048, 2, big.NewInt(200000))
	if err != nil {
		t.Fatal(err)
	}
	order := scalarOrder()
	puzzles := make([]*puzzle.Puzzle, 6)
	witnesses := make([]*proofs.PuzzleValues, 6)
	var offer publicOffer
	for i := range puzzles {
		value := big.NewInt(int64(i + 1))
		if i == 0 {
			value.Add(order, big.NewInt(1))
		}
		var nonce *big.Int
		puzzles[i], nonce, err = puzzle.GeneratePuzzleAndReturnNonce(p, value)
		if err != nil {
			t.Fatal(err)
		}
		witnesses[i] = proofs.NewPuzzleValues(value, nonce)
		offer.Puzzles = append(offer.Puzzles, encode(puzzles[i]))
	}
	proof, err := proofs.GenerateRangeProof(160, p, puzzles, order, witnesses)
	if err != nil {
		t.Fatal(err)
	}
	offer = offerWithSetup(p, proof, offer)
	solver, err := newPublicSolver(offer)
	if err != nil {
		t.Fatal("public offer rejected before the counterexample:", err)
	}
	if _, _, err = solver.solve(1); err == nil {
		t.Fatal("noncanonical recovered scalar accepted")
	}
	valid, _, err := solver.solve(2)
	if err != nil || valid.Scalar[0] != 2 {
		t.Fatal("remaining honest puzzle did not recover")
	}
	t.Log("range verification accepted q+1; canonical decoding rejected it; another puzzle remained recoverable")
	var output bytes.Buffer
	input := sessionInput(offer, []uint16{1, 3, 5}, "{\"index\":1}\n{\"index\":3}\n")
	if err := serveSolveSession(strings.NewReader(input), &output); err != nil {
		t.Fatal("noncanonical candidate aborted recovery:", err)
	}
	frames := sessionFrames(t, &output)
	if len(frames) != 4 || frames[1]["result"] != "invalid" || frames[1]["index"] != float64(1) ||
		frames[1]["reason"] != "noncanonical_plaintext" || frames[1]["solve_seconds"].(float64) <= 0 ||
		frames[2]["result"] != "solved" || frames[2]["opening"].(map[string]any)["index"] != float64(3) ||
		frames[3]["completed"] != float64(2) {
		t.Fatal("incorrect fallback evidence", frames)
	}
}

func TestSessionFramesRejectUnboundedOrAmbiguousMessages(t *testing.T) {
	for _, input := range []string{"\n", " \t\n", "{\"index\":1}", "{\"index\":1} {}\n", "{\"unknown\":1}\n", strings.Repeat(" ", 1024) + "{}\n"} {
		var target struct {
			Index uint16 `json:"index"`
		}
		if err := strictFrame(bufio.NewReaderSize(strings.NewReader(input), 2048), 1024, &target); err == nil {
			t.Fatalf("accepted invalid frame %q", input)
		}
	}
}

func preparedOfferFrame(offer publicOffer, indexes []uint16, opened []opening) string {
	return encode(struct {
		Offer   publicOffer `json:"offer"`
		Indexes []uint16    `json:"indexes"`
		Opened  []opening   `json:"opened"`
	}{offer, indexes, opened}) + "\n"
}

func zeroOpenings() []opening {
	return []opening{{Index: 2, Nonce: "0"}, {Index: 4, Nonce: "0"}, {Index: 6, Nonce: "0"}}
}

func TestPreparedSessionCompletesSetupBeforeReceivingAnyPuzzles(t *testing.T) {
	offer := sessionFixture(t)
	inputReader, inputWriter := io.Pipe()
	outputReader, outputWriter := io.Pipe()
	defer inputReader.Close()
	defer inputWriter.Close()
	defer outputReader.Close()
	defer outputWriter.Close()
	done := make(chan error, 1)
	go func() {
		err := servePreparedSession(inputReader, outputWriter)
		outputWriter.CloseWithError(err)
		done <- err
	}()
	decoder := json.NewDecoder(outputReader)
	read := func() map[string]any {
		result := make(chan map[string]any, 1)
		errors := make(chan error, 1)
		go func() {
			var frame map[string]any
			if err := decoder.Decode(&frame); err != nil {
				errors <- err
			} else {
				result <- frame
			}
		}()
		select {
		case frame := <-result:
			return frame
		case err := <-errors:
			t.Fatal(err)
		case <-time.After(10 * time.Second):
			t.Fatal("staged handshake stalled")
		}
		return nil
	}
	if _, err := io.WriteString(inputWriter, encode(map[string]string{"setup": offer.Setup})+"\n"); err != nil {
		t.Fatal(err)
	}
	setup := read()
	if setup["result"] != "setup_ready" || setup["setup_binding"] != setupBinding(offer.Setup) || setup["setup_verifications"] != float64(1) {
		t.Fatal("setup not independently verified", setup)
	}
	// No puzzle bytes have been sent to the verifier before this point.
	if _, err := io.WriteString(inputWriter, preparedOfferFrame(offer, []uint16{1, 3, 5}, zeroOpenings())); err != nil {
		t.Fatal(err)
	}
	ready := read()
	if ready["result"] != "ready" || ready["checked_openings"] != float64(3) || ready["setup_verified_before_offer"] != true {
		t.Fatal("offer not verified after setup", ready)
	}
	if _, err := io.WriteString(inputWriter, "{\"index\":1}\n"); err != nil {
		t.Fatal(err)
	}
	if solved := read(); solved["result"] != "solved" {
		t.Fatal(solved)
	}
	inputWriter.Close()
	if closed := read(); closed["result"] != "closed" || closed["completed"] != float64(1) {
		t.Fatal(closed)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPreparedSessionRejectsSetupReplacementFalseProofAndBadOpenings(t *testing.T) {
	original := sessionFixture(t)
	for _, name := range []string{"replacement", "invalid proof", "wrong nonce", "overlap", "missing offer"} {
		t.Run(name, func(t *testing.T) {
			offer := original
			opened := zeroOpenings()
			switch name {
			case "replacement":
				offer.Setup = " " + offer.Setup
			case "invalid proof":
				_, _, proof, _, err := parsePublicOffer(offer, scalarOrder())
				if err != nil {
					t.Fatal(err)
				}
				proof.Values[0].X = big.NewInt(1)
				offer.Proof = encode(proof)
			case "wrong nonce":
				opened[0].Nonce = "1"
			case "overlap":
				opened[0].Index = 1
			}
			input := encode(map[string]string{"setup": original.Setup}) + "\n"
			if name != "missing offer" {
				input += preparedOfferFrame(offer, []uint16{1, 3, 5}, opened)
			}
			var output bytes.Buffer
			if err := servePreparedSession(strings.NewReader(input), &output); err == nil {
				t.Fatal("invalid staged offer accepted")
			}
			frames := sessionFrames(t, &output)
			if len(frames) != 1 || frames[0]["result"] != "setup_ready" {
				t.Fatal("bad offer reached solver", frames)
			}
		})
	}
}

func TestPreparedSessionRejectsFalseSetupAndPrematureOffer(t *testing.T) {
	p, proof, offer := publicShapeFixture(t)
	p.H = new(big.Int).Mul(p.H, p.G)
	p.H.Mod(p.H, p.N)
	offer = offerWithSetup(p, proof, offer)
	for _, input := range []string{
		encode(map[string]string{"setup": offer.Setup}) + "\n",
		preparedOfferFrame(offer, []uint16{1}, nil),
	} {
		var output bytes.Buffer
		if err := servePreparedSession(strings.NewReader(input), &output); err == nil || output.Len() != 0 {
			t.Fatal("invalid first stage acknowledged")
		}
	}
}

// Synthetic identity/zero fixtures isolate parser rejection. They may satisfy
// the trivial zero-message relation; the Rust bridge tests real random puzzles.
func publicShapeFixture(t *testing.T) (*params.Params, *proofs.RangeProof, publicOffer) {
	t.Helper()
	p, err := params.GenerateParams(2048, 2, big.NewInt(200000))
	if err != nil {
		t.Fatal(err)
	}
	proof := &proofs.RangeProof{}
	for i := 0; i < 160; i++ {
		proof.D = append(proof.D, puzzle.NewPuzzle(big.NewInt(1), big.NewInt(1)))
		proof.Values = append(proof.Values, proofs.NewPuzzleValues(big.NewInt(0), big.NewInt(0)))
	}
	offer := publicOffer{Puzzles: []string{encode(proof.D[0]), encode(proof.D[1])}}
	return p, proof, offer
}

func offerWithSetup(p *params.Params, proof *proofs.RangeProof, offer publicOffer) publicOffer {
	offer.Setup = encode(struct {
		Parameters  *params.Params
		RangeBits   int
		ScalarOrder *big.Int
	}{p, 160, scalarOrder()})
	offer.Proof = encode(proof)
	return offer
}

func TestPublicParserRejectsMalformedInputsBeforeArithmetic(t *testing.T) {
	p, proof, offer := publicShapeFixture(t)
	valid := offerWithSetup(p, proof, offer)
	if _, _, _, _, err := parsePublicOffer(valid, scalarOrder()); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*params.Params, *proofs.RangeProof, *publicOffer)
	}{
		{"nil modulus", func(p *params.Params, _ *proofs.RangeProof, _ *publicOffer) { p.N = nil }},
		{"zero modulus", func(p *params.Params, _ *proofs.RangeProof, _ *publicOffer) { p.N = big.NewInt(0) }},
		{"wrong exponent", func(p *params.Params, _ *proofs.RangeProof, _ *publicOffer) { p.Y = 3 }},
		{"zero difficulty", func(p *params.Params, _ *proofs.RangeProof, _ *publicOffer) { p.T = big.NewInt(0) }},
		{"missing difficulty", func(p *params.Params, _ *proofs.RangeProof, _ *publicOffer) { p.T = nil }},
		{"wrong modulus power", func(p *params.Params, _ *proofs.RangeProof, _ *publicOffer) { p.NExpY = p.N }},
		{"missing modulus power", func(p *params.Params, _ *proofs.RangeProof, _ *publicOffer) { p.NExpYMinusOne = nil }},
		{"identity generator", func(p *params.Params, _ *proofs.RangeProof, _ *publicOffer) { p.G = big.NewInt(1) }},
		{"missing generator", func(p *params.Params, _ *proofs.RangeProof, _ *publicOffer) { p.G = nil }},
		{"order two generator", func(p *params.Params, _ *proofs.RangeProof, _ *publicOffer) {
			p.G = new(big.Int).Sub(p.N, big.NewInt(1))
		}},
		{"missing delayed element", func(p *params.Params, _ *proofs.RangeProof, _ *publicOffer) { p.H = nil }},
		{"truncated proof", func(_ *params.Params, p *proofs.RangeProof, _ *publicOffer) {
			p.D = p.D[:159]
			p.Values = p.Values[:159]
		}},
		{"excess proof", func(_ *params.Params, p *proofs.RangeProof, _ *publicOffer) {
			p.D = append(p.D, p.D[0])
			p.Values = append(p.Values, p.Values[0])
		}},
		{"nil proof puzzle", func(_ *params.Params, p *proofs.RangeProof, _ *publicOffer) { p.D[0] = nil }},
		{"nil proof response", func(_ *params.Params, p *proofs.RangeProof, _ *publicOffer) { p.Values[0] = nil }},
		{"nil response scalar", func(_ *params.Params, p *proofs.RangeProof, _ *publicOffer) { p.Values[0].X = nil }},
		{"negative response nonce", func(_ *params.Params, p *proofs.RangeProof, _ *publicOffer) { p.Values[0].R = big.NewInt(-1) }},
		{"oversized response nonce", func(s *params.Params, p *proofs.RangeProof, _ *publicOffer) {
			p.Values[0].R = new(big.Int).Mul(s.NExpY, big.NewInt(4))
		}},
		{"oversized response scalar", func(_ *params.Params, p *proofs.RangeProof, _ *publicOffer) {
			p.Values[0].X = new(big.Int).Mul(scalarOrder(), big.NewInt(8))
		}},
		{"null puzzle", func(_ *params.Params, _ *proofs.RangeProof, o *publicOffer) { o.Puzzles[0] = "null" }},
		{"nonunit puzzle", func(p *params.Params, _ *proofs.RangeProof, o *publicOffer) {
			o.Puzzles[0] = encode(puzzle.NewPuzzle(p.N, big.NewInt(1)))
		}},
		{"odd puzzle count", func(_ *params.Params, _ *proofs.RangeProof, o *publicOffer) { o.Puzzles = o.Puzzles[:1] }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			// Parse a new copy so negative cases cannot corrupt one another.
			p, puzzles, proof, _, err := parsePublicOffer(valid, scalarOrder())
			if err != nil {
				t.Fatal(err)
			}
			offer := publicOffer{}
			for _, z := range puzzles {
				offer.Puzzles = append(offer.Puzzles, encode(z))
			}
			test.mutate(p, proof, &offer)
			if _, _, _, _, err := parsePublicOffer(offerWithSetup(p, proof, offer), scalarOrder()); err == nil {
				t.Fatal("malformed offer accepted")
			}
		})
	}
}

func TestPublicSetupRelationRejectsFalseDelayedElement(t *testing.T) {
	p, _, _ := publicShapeFixture(t)
	if err := verifySetupRelation(p); err != nil {
		t.Fatal(err)
	}
	p.H = new(big.Int).Mul(p.H, p.G)
	p.H.Mod(p.H, p.N)
	if err := validateParameters(p); err != nil {
		t.Fatal(err)
	}
	if err := verifySetupRelation(p); err == nil {
		t.Fatal("accepted false delayed element")
	}
}
