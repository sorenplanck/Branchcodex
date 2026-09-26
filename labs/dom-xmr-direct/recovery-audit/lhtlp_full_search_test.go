package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/primefactor-io/lhtlp/pkg/params"
	"github.com/primefactor-io/lhtlp/pkg/proofs"
	"github.com/primefactor-io/lhtlp/pkg/puzzle"
)

// Workload measurement only. The fixed odd/even partition is NOT a derived
// Fiat-Shamir challenge or an accepted funded capsule. It makes 98 invalid
// delayed plaintexts and one valid last candidate feasible to exercise without
// grinding an exponentially unlikely challenge. Run explicitly with
// -run '^$' -bench '^BenchmarkPreparedSearch198$' -benchtime=1x.
func BenchmarkPreparedSearch198(b *testing.B) {
	for iteration := 0; iteration < b.N; iteration++ {
		total := time.Now()
		p, err := params.GenerateParams(2048, 2, big.NewInt(200000))
		if err != nil {
			b.Fatal(err)
		}
		order := scalarOrder()
		offer := publicOffer{Setup: encode(publicSetup{p, 160, order})}
		started := time.Now()
		setup, err := verifyPublicSetup(offer.Setup)
		if err != nil {
			b.Fatal(err)
		}
		setupSeconds := time.Since(started).Seconds()
		puzzles := make([]*puzzle.Puzzle, 198)
		witnesses := make([]*proofs.PuzzleValues, len(puzzles))
		var opened []opening
		var indexes []uint16
		var expectedLast [32]byte
		for i := range puzzles {
			value, err := rand.Int(rand.Reader, order)
			if err != nil {
				b.Fatal(err)
			}
			if i%2 == 0 && i != 196 {
				value = new(big.Int).Add(order, big.NewInt(1))
			}
			var nonce *big.Int
			puzzles[i], nonce, err = puzzle.GeneratePuzzleAndReturnNonce(p, value)
			if err != nil {
				b.Fatal(err)
			}
			witnesses[i] = proofs.NewPuzzleValues(value, nonce)
			offer.Puzzles = append(offer.Puzzles, encode(puzzles[i]))
			if i%2 == 0 {
				indexes = append(indexes, uint16(i+1))
			} else {
				scalar, err := scalarToLittleEndian(value, order)
				if err != nil {
					b.Fatal(err)
				}
				opened = append(opened, opening{Index: uint16(i + 1), Scalar: scalar, Nonce: nonce.String()})
			}
			if i == 196 {
				expectedLast, err = scalarToLittleEndian(value, order)
				if err != nil {
					b.Fatal(err)
				}
			}
		}
		proof, err := proofs.GenerateRangeProof(160, p, puzzles, order, witnesses)
		if err != nil {
			b.Fatal(err)
		}
		offer.Proof = encode(proof)
		started = time.Now()
		solver, err := newPublicSolverWithSetup(setup, offer)
		if err != nil {
			b.Fatal(err)
		}
		if _, _, _, err := checkPublicOpenings(solver.parameters, solver.puzzles, opened, order); err != nil {
			b.Fatal(err)
		}
		if err := validateSolverIndexes(len(puzzles), indexes); err != nil {
			b.Fatal(err)
		}
		verificationSeconds := time.Since(started).Seconds()
		preparationSeconds := time.Since(total).Seconds()
		var requests strings.Builder
		for _, index := range indexes {
			requests.WriteString(encode(struct {
				Index uint16 `json:"index"`
			}{index}) + "\n")
		}
		var output bytes.Buffer
		started = time.Now()
		if err := serveVerifiedSolver(bufio.NewReader(strings.NewReader(requests.String())), json.NewEncoder(&output), solver, indexes); err != nil {
			b.Fatal(err)
		}
		recoverySeconds := time.Since(started).Seconds()
		decoder := json.NewDecoder(&output)
		solveSeconds := 0.0
		for i, index := range indexes {
			var result struct {
				Result  string  `json:"result"`
				Index   uint16  `json:"index"`
				Reason  string  `json:"reason"`
				Opening opening `json:"opening"`
				Seconds float64 `json:"solve_seconds"`
			}
			if err := decoder.Decode(&result); err != nil {
				b.Fatal(err)
			}
			solveSeconds += result.Seconds
			if i < 98 {
				if result.Result != "invalid" || result.Index != index || result.Reason != "noncanonical_plaintext" {
					b.Fatalf("candidate %d was not rejected", index)
				}
			} else if result.Result != "solved" || result.Opening.Index != index || result.Opening.Scalar != expectedLast {
				b.Fatal("last candidate did not recover")
			}
		}
		var closed struct {
			Result        string `json:"result"`
			Completed     int    `json:"completed"`
			Verifications int    `json:"public_offer_verifications"`
		}
		if err := decoder.Decode(&closed); err != nil || closed.Result != "closed" || closed.Completed != 99 || closed.Verifications != 1 || decoder.More() {
			b.Fatal("inexact completion", closed, err)
		}
		b.Logf("FULL_SEARCH_RESULT=%s", encode(map[string]any{
			"experiment":   "fixed-partition public search workload",
			"participants": 198, "delayed_candidates": 99, "rejected_noncanonical": 98,
			"last_candidate_recovered": true, "squarings": 200000,
			"setup_verification_seconds":             setupSeconds,
			"offer_and_opening_verification_seconds": verificationSeconds,
			"preparation_seconds":                    preparationSeconds, "sequential_solve_seconds": solveSeconds,
			"recovery_session_seconds": recoverySeconds, "total_seconds": time.Since(total).Seconds(),
			"derived_challenge": false, "feldman_checks_included": false,
			"process_ipc_included": false, "funding_included": false,
			"worst_case_time_bound_proven": false, "minimum_adversarial_delay_proven": false,
		}))
	}
}
