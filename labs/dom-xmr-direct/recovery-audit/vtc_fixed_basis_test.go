package vtc

import (
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/primefactor-io/ecc/pkg/curves"
	"github.com/primefactor-io/ecc/pkg/elliptic"
	lparams "github.com/primefactor-io/lhtlp/pkg/params"
	"github.com/primefactor-io/lhtlp/pkg/proofs"
	"github.com/primefactor-io/lhtlp/pkg/puzzle"
	"github.com/primefactor-io/vtc/pkg/params"
	"github.com/primefactor-io/vtc/pkg/sss"
)

func TestDelayedPuzzleSequentialCost(t *testing.T) {
	const squarings = 200000
	started := time.Now()
	p, err := lparams.GenerateParams(2048, 2, big.NewInt(squarings))
	if err != nil {
		t.Fatal(err)
	}
	setup := time.Since(started)
	secret, err := curves.Secp256k1.GetRandomScalar()
	if err != nil {
		t.Fatal(err)
	}
	started = time.Now()
	capsule, err := puzzle.GeneratePuzzle(p, secret)
	if err != nil {
		t.Fatal(err)
	}
	generation := time.Since(started)
	started = time.Now()
	recovered := puzzle.SolvePuzzle(p, capsule)
	solve := time.Since(started)
	if recovered.Cmp(secret) != 0 {
		t.Fatal("delayed puzzle opened to wrong scalar")
	}
	t.Logf("RSA=2048 y=2 squarings=%d setup=%s generation=%s solve=%s; local throughput only, no adversarial lower bound or wall-clock guarantee", squarings, setup, generation, solve)
}

// Rejected repair experiment, not a backend or a replacement verifier.
// Standard indexed interpolation does not match upstream's fixed-basis share
// generation. This helper verifies that changing only the solver is insufficient.
func recoverFromVerifiedWindow(p *params.Params, point *elliptic.Point, c *TimedCommitment) (*big.Int, int, error) {
	valid, err := VerifyTimedCommitment(p, point, c)
	if err != nil || !valid {
		return nil, 0, fmt.Errorf("commitment not verified: %v", err)
	}
	opened := generateIndexValues(p, point, c.RangeProof, c.PointShares, c.Puzzles)
	attempts := 0
	for candidate := 0; candidate < p.N; candidate++ {
		if containsIndex(opened, candidate) {
			continue
		}
		attempts++
		delayed := puzzle.SolvePuzzle(p.PuzzleParams, c.Puzzles[candidate])
		if delayed.Sign() < 0 || delayed.Cmp(p.Q) >= 0 {
			continue
		}
		delayedPoint, err := p.Curve.ScalarMultiply(delayed, p.Curve.G())
		if err != nil || !delayedPoint.Equal(c.PointShares[candidate]) {
			continue
		}
		indexes := append(append([]int(nil), opened...), candidate)
		values := append(append([]*big.Int(nil), c.PuzzleValues...), delayed)
		secret := new(big.Int)
		for i, index := range indexes {
			xi := big.NewInt(int64(index + 1))
			numerator, denominator := big.NewInt(1), big.NewInt(1)
			for j, other := range indexes {
				if i == j {
					continue
				}
				xj := big.NewInt(int64(other + 1))
				numerator.Mul(numerator, new(big.Int).Neg(xj)).Mod(numerator, p.Q)
				denominator.Mul(denominator, new(big.Int).Sub(xi, xj)).Mod(denominator, p.Q)
			}
			inverse := new(big.Int).ModInverse(denominator, p.Q)
			if inverse == nil {
				return nil, attempts, fmt.Errorf("noninvertible indexes")
			}
			term := new(big.Int).Mul(numerator, inverse)
			term.Mul(term, values[i])
			secret.Add(secret, term).Mod(secret, p.Q)
		}
		public, err := p.Curve.ScalarMultiply(secret, p.Curve.G())
		if err == nil && public.Equal(point) {
			return secret, attempts, nil
		}
	}
	return nil, attempts, fmt.Errorf("no delayed share recovered the committed point")
}

func containsIndex(indexes []int, needle int) bool {
	for _, index := range indexes {
		if index == needle {
			return true
		}
	}
	return false
}

func TestAcceptedCommitmentCanRecoverWrongScalar(t *testing.T) {
	curve := curves.Secp256k1
	q := curves.Secp256k1.N()
	params, err := params.GenerateParams(curve, 20, 3, 256, 2048, 40, big.NewInt(1), q)
	if err != nil {
		t.Fatalf("generate params: %v", err)
	}

	scalar, err := curve.GetRandomScalar()
	if err != nil {
		t.Fatalf("sample scalar: %v", err)
	}
	point, err := curve.ScalarMultiply(scalar, curve.G())
	if err != nil {
		t.Fatalf("derive point: %v", err)
	}

	honest, err := GenerateTimedCommitment(params, scalar, point)
	if err != nil {
		t.Fatalf("honest commitment: %v", err)
	}
	valid, err := VerifyTimedCommitment(params, point, honest)
	if err != nil {
		t.Fatalf("honest verify: %v", err)
	}
	if !valid {
		t.Fatalf("honest commitment rejected")
	}
	recovered, err := SolveTimedCommitment(params, honest)
	if err != nil {
		t.Fatalf("honest solve: %v", err)
	}
	if recovered.Cmp(scalar) != 0 {
		t.Fatalf("honest recovery mismatch: want %v got %v", scalar, recovered)
	}

	shares, err := sss.GenerateShares(params, scalar, point)
	if err != nil {
		t.Fatalf("generate shares: %v", err)
	}

	badShare := new(big.Int).Add(shares.ScalarShares[0], big.NewInt(1))
	badShare.Mod(badShare, q)

	for attempt := 0; attempt < 64; attempt++ {
		xs := make([]*big.Int, params.N)
		rs := make([]*big.Int, params.N)
		puzzles := make([]*puzzle.Puzzle, params.N)
		witnesses := make([]*proofs.PuzzleValues, params.N)

		for i := range params.N {
			xi := new(big.Int).Set(shares.ScalarShares[i])
			if i == 0 {
				xi = new(big.Int).Set(badShare)
			}

			zi, ri, err := puzzle.GeneratePuzzleAndReturnNonce(params.PuzzleParams, xi)
			if err != nil {
				t.Fatalf("generate puzzle %d: %v", i, err)
			}

			xs[i] = xi
			rs[i] = ri
			puzzles[i] = zi
			witnesses[i] = proofs.NewPuzzleValues(xi, ri)
		}

		rangeProof, err := proofs.GenerateRangeProof(params.RangeProofBits, params.PuzzleParams, puzzles, q, witnesses)
		if err != nil {
			t.Fatalf("range proof: %v", err)
		}

		indexes := generateIndexValues(params, point, rangeProof, shares.PointShares, puzzles)
		if containsIndex(indexes, 0) {
			continue
		}

		openedNonces := make([]*big.Int, len(indexes))
		openedValues := make([]*big.Int, len(indexes))
		for i, index := range indexes {
			openedNonces[i] = rs[index]
			openedValues[i] = xs[index]
		}

		forged := NewTimedCommitment(shares.PointShares, puzzles, openedNonces, openedValues, rangeProof)
		valid, err := VerifyTimedCommitment(params, point, forged)
		if err != nil {
			t.Fatalf("forged verify: %v", err)
		}
		if !valid {
			t.Fatalf("forged commitment rejected with indexes %v", indexes)
		}

		recovered, err := SolveTimedCommitment(params, forged)
		if err != nil {
			t.Fatalf("forged solve: %v", err)
		}
		if recovered.Cmp(scalar) == 0 {
			t.Fatalf("forged commitment unexpectedly recovered the original scalar")
		}

		recoveredPoint, err := curve.ScalarMultiply(recovered, curve.G())
		if err != nil {
			t.Fatalf("derive recovered point: %v", err)
		}
		if recoveredPoint.Equal(point) {
			t.Fatalf("forged commitment recovered a scalar matching the public point")
		}
		t.Logf("accepted forged commitment with opened indexes %v; recovered scalar no longer matches the committed public point", indexes)
		started := time.Now()
		corrected, attempts, err := recoverFromVerifiedWindow(params, point, forged)
		if err == nil || corrected != nil {
			t.Fatal("unexpected success from incompatible indexed interpolation")
		}
		if attempts != params.N-len(indexes) {
			t.Fatalf("expected all unopened candidates to be checked; got %d attempts", attempts)
		}
		t.Logf("solver-only repair rejected: all %d unopened puzzles checked in %s, no indexed reconstruction matches the committed point; difficulty=1", attempts, time.Since(started))
		return
	}

	t.Fatalf("could not sample a Fiat-Shamir challenge excluding the forged first share")
}
