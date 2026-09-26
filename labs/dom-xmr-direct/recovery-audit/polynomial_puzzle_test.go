package vtc

import (
	"math/big"
	"testing"
	"time"

	"github.com/primefactor-io/ecc/pkg/curves"
	"github.com/primefactor-io/ecc/pkg/elliptic"
	lparams "github.com/primefactor-io/lhtlp/pkg/params"
	"github.com/primefactor-io/lhtlp/pkg/puzzle"
)

// This is a new composition experiment, not an adapter for upstream's share
// generator. It deliberately does not provide a pre-funding capsule verifier:
// the open subset is a fixture, not a sound Fiat-Shamir challenge.
func TestPolynomialRecoveryWithRealDelayedPuzzles(t *testing.T) {
	curve := curves.Secp256k1
	q := curve.N()
	const threshold, participants = 3, 6
	const squarings = 200000
	started := time.Now()
	parameters, err := lparams.GenerateParams(2048, 2, big.NewInt(squarings))
	if err != nil {
		t.Fatal(err)
	}
	setupTime := time.Since(started)

	coefficients := make([]*big.Int, threshold)
	commitments := make([]*elliptic.Point, threshold)
	for i := range coefficients {
		coefficients[i], err = curve.GetRandomScalar()
		if err != nil {
			t.Fatal(err)
		}
		commitments[i], err = curve.ScalarMultiply(coefficients[i], curve.G())
		if err != nil {
			t.Fatal(err)
		}
	}
	// Only this fixture generator retains the polynomial. The recovery closure
	// below receives public commitments, opened values and encrypted puzzles.
	shares := make([]*big.Int, participants)
	puzzles := make([]*puzzle.Puzzle, participants)
	started = time.Now()
	for i := range shares {
		x := big.NewInt(int64(i + 1))
		shares[i] = new(big.Int)
		for j := threshold - 1; j >= 0; j-- {
			shares[i].Mul(shares[i], x).Add(shares[i], coefficients[j]).Mod(shares[i], q)
		}
		plaintext := new(big.Int).Set(shares[i])
		if i == 0 {
			plaintext.Add(plaintext, big.NewInt(1)).Mod(plaintext, q)
		}
		puzzles[i], err = puzzle.GeneratePuzzle(parameters, plaintext)
		if err != nil {
			t.Fatal(err)
		}
	}
	generationTime := time.Since(started)

	verifyShare := func(index int, value *big.Int) bool {
		if index < 0 || index >= participants || value == nil || value.Sign() < 0 || value.Cmp(q) >= 0 {
			return false
		}
		x, power := big.NewInt(int64(index+1)), big.NewInt(1)
		expected := elliptic.NewPoint(big.NewInt(0), big.NewInt(0))
		for _, commitment := range commitments {
			term, e := curve.ScalarMultiply(power, commitment)
			if e != nil {
				return false
			}
			expected, e = curve.Add(expected, term)
			if e != nil {
				return false
			}
			power.Mul(power, x).Mod(power, q)
		}
		actual, e := curve.ScalarMultiply(value, curve.G())
		return e == nil && actual.Equal(expected)
	}

	// Non-prefix opened indexes distinguish this from the rejected fixed basis.
	opened := []int{1, 4}
	openedValues := []*big.Int{new(big.Int).Set(shares[1]), new(big.Int).Set(shares[4])}
	for i, index := range opened {
		if !verifyShare(index, openedValues[i]) {
			t.Fatal("invalid opened share")
		}
	}
	for _, badIndex := range []int{-1, participants} {
		if verifyShare(badIndex, openedValues[0]) {
			t.Fatal("invalid index accepted")
		}
	}
	if verifyShare(opened[0], new(big.Int).Add(openedValues[0], big.NewInt(1))) {
		t.Fatal("forged opened share accepted")
	}

	started = time.Now()
	attempts, rejected := 0, 0
	var recovered *big.Int
	for candidate := 0; candidate < participants; candidate++ {
		if containsIndex(opened, candidate) {
			continue
		}
		attempts++
		value := puzzle.SolvePuzzle(parameters, puzzles[candidate])
		if !verifyShare(candidate, value) {
			rejected++
			continue
		}
		indexes := append(append([]int(nil), opened...), candidate)
		values := append(append([]*big.Int(nil), openedValues...), value)
		recovered = new(big.Int)
		for i, index := range indexes {
			xi := big.NewInt(int64(index + 1))
			numerator, denominator := big.NewInt(1), big.NewInt(1)
			for j, other := range indexes {
				if i == j {
					continue
				}
				xj := big.NewInt(int64(other + 1))
				numerator.Mul(numerator, new(big.Int).Neg(xj)).Mod(numerator, q)
				denominator.Mul(denominator, new(big.Int).Sub(xi, xj)).Mod(denominator, q)
			}
			inverse := new(big.Int).ModInverse(denominator, q)
			if inverse == nil {
				t.Fatal("duplicate indexes")
			}
			term := new(big.Int).Mul(numerator, inverse)
			term.Mul(term, values[i])
			recovered.Add(recovered, term).Mod(recovered, q)
		}
		public, e := curve.ScalarMultiply(recovered, curve.G())
		if e != nil || !public.Equal(commitments[0]) {
			t.Fatal("recovery public key mismatch")
		}
		break
	}
	recoveryTime := time.Since(started)
	if recovered == nil || recovered.Cmp(coefficients[0]) != 0 {
		t.Fatal("secret not recovered")
	}
	if attempts != 2 || rejected != 1 {
		t.Fatalf("attempts=%d rejected=%d", attempts, rejected)
	}
	t.Logf("polynomial/LHTLP composition: RSA=2048 squarings=%d threshold=%d participants=%d setup=%s encryption=%s recovery=%s; rejected bad delayed share then recovered from non-prefix indexes", squarings, threshold, participants, setupTime, generationTime, recoveryTime)
}
