package main

// Competing evaluator for auditing the assumed adversarial minimum, NOT a
// timing admission or funding path. Ordinary math/big with reused temporaries.
// Exactly T sequential squarings; no factors, producer secret or shortcut.
import (
	"fmt"
	"math/big"
	"os"
	"time"
)

func (capsule *verifiedDirectCapsule) openFastAudit() ([32]byte, float64, error) {
	started := time.Now()
	p := capsule.parameters
	if p == nil || p.Y != 2 || p.T == nil || !p.T.IsInt64() || !directWorkAllowed(p.T.Int64()) ||
		p.N == nil || p.NExpY == nil || p.NExpYMinusOne == nil ||
		p.NExpYMinusOne.Cmp(p.N) != 0 || p.NExpY.Cmp(new(big.Int).Mul(p.N, p.N)) != 0 ||
		capsule.ciphertext == nil || !unit(capsule.ciphertext.U, p.N) || !unit(capsule.ciphertext.V, p.NExpY) {
		return [32]byte{}, time.Since(started).Seconds(), fmt.Errorf("invalid fast audit parameters")
	}
	w := new(big.Int).Set(capsule.ciphertext.U)
	for i := int64(0); i < p.T.Int64(); i++ {
		w.Mul(w, w).Mod(w, p.N)
	}
	// The verified policy requires Y=2. This is the j=1 specialization of
	// pinned upstream SolvePuzzle's final Paillier extraction, without changing
	// its residue convention. Reject a nonintegral quotient instead of rounding.
	w.Exp(w, p.NExpYMinusOne, p.NExpY)
	if w.ModInverse(w, p.NExpY) == nil {
		return [32]byte{}, time.Since(started).Seconds(), fmt.Errorf("noninvertible delayed element")
	}
	w.Mul(w, capsule.ciphertext.V).Mod(w, p.NExpY).Sub(w, big.NewInt(1))
	value, remainder := new(big.Int), new(big.Int)
	value.QuoRem(w, p.N, remainder)
	if remainder.Sign() != 0 {
		return [32]byte{}, time.Since(started).Seconds(), fmt.Errorf("nonintegral plaintext residue")
	}
	scalar, err := capsule.decodePlaintext(value)
	return scalar, time.Since(started).Seconds(), err
}

func init() {
	additionalLabModes["direct-restore-fast-audit"] = func() error {
		key, err := readLocalSetupAuthority(os.Getenv(localSetupAuthorityEnv))
		if err != nil {
			return err
		}
		return serveDirectSessionWithEvaluator(os.Stdin, os.Stdout, key, true,
			func(c *verifiedDirectCapsule) ([32]byte, float64, error) { return c.openFastAudit() })
	}
}
