package main

// Explicit owned-regtest adversary mode. The honest verifier still verifies
// setup and proof before funding. Only the independent opening is accelerated.
import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const montgomeryAuditEnv = "DXP1_MONTGOMERY_AUDIT_BINARY"

func (capsule *verifiedDirectCapsule) openMontgomeryAudit(binary string) ([32]byte, float64, error) {
	started := time.Now()
	info, err := os.Stat(binary)
	if !filepath.IsAbs(binary) || err != nil || !info.Mode().IsRegular() {
		return [32]byte{}, 0, fmt.Errorf("missing local Montgomery audit executable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, capsule.parameters.T.String())
	// Exactly three PUBLIC inputs. No local share, authority, factors or V.
	cmd.Stdin = strings.NewReader(capsule.parameters.N.Text(16) + "\n" + capsule.ciphertext.U.Text(16) + "\n")
	raw, err := cmd.Output()
	if err != nil || len(raw) > 2048 {
		return [32]byte{}, time.Since(started).Seconds(), fmt.Errorf("Montgomery audit process failed")
	}
	var result struct {
		Work    int64   `json:"work"`
		Seconds float64 `json:"sequential_seconds"`
		Element string  `json:"delayed_element_hex"`
	}
	if err := json.Unmarshal(raw, &result); err != nil || result.Work != capsule.parameters.T.Int64() || len(result.Element) > 512 {
		return [32]byte{}, time.Since(started).Seconds(), fmt.Errorf("invalid Montgomery audit result")
	}
	element, ok := new(big.Int).SetString(result.Element, 16)
	if !ok {
		return [32]byte{}, time.Since(started).Seconds(), fmt.Errorf("invalid delayed element encoding")
	}
	scalar, err := capsule.decodeDelayedElement(element)
	elapsed := time.Since(started).Seconds()
	if err == nil {
		evidence, _ := json.Marshal(map[string]any{"pid": cmd.Process.Pid, "work": result.Work, "sequential_seconds": result.Seconds, "opening_seconds": elapsed, "original_point_checked": true})
		fmt.Fprintln(os.Stderr, "montgomery_audit:", string(evidence))
	}
	return scalar, elapsed, err
}

func init() {
	additionalLabModes["direct-prepare-montgomery-audit"] = func() error {
		binary := os.Getenv(montgomeryAuditEnv)
		return serveDirectSessionWithEvaluator(os.Stdin, os.Stdout, nil, false,
			func(c *verifiedDirectCapsule) ([32]byte, float64, error) { return c.openMontgomeryAudit(binary) })
	}
}
