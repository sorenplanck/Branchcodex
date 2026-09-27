package main

import (
	"github.com/primefactor-io/lhtlp/pkg/params"
	"github.com/primefactor-io/lhtlp/pkg/puzzle"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

func TestMontgomeryBridgeChecksWorkAndOriginalPoint(t *testing.T) {
	binary := os.Getenv(montgomeryAuditEnv)
	if binary == "" {
		t.Fatal("explicit compiled audit binary required")
	}
	p, err := params.GenerateParams(2048, 2, big.NewInt(directShortWork))
	if err != nil {
		t.Fatal(err)
	}
	message := big.NewInt(41)
	ciphertext, err := puzzle.GeneratePuzzle(p, message)
	if err != nil {
		t.Fatal(err)
	}
	capsule := &verifiedDirectCapsule{p, ciphertext, directPoint(message)}
	original, _, err := capsule.open()
	if err != nil {
		t.Fatal(err)
	}
	actual, _, err := capsule.openMontgomeryAudit(binary)
	if err != nil || actual != original {
		t.Fatal("native evaluator differs", err)
	}
	before := encode(p) + encode(ciphertext)
	fake := filepath.Join(t.TempDir(), "fake-audit")
	for _, result := range []string{`{"work":1,"delayed_element_hex":"01"}`, `{"work":200000,"delayed_element_hex":"01"}`, `{"work":200000,"delayed_element_hex":"ZZ"}`} {
		if err := os.WriteFile(fake, []byte("#!/bin/sh\necho '"+result+"'\n"), 0700); err != nil {
			t.Fatal(err)
		}
		if _, _, err := capsule.openMontgomeryAudit(fake); err == nil {
			t.Fatal("forged native output accepted")
		}
	}
	if before != encode(p)+encode(ciphertext) {
		t.Fatal("native evaluator modified capsule")
	}
}
