package main

import (
	"github.com/primefactor-io/lhtlp/pkg/params"
	"github.com/primefactor-io/lhtlp/pkg/puzzle"
	"math/big"
	"testing"
)

func TestFastAuditMatchesPinnedSequentialSolverForSignedRepresentatives(t *testing.T) {
	p, err := params.GenerateParams(2048, 2, big.NewInt(directShortWork))
	if err != nil {
		t.Fatal(err)
	}
	for _, message := range []*big.Int{big.NewInt(1), big.NewInt(-1), new(big.Int).Sub(scalarOrder(), big.NewInt(1)), new(big.Int).Add(scalarOrder(), big.NewInt(1))} {
		cipher, err := puzzle.GeneratePuzzle(p, message)
		if err != nil {
			t.Fatal(err)
		}
		c := &verifiedDirectCapsule{p, cipher, directPoint(message)}
		before := encode(c.parameters) + encode(c.ciphertext)
		ordinary, _, err := c.open()
		if err != nil {
			t.Fatal(err)
		}
		fast, _, err := c.openFastAudit()
		if err != nil || fast != ordinary {
			t.Fatal("evaluators differ", err)
		}
		if before != encode(c.parameters)+encode(c.ciphertext) {
			t.Fatal("evaluator modified original capsule")
		}
		c.public = directPoint(big.NewInt(17))
		if _, _, err := c.openFastAudit(); err == nil {
			t.Fatal("wrong public key accepted")
		}
	}
}

func TestFastAuditRejectsPolicyChangesBeforeEvaluation(t *testing.T) {
	for _, p := range []*params.Params{nil, {Y: 3}, {Y: 2, T: big.NewInt(0)}, {Y: 2, T: big.NewInt(directShortWork)}} {
		if _, _, err := (&verifiedDirectCapsule{parameters: p}).openFastAudit(); err == nil {
			t.Fatal("bad shape accepted")
		}
	}
}
