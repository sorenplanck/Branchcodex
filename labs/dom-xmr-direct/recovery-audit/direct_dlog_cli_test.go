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
)

func TestDirectWorkPolicyRejectsDowngradeAndLeavesLegacyFixed(t *testing.T) {
	p, err := params.GenerateParams(2048, 2, big.NewInt(directShortWork))
	if err != nil {
		t.Fatal(err)
	}
	raw := encode(publicSetup{p, 160, scalarOrder()})
	if _, err := verifyDirectPublicSetup(raw, directShortWork); err != nil {
		t.Fatal(err)
	}
	// Both values are allowed individually, but the peer cannot change the
	// receiver's choice. Reject before acknowledging setup or doing long work.
	if _, err := verifyDirectPublicSetup(raw, directLongWork); err == nil {
		t.Fatal("accepted downgrade")
	}
	var output bytes.Buffer
	initial := encode(map[string]any{"setup": raw, "context": [32]byte{1}, "public": directPoint(big.NewInt(1)), "squarings": directLongWork})
	if err := serveDirectPrepared(strings.NewReader(initial+"\n"), &output); err == nil || output.Len() != 0 {
		t.Fatal("public process acknowledged downgraded work")
	}
	for _, work := range []*big.Int{big.NewInt(-1), big.NewInt(0), big.NewInt(200001), big.NewInt(10000001), new(big.Int).Lsh(big.NewInt(1), 80)} {
		p.T = work
		if _, err := parseDirectSetup(encode(publicSetup{p, 160, scalarOrder()})); err == nil {
			t.Fatal("accepted unbounded work")
		}
	}
	p.T = big.NewInt(directLongWork)
	longRaw := encode(publicSetup{p, 160, scalarOrder()})
	if _, err := parseDirectSetup(longRaw); err != nil {
		t.Fatal("long profile shape rejected", err)
	}
	if _, err := parseSetup(longRaw, scalarOrder()); err == nil {
		t.Fatal("legacy policy expanded")
	}
	// Merely relabelling T must not turn the old h into a verified long
	// setup. This exercises the full sequential check of the long profile.
	if _, err := verifyDirectPublicSetup(longRaw, directLongWork); err == nil {
		t.Fatal("accepted relabelled difficulty without matching delayed element")
	}
	if _, err := verifyDirectPublicSetup(longRaw, directShortWork); err == nil {
		t.Fatal("accepted unsolicited long work")
	}
	for _, work := range []int64{-1, 200001, 10000001} {
		output.Reset()
		request := encode(map[string]any{"secret": [32]byte{1}, "context": [32]byte{1}, "squarings": work})
		if err := produceDirect(strings.NewReader(request+"\n"), &output); err == nil || output.Len() != 0 {
			t.Fatal("producer accepted unsupported work")
		}
	}
}

func TestDirectPayloadFramingRejectsMissingExtraAndOversizedInput(t *testing.T) {
	validShape := encode(directOffer{Proof: &directProof{Rounds: make([]directRound, directRounds)}})
	if _, err := parseDirectOffer(validShape); err != nil {
		t.Fatal("structural fixture failed to parse", err)
	}
	for _, raw := range []string{
		"", "null", "{}", "{\"unknown\":1}", validShape + " {}", validShape + "\n",
		strings.Repeat(" ", directWireLimit),
		encode(directOffer{Proof: &directProof{Rounds: make([]directRound, directRounds-1)}}),
	} {
		if _, err := parseDirectOffer(raw); err == nil {
			t.Fatal("accepted malformed payload")
		}
	}
}

func TestDirectProducerWaitsForExactSetupAcknowledgement(t *testing.T) {
	input, writer := io.Pipe()
	reader, output := io.Pipe()
	defer input.Close()
	defer writer.Close()
	defer reader.Close()
	defer output.Close()
	done := make(chan error, 1)
	go func() { done <- produceDirect(input, output); output.Close() }()
	secret := [32]byte{1}
	request := encode(map[string]any{"secret": secret, "context": [32]byte{1}}) + "\n"
	if _, err := io.WriteString(writer, request); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bufio.NewReader(reader))
	got := make(chan map[string]any, 1)
	go func() {
		var frame map[string]any
		if decoder.Decode(&frame) != nil {
			got <- nil
			return
		}
		got <- frame
	}()
	select {
	case frame := <-got:
		if frame["result"] != "setup" || frame["setup"] == nil {
			t.Fatal("did not receive setup first")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("setup frame timeout")
	}
	if _, err := io.WriteString(writer, "{\"accepted_setup\":\"wrong\"}\n"); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil {
		t.Fatal("producer ignored wrong acknowledgement")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatal("producer released a puzzle after wrong acknowledgement")
	}
}

func TestDirectPublicProcessRejectsSecretAndPrematureOffer(t *testing.T) {
	public := directPoint(big.NewInt(1))
	for _, frame := range []string{
		encode(map[string]any{"payload": "premature offer"}),
		encode(map[string]any{"context": [32]byte{}, "public": public, "setup": "missing"}),
		encode(map[string]any{"context": [32]byte{1}, "public": public, "setup": "missing", "secret": [32]byte{1}}),
	} {
		var output bytes.Buffer
		if err := serveDirectPrepared(strings.NewReader(frame+"\n"), &output); err == nil || output.Len() != 0 {
			t.Fatal("public process acknowledged invalid first frame")
		}
	}
}

func TestDirectOpeningRequestsCancelRejectReplayAndCountExactlyOne(t *testing.T) {
	const binding = "fixture-exact-offer-binding"
	valid := "{\"action\":\"open\",\"offer_binding\":\"" + binding + "\"}\n"
	for _, test := range []struct {
		name, input string
		calls       int
		fails       bool
	}{
		{"cancel", "", 0, false},
		{"one", valid, 1, false},
		{"wrong_binding", "{\"action\":\"open\",\"offer_binding\":\"other\"}\n", 0, true},
		{"wrong_action", "{\"action\":\"replace\",\"offer_binding\":\"" + binding + "\"}\n", 0, true},
		{"blank", "\n", 0, true},
		{"unterminated", strings.TrimSuffix(valid, "\n"), 0, true},
		{"repeated", valid + valid, 1, true},
		{"blank_after_open", valid + "\n", 1, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			var output bytes.Buffer
			err := serveDirectOpening(bufio.NewReader(strings.NewReader(test.input)), json.NewEncoder(&output), binding,
				func() ([32]byte, float64, error) { calls++; return [32]byte{1}, 0.25, nil })
			if (err != nil) != test.fails || calls != test.calls {
				t.Fatal("unexpected opening count or result", calls, err)
			}
			if !test.fails {
				decoder := json.NewDecoder(&output)
				var frame map[string]any
				if calls == 1 {
					if err := decoder.Decode(&frame); err != nil || frame["result"] != "opened" || frame["offer_binding"] != binding {
						t.Fatal("missing bound opening", err)
					}
				}
				if err := decoder.Decode(&frame); err != nil || frame["result"] != "closed" || frame["completed"] != float64(calls) || frame["offer_binding"] != binding {
					t.Fatal("incorrect close frame", err)
				}
				if err := decoder.Decode(&frame); err != io.EOF {
					t.Fatal("unexpected output", err)
				}
			}
		})
	}
}
