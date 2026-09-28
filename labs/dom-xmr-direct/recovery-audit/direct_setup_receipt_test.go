package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/primefactor-io/lhtlp/pkg/params"
)

func TestLocalSetupAuthorityRequiresPrivateConfiguredFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "local-authority")
	key := bytes.Repeat([]byte{17}, 32)
	for _, invalid := range []string{"", "relative", path} {
		if _, err := readLocalSetupAuthority(invalid); err == nil {
			t.Fatal("missing/configuration accepted")
		}
	}
	if err := os.WriteFile(path, key, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := readLocalSetupAuthority(path)
	if err != nil || !bytes.Equal(loaded, key) {
		t.Fatal("local authority roundtrip", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readLocalSetupAuthority(path); err == nil {
		t.Fatal("public authority file accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{nil, key[:31], append(append([]byte{}, key...), 1), make([]byte, 32)} {
		if err := os.WriteFile(path, invalid, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readLocalSetupAuthority(path); err == nil {
			t.Fatal("malformed authority accepted")
		}
	}
	if err := os.WriteFile(path, key, 0600); err != nil {
		t.Fatal(err)
	}
	link := path + "-link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readLocalSetupAuthority(link); err == nil {
		t.Fatal("symlink authority accepted")
	}
}

func TestLocalSetupReceiptBindsEveryOperationFieldAndRejectsWireAuthority(t *testing.T) {
	key := bytes.Repeat([]byte{17}, 32)
	request := directLocalResume{
		directInitial: directInitial{Setup: "shape irrelevant until MAC acceptance", Context: [32]byte{1}, Public: directPoint(big.NewInt(3)), Squarings: directShortWork},
		OfferBinding:  setupBinding("approved offer"), OriginalReceipt: 1000,
	}
	mac, err := localSetupMAC(key, request.directInitial, request.OfferBinding, request.OriginalReceipt)
	if err != nil {
		t.Fatal(err)
	}
	request.Receipt = hex.EncodeToString(mac)
	for name, mutate := range map[string]func(*directLocalResume){
		"setup":           func(r *directLocalResume) { r.Setup += " " },
		"context":         func(r *directLocalResume) { r.Context[0] ^= 1 },
		"public":          func(r *directLocalResume) { r.Public = directPoint(big.NewInt(5)) },
		"work":            func(r *directLocalResume) { r.Squarings = directLongWork },
		"offer":           func(r *directLocalResume) { r.OfferBinding = setupBinding("other") },
		"receipt_time":    func(r *directLocalResume) { r.OriginalReceipt++ },
		"missing_receipt": func(r *directLocalResume) { r.Receipt = "" },
		"forged_receipt":  func(r *directLocalResume) { r.Receipt = strings.Repeat("00", 32) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := request
			mutate(&changed)
			if _, err := restoreLocalSetup(key, changed); err == nil || err.Error() != "local setup acceptance receipt rejected" {
				t.Fatal("receipt did not bind mutation", err)
			}
		})
	}
	for _, invalidKey := range [][]byte{nil, make([]byte, 32), bytes.Repeat([]byte{23}, 32)} {
		if _, err := restoreLocalSetup(invalidKey, request); err == nil {
			t.Fatal("wrong/missing authority accepted")
		}
	}
	var output bytes.Buffer
	// The first-acceptance endpoint has no skip-verification field or wire key.
	if err := serveDirectPrepared(strings.NewReader(encode(request)+"\n"), &output); err == nil || output.Len() != 0 {
		t.Fatal("receipt admitted by first-acceptance endpoint")
	}
	wire := encode(map[string]any{"setup": "x", "context": request.Context, "public": request.Public, "squarings": directShortWork, "authority_key": key}) + "\n"
	if err := serveDirectSession(strings.NewReader(wire), &output, key, false); err == nil || output.Len() != 0 {
		t.Fatal("wire authority accepted")
	}
}

func TestLocalSetupReceiptIssuedAfterVerificationAndColdRestoreStillChecksProof(t *testing.T) {
	p, err := params.GenerateParams(2048, 2, big.NewInt(directShortWork))
	if err != nil {
		t.Fatal(err)
	}
	setup, err := verifyDirectPublicSetup(encode(publicSetup{p, 160, scalarOrder()}), directShortWork)
	if err != nil {
		t.Fatal(err)
	}
	context := [32]byte{11}
	secret := [32]byte{7}
	statement, proof, err := proveDirect(setup, context, secret)
	if err != nil {
		t.Fatal(err)
	}
	payload := encode(directOffer{statement, proof})
	initial := directInitial{Setup: setup.raw, Context: context, Public: statement.Public, Squarings: directShortWork}
	key := bytes.Repeat([]byte{19}, 32)
	var output bytes.Buffer
	var badSetup publicSetup
	if err := json.Unmarshal([]byte(setup.raw), &badSetup); err != nil {
		t.Fatal(err)
	}
	badSetup.Parameters.H.SetInt64(1)
	badInitial := initial
	badInitial.Setup = encode(badSetup)
	if err := serveDirectSession(strings.NewReader(encode(badInitial)+"\n"), &output, key, false); err == nil || output.Len() != 0 {
		t.Fatal("local receipt issuer skipped first setup verification")
	}
	input := encode(initial) + "\n" + encode(map[string]any{"payload": payload, "original_receipt_unix_seconds": uint64(1000)}) + "\n"
	if err := serveDirectSession(strings.NewReader(input), &output, key, false); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(&output)
	var prepared, ready, closed map[string]any
	for _, frame := range []*map[string]any{&prepared, &ready, &closed} {
		if err := decoder.Decode(frame); err != nil {
			t.Fatal(err)
		}
	}
	if prepared["setup_verifications"] != float64(1) || ready["setup_relation_recomputed"] != true || closed["completed"] != float64(0) {
		t.Fatal("initial verification/opening changed")
	}
	request := directLocalResume{directInitial: initial, OfferBinding: setupBinding(payload), Receipt: ready["local_setup_receipt"].(string), OriginalReceipt: 1000}
	if _, err := restoreLocalSetup(key, request); err != nil {
		t.Fatal("verifier receipt not restorable", err)
	}
	output.Reset()
	input = encode(request) + "\n" + encode(map[string]any{"payload": payload}) + "\n" + encode(map[string]any{"action": "open", "offer_binding": request.OfferBinding}) + "\n"
	if err := serveDirectSession(strings.NewReader(input), &output, key, true); err != nil {
		t.Fatal(err)
	}
	decoder = json.NewDecoder(&output)
	var reopened, finished map[string]any
	for _, frame := range []*map[string]any{&prepared, &ready, &reopened, &finished} {
		if err := decoder.Decode(frame); err != nil {
			t.Fatal(err)
		}
	}
	if prepared["setup_verifications"] != float64(0) || ready["local_setup_receipt_verified"] != true || ready["setup_relation_recomputed"] != false ||
		reopened["result"] != "opened" || encode(reopened["scalar"]) != encode(secret) || finished["completed"] != float64(1) {
		t.Fatal("cold restore policy/opening changed")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatal("unexpected restore output", err)
	}

	bad, err := parseDirectOffer(payload)
	if err != nil {
		t.Fatal(err)
	}
	bad.Proof.Rounds[0].MessageResponse.Add(bad.Proof.Rounds[0].MessageResponse, big.NewInt(1))
	badPayload := encode(bad)
	output.Reset()
	input = encode(initial) + "\n" + encode(map[string]any{"payload": badPayload, "original_receipt_unix_seconds": 1000}) + "\n"
	if err := serveDirectSession(strings.NewReader(input), &output, key, false); err == nil {
		t.Fatal("receipt issued for invalid proof")
	}
	if strings.Contains(output.String(), `"local_setup_receipt":`) || strings.Contains(output.String(), `"result":"ready"`) {
		t.Fatal("invalid proof released acceptance")
	}

	// A changed offer cannot reuse the original receipt, even if its public
	// point/setup are unchanged. No opening/ready should be emitted.
	output.Reset()
	input = encode(request) + "\n" + encode(map[string]any{"payload": badPayload}) + "\n"
	if err := serveDirectSession(strings.NewReader(input), &output, key, true); err == nil || strings.Contains(output.String(), `"result":"ready"`) {
		t.Fatal("receipt replayed for different offer")
	}

	// Deliberately mint a receipt with the trusted TEST key for a broken proof.
	// This is not something a peer can do. It checks that the resume path still
	// verifies all proof equations rather than treating the MAC as proof validity.
	request.OfferBinding = setupBinding(badPayload)
	mac, err := localSetupMAC(key, initial, request.OfferBinding, 1000)
	if err != nil {
		t.Fatal(err)
	}
	request.Receipt = hex.EncodeToString(mac)
	output.Reset()
	input = encode(request) + "\n" + encode(map[string]any{"payload": badPayload}) + "\n"
	if err := serveDirectSession(strings.NewReader(input), &output, key, true); err == nil || strings.Contains(output.String(), `"result":"ready"`) {
		t.Fatal("resume skipped proof verification")
	}
}
