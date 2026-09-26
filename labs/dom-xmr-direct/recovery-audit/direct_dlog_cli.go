package main

// Local process experiment only: no wallet, node, address or funding command.
import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/primefactor-io/lhtlp/pkg/params"
)

const directWireLimit = 2 * 1024 * 1024

type directOffer struct {
	Statement directStatement
	Proof     *directProof
}

func parseDirectOffer(payload string) (*directOffer, error) {
	if len(payload) == 0 || len(payload)+1 > directWireLimit || strings.ContainsAny(payload, "\r\n") {
		return nil, fmt.Errorf("invalid direct payload frame")
	}
	var offer directOffer
	reader := bufio.NewReaderSize(strings.NewReader(payload+"\n"), directWireLimit+1)
	if err := strictFrame(reader, directWireLimit, &offer); err != nil {
		return nil, err
	}
	if offer.Proof == nil || len(offer.Proof.Rounds) != directRounds {
		return nil, fmt.Errorf("missing or wrong direct proof")
	}
	return &offer, nil
}

func produceDirect(input io.Reader, output io.Writer) error {
	reader := bufio.NewReaderSize(input, 4097)
	encoder := json.NewEncoder(output)
	var request struct {
		Secret    [32]byte `json:"secret"`
		Context   [32]byte `json:"context"`
		Squarings int64    `json:"squarings"`
	}
	if err := strictFrame(reader, 4096, &request); err != nil {
		return err
	}
	if request.Squarings == 0 {
		request.Squarings = directShortWork
	}
	if !directWorkAllowed(request.Squarings) {
		return fmt.Errorf("unsupported direct work")
	}
	secret, err := scalarFromLittleEndian(request.Secret, scalarOrder())
	if err != nil || secret.Sign() == 0 || request.Context == [32]byte{} {
		return fmt.Errorf("invalid direct secret or context")
	}
	public := directPoint(secret)
	p, err := params.GenerateParams(2048, 2, big.NewInt(request.Squarings))
	if err != nil {
		return err
	}
	raw := encode(publicSetup{p, 160, scalarOrder()})
	if _, err := parseDirectSetup(raw); err != nil {
		return err
	}
	if err := encoder.Encode(map[string]any{"result": "setup", "setup": raw, "public": public, "context": request.Context, "squarings": request.Squarings}); err != nil {
		return err
	}
	var acknowledgement struct {
		Binding string `json:"accepted_setup"`
	}
	if err := strictFrame(reader, 1024, &acknowledgement); err != nil {
		return err
	}
	if acknowledgement.Binding != setupBinding(raw) {
		return fmt.Errorf("wrong setup acknowledgement")
	}
	// The local coordinator obtains this acknowledgement from the separate
	// public verifier after the sequential setup check. Parameters were locally
	// generated; this acknowledgement is not remote authentication.
	started := time.Now()
	statement, proof, err := proveDirect(&verifiedDirectSetup{raw}, request.Context, request.Secret)
	if err != nil {
		return err
	}
	payload := encode(directOffer{statement, proof})
	if len(payload)+1 > directWireLimit {
		return fmt.Errorf("direct offer exceeds bound")
	}
	return encoder.Encode(map[string]any{
		"result": "offer", "payload": payload, "offer_binding": setupBinding(payload),
		"proof_generation_seconds": time.Since(started).Seconds(),
	})
}

func serveDirectPrepared(input io.Reader, output io.Writer) error {
	reader := bufio.NewReaderSize(input, directWireLimit+1)
	encoder := json.NewEncoder(output)
	var initial struct {
		Setup     string   `json:"setup"`
		Context   [32]byte `json:"context"`
		Public    [32]byte `json:"public"`
		Squarings int64    `json:"squarings"`
	}
	if err := strictFrame(reader, 128*1024, &initial); err != nil {
		return err
	}
	if initial.Squarings == 0 {
		initial.Squarings = directShortWork
	}
	if initial.Context == [32]byte{} {
		return fmt.Errorf("missing context")
	}
	if _, err := parseDirectPoint(initial.Public, false); err != nil {
		return err
	}
	started := time.Now()
	setup, err := verifyDirectPublicSetup(initial.Setup, initial.Squarings)
	if err != nil {
		return err
	}
	if err := encoder.Encode(map[string]any{
		"result": "setup_ready", "setup_binding": setupBinding(setup.raw),
		"setup_verification_seconds": time.Since(started).Seconds(), "setup_verifications": 1,
		"squarings": initial.Squarings,
	}); err != nil {
		return err
	}
	var supplied struct {
		Payload string `json:"payload"`
	}
	if err := strictFrame(reader, directWireLimit, &supplied); err != nil {
		return err
	}
	started = time.Now()
	offer, err := parseDirectOffer(supplied.Payload)
	if err != nil {
		return err
	}
	capsule, err := verifyDirect(setup, initial.Context, initial.Public, offer.Statement, offer.Proof)
	if err != nil {
		return err
	}
	binding := setupBinding(supplied.Payload)
	if err := encoder.Encode(map[string]any{
		"result": "ready", "offer_binding": binding, "public": initial.Public, "context": initial.Context,
		"proof_verification_seconds":  time.Since(started).Seconds(),
		"setup_verified_before_offer": true, "public_verifier_no_share_secret": true,
		"squarings": initial.Squarings,
	}); err != nil {
		return err
	}
	return serveDirectOpening(reader, encoder, binding, capsule.open)
}

// Called only after the immutable capsule has been verified. Separating the
// request machine permits cancellation/replay tests without repeating a proof.
func serveDirectOpening(reader *bufio.Reader, encoder *json.Encoder, binding string, open func() ([32]byte, float64, error)) error {
	var action struct {
		Action  string `json:"action"`
		Binding string `json:"offer_binding"`
	}
	if err := strictFrame(reader, 1024, &action); err != nil {
		if err == io.EOF {
			return encoder.Encode(map[string]any{"result": "closed", "completed": 0, "offer_binding": binding})
		}
		return err
	}
	if action.Action != "open" || action.Binding != binding {
		return fmt.Errorf("wrong capsule opening request")
	}
	scalar, seconds, err := open()
	if err != nil {
		return err
	}
	if err := encoder.Encode(map[string]any{"result": "opened", "scalar": scalar, "solve_seconds": seconds, "offer_binding": binding}); err != nil {
		return err
	}
	var extra any
	if err := strictFrame(reader, 1024, &extra); err != io.EOF {
		return fmt.Errorf("extra or incomplete request after opening")
	}
	return encoder.Encode(map[string]any{"result": "closed", "completed": 1, "offer_binding": binding})
}

func init() {
	additionalLabModes["direct-produce"] = func() error { return produceDirect(os.Stdin, os.Stdout) }
	additionalLabModes["direct-prepare"] = func() error { return serveDirectPrepared(os.Stdin, os.Stdout) }
}
