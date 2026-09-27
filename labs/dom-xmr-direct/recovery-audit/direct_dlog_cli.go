package main

// Local process experiment only: no wallet, node, address or funding command.
import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/primefactor-io/lhtlp/pkg/params"
)

const directWireLimit = 2 * 1024 * 1024

// A local verifier capability, NOT a remotely verifiable setup proof. Its key
// comes from trusted process configuration, never a peer's request/offer.
const localSetupAuthorityEnv = "DXP1_LOCAL_SETUP_AUTHORITY_FILE"

func readLocalSetupAuthority(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("local setup authority requires absolute configured path")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() != 32 {
		return nil, fmt.Errorf("invalid local setup authority file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("local setup authority unavailable")
	}
	defer file.Close()
	key, err := io.ReadAll(io.LimitReader(file, 33))
	if err != nil || !validLocalAuthority(key) {
		return nil, fmt.Errorf("invalid local setup authority key")
	}
	return key, nil
}

func validLocalAuthority(key []byte) bool {
	if len(key) != 32 {
		return false
	}
	var nonzero byte
	for _, b := range key {
		nonzero |= b
	}
	return nonzero != 0
}

type directInitial struct {
	Setup     string   `json:"setup"`
	Context   [32]byte `json:"context"`
	Public    [32]byte `json:"public"`
	Squarings int64    `json:"squarings"`
}

type directLocalResume struct {
	directInitial
	OfferBinding    string `json:"offer_binding"`
	Receipt         string `json:"local_setup_receipt"`
	OriginalReceipt uint64 `json:"original_receipt_unix_seconds"`
}

func localSetupMAC(key []byte, initial directInitial, binding string, received uint64) ([]byte, error) {
	bound, err := hex.DecodeString(binding)
	if !validLocalAuthority(key) || err != nil || len(bound) != 32 || hex.EncodeToString(bound) != binding ||
		!directWorkAllowed(initial.Squarings) || initial.Context == [32]byte{} || received == 0 {
		return nil, fmt.Errorf("invalid local setup receipt fields")
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte("DXP1/local-accepted-setup/receipt/v1\x00"))
	setupHash := sha256.Sum256([]byte(initial.Setup))
	h.Write(setupHash[:])
	h.Write(bound)
	h.Write(initial.Context[:])
	h.Write(initial.Public[:])
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], uint64(initial.Squarings))
	h.Write(number[:])
	binary.BigEndian.PutUint64(number[:], received)
	h.Write(number[:])
	return h.Sum(nil), nil
}

func restoreLocalSetup(key []byte, request directLocalResume) (*verifiedDirectSetup, error) {
	mac, err := hex.DecodeString(request.Receipt)
	expected, expectedErr := localSetupMAC(key, request.directInitial, request.OfferBinding, request.OriginalReceipt)
	if err != nil || expectedErr != nil || len(mac) != 32 || hex.EncodeToString(mac) != request.Receipt || !hmac.Equal(mac, expected) {
		return nil, fmt.Errorf("local setup acceptance receipt rejected")
	}
	// Receipt authenticates a PRIOR full check by this local verifier authority.
	// Shape/work policy is checked again; only the sequential H recomputation
	// is omitted. Never call this for first acceptance of an untrusted setup.
	parsed, err := parseDirectSetup(request.Setup)
	if err != nil {
		return nil, err
	}
	if parsed.Parameters.T.Int64() != request.Squarings {
		return nil, fmt.Errorf("restored setup differs from original work policy")
	}
	return &verifiedDirectSetup{request.Setup}, nil
}

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
	return serveDirectSession(input, output, nil, false)
}

func serveDirectSession(input io.Reader, output io.Writer, authority []byte, resuming bool) error {
	return serveDirectSessionWithEvaluator(input, output, authority, resuming, nil)
}

// The optional evaluator is configured by local audit mode, never wire input.
// Setup acceptance and the entire original proof are still checked first.
func serveDirectSessionWithEvaluator(input io.Reader, output io.Writer, authority []byte, resuming bool,
	evaluator func(*verifiedDirectCapsule) ([32]byte, float64, error)) error {
	if (authority != nil || resuming) && !validLocalAuthority(authority) {
		return fmt.Errorf("local verifier authority missing")
	}
	reader := bufio.NewReaderSize(input, directWireLimit+1)
	encoder := json.NewEncoder(output)
	var initial directInitial
	var resumed directLocalResume
	if resuming {
		if err := strictFrame(reader, 128*1024, &resumed); err != nil {
			return err
		}
		initial = resumed.directInitial
	} else {
		if err := strictFrame(reader, 128*1024, &initial); err != nil {
			return err
		}
	}
	if initial.Squarings == 0 && !resuming {
		initial.Squarings = directShortWork
	}
	if initial.Context == [32]byte{} {
		return fmt.Errorf("missing context")
	}
	if _, err := parseDirectPoint(initial.Public, false); err != nil {
		return err
	}
	started := time.Now()
	var setup *verifiedDirectSetup
	var err error
	setupVerifications := 1
	if resuming {
		setup, err = restoreLocalSetup(authority, resumed)
		setupVerifications = 0
	} else {
		setup, err = verifyDirectPublicSetup(initial.Setup, initial.Squarings)
	}
	if err != nil {
		return err
	}
	if err := encoder.Encode(map[string]any{
		"result": "setup_ready", "setup_binding": setupBinding(setup.raw),
		"setup_verification_seconds": time.Since(started).Seconds(), "setup_verifications": setupVerifications,
		"local_setup_receipt_verified": resuming,
		"squarings":                    initial.Squarings,
	}); err != nil {
		return err
	}
	var supplied struct {
		Payload string `json:"payload"`
	}
	var received uint64
	if authority != nil && !resuming {
		var accepted struct {
			Payload         string `json:"payload"`
			OriginalReceipt uint64 `json:"original_receipt_unix_seconds"`
		}
		if err := strictFrame(reader, directWireLimit, &accepted); err != nil {
			return err
		}
		if accepted.OriginalReceipt == 0 {
			return fmt.Errorf("missing original local receipt time")
		}
		supplied.Payload, received = accepted.Payload, accepted.OriginalReceipt
	} else {
		if err := strictFrame(reader, directWireLimit, &supplied); err != nil {
			return err
		}
	}
	if resuming && setupBinding(supplied.Payload) != resumed.OfferBinding {
		return fmt.Errorf("restored offer differs from local acceptance receipt")
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
	ready := map[string]any{
		"result": "ready", "offer_binding": binding, "public": initial.Public, "context": initial.Context,
		"proof_verification_seconds":  time.Since(started).Seconds(),
		"proof_verification_workers":  directVerificationWorkers,
		"setup_verified_before_offer": true, "public_verifier_no_share_secret": true,
		"squarings":                     initial.Squarings,
		"local_setup_receipt_verified":  resuming,
		"setup_relation_recomputed":     !resuming,
		"non_reference_audit_evaluator": evaluator != nil,
	}
	// Issue only AFTER proof/context/public validation, never merely parsing
	// a setup or accepting a peer's assertion that it has already been checked.
	if authority != nil && !resuming {
		mac, err := localSetupMAC(authority, initial, binding, received)
		if err != nil {
			return err
		}
		ready["local_setup_receipt"] = hex.EncodeToString(mac)
		ready["original_receipt_unix_seconds"] = received
	}
	if err := encoder.Encode(ready); err != nil {
		return err
	}
	if evaluator != nil {
		return serveDirectOpening(reader, encoder, binding, func() ([32]byte, float64, error) { return evaluator(capsule) })
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
	additionalLabModes["direct-prepare-local-receipt"] = func() error {
		key, err := readLocalSetupAuthority(os.Getenv(localSetupAuthorityEnv))
		if err != nil {
			return err
		}
		return serveDirectSession(os.Stdin, os.Stdout, key, false)
	}
	additionalLabModes["direct-restore-local-receipt"] = func() error {
		key, err := readLocalSetupAuthority(os.Getenv(localSetupAuthorityEnv))
		if err != nil {
			return err
		}
		return serveDirectSession(os.Stdin, os.Stdout, key, true)
	}
}
