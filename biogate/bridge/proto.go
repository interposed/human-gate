// Package bridge is the pure-Go wire protocol between the main biogate binary
// and the biogate-fido-bridge helper. The helper owns the cgo/libfido2
// dependency and USB CTAP2 access; the main binary stays pure-Go and talks to
// it over a Unix-domain socket. One JSON object per line, request then response.
package bridge

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
)

// Op is a bridge operation.
type Op string

const (
	OpPing     Op = "ping"
	OpList     Op = "list"     // list connected FIDO2 devices
	OpRegister Op = "register" // make a resident credential
	OpAssert   Op = "assert"   // sign a challenge (the tap)
)

// COSE algorithm identifiers.
const (
	AlgEdDSA = -8 // Ed25519 (preferred: pure-Go verification)
	AlgES256 = -7 // ECDSA P-256
)

// Request is sent from biogate to the bridge.
type Request struct {
	Op           Op     `json:"op"`
	RPID         string `json:"rp_id,omitempty"`
	RPName       string `json:"rp_name,omitempty"`
	UserName     string `json:"user_name,omitempty"`
	PIN          string `json:"pin,omitempty"`
	Alg          int    `json:"alg,omitempty"`            // register: preferred COSE alg
	Challenge    []byte `json:"challenge,omitempty"`      // 32-byte clientDataHash
	CredentialID []byte `json:"credential_id,omitempty"`  // assert: which credential
}

// Response is returned by the bridge.
type Response struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`

	Devices []string `json:"devices,omitempty"` // OpList

	// OpRegister
	CredentialID []byte `json:"credential_id,omitempty"`
	PubKey       []byte `json:"pub_key,omitempty"`
	Alg          int    `json:"alg,omitempty"`

	// OpAssert
	AuthData []byte `json:"auth_data,omitempty"` // raw authenticator data (CBOR unwrapped)
	Sig      []byte `json:"sig,omitempty"`
}

// WriteMsg writes one JSON message followed by a newline.
func WriteMsg(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}

// ReadMsg reads one newline-delimited JSON message.
func ReadMsg(r *bufio.Reader, v any) error {
	line, err := r.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return err
	}
	return json.Unmarshal(line, v)
}

// DefaultSocketPath is where the bridge listens by default.
func DefaultSocketPath() string {
	if x := os.Getenv("BIOGATE_BRIDGE_SOCK"); x != "" {
		return x
	}
	if x := os.Getenv("XDG_RUNTIME_DIR"); x != "" {
		return filepath.Join(x, "biogate-fido-bridge.sock")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "biogate", "bridge.sock")
}
