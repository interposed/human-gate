package biogatetest

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"net"
	"path/filepath"
	"testing"

	"github.com/interposed/nono-biogate/biogate"
	"github.com/interposed/nono-biogate/biogate/bridge"
)

// mockApprover auto-approves (or returns err) under the "mock" method, so tests
// can drive RequireApproval without any real ceremony.
type mockApprover struct{ err error }

func (m mockApprover) Method() biogate.Method                        { return biogate.Method("mock") }
func (m mockApprover) Approve(context.Context, biogate.Request) error { return m.err }

// fakeBridge is an in-process stand-in for biogate-fido-bridge. It holds one
// Ed25519 keypair and answers register/assert over a Unix socket exactly like
// the real bridge, signing assertions in software so the fido2 path is testable
// without hardware.
type fakeBridge struct {
	sock   string
	priv   ed25519.PrivateKey
	pub    ed25519.PublicKey
	credID []byte
}

func startFakeBridge(t *testing.T) *fakeBridge {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "bridge.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("fake bridge listen: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	fb := &fakeBridge{sock: sock, priv: priv, pub: pub, credID: []byte("fake-credential-id")}
	go fb.serve(ln)
	t.Cleanup(func() { ln.Close() })
	return fb
}

func (fb *fakeBridge) serve(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			var req bridge.Request
			if bridge.ReadMsg(bufio.NewReader(conn), &req) != nil {
				return
			}
			var resp bridge.Response
			switch req.Op {
			case bridge.OpPing:
				resp = bridge.Response{OK: true}
			case bridge.OpRegister:
				resp = bridge.Response{OK: true, CredentialID: fb.credID, PubKey: fb.pub, Alg: bridge.AlgEdDSA}
			case bridge.OpAssert:
				authData := []byte("fake-authenticator-data-0123456789")
				sig := ed25519.Sign(fb.priv, append(append([]byte{}, authData...), req.Challenge...))
				resp = bridge.Response{OK: true, AuthData: authData, Sig: sig}
			default:
				resp = bridge.Response{OK: false, Error: "fake bridge: unknown op"}
			}
			_ = bridge.WriteMsg(conn, &resp)
		}()
	}
}
