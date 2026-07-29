// Command biogate-fido-bridge owns the cgo/libfido2 dependency and USB CTAP2
// access so the main biogate binary stays pure-Go. It listens on a Unix socket
// and answers register/assert requests. Talking raw CTAP2 to an external FIDO2
// key needs no Apple entitlement (no Secure Enclave, no Endpoint Security).
//
// Build WITH hardware support (needs libfido2):
//
//	brew install libfido2            # or: apt install libfido2-dev
//	make bridge                      # go build -tags fido2 ...
//
// Without the fido2 tag it still builds, but every op returns "not built".
package main

import (
	"bufio"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/interposed/nono-bio-gate/biogate/bridge"
)

// backend performs the actual FIDO2 operations. Implemented by the fido2-tagged
// build (libfido2) and by a stub otherwise.
type backend interface {
	list() ([]string, error)
	register(req bridge.Request) (credID, pubKey []byte, alg int, err error)
	assert(req bridge.Request) (authData, sig []byte, err error)
}

var errUnknownOp = errors.New("biogate-fido-bridge: unknown op")

func main() {
	sock := bridge.DefaultSocketPath()
	quiet := false
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--socket":
			if i+1 < len(args) {
				i++
				sock = args[i]
			}
		case "--quiet":
			quiet = true
		case "-h", "--help":
			os.Stdout.WriteString("usage: biogate-fido-bridge [--socket <path>] [--quiet]\n")
			return
		}
	}

	be := newBackend()
	if dir := filepath.Dir(sock); dir != "" {
		_ = os.MkdirAll(dir, 0o700)
	}
	_ = os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		log.Fatalf("biogate-fido-bridge: listen %s: %v", sock, err)
	}
	defer os.Remove(sock)
	if !quiet {
		log.Printf("biogate-fido-bridge listening on %s", sock)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sig; _ = os.Remove(sock); os.Exit(0) }()

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handle(conn, be)
	}
}

func handle(conn net.Conn, be backend) {
	defer conn.Close()
	var req bridge.Request
	if err := bridge.ReadMsg(bufio.NewReader(conn), &req); err != nil {
		return
	}
	_ = bridge.WriteMsg(conn, dispatch(be, req))
}

func dispatch(be backend, req bridge.Request) *bridge.Response {
	switch req.Op {
	case bridge.OpPing:
		return &bridge.Response{OK: true}
	case bridge.OpList:
		devs, err := be.list()
		if err != nil {
			return fail(err)
		}
		return &bridge.Response{OK: true, Devices: devs}
	case bridge.OpRegister:
		cred, pub, alg, err := be.register(req)
		if err != nil {
			return fail(err)
		}
		return &bridge.Response{OK: true, CredentialID: cred, PubKey: pub, Alg: alg}
	case bridge.OpAssert:
		ad, sig, err := be.assert(req)
		if err != nil {
			return fail(err)
		}
		return &bridge.Response{OK: true, AuthData: ad, Sig: sig}
	default:
		return fail(errUnknownOp)
	}
}

func fail(err error) *bridge.Response { return &bridge.Response{OK: false, Error: err.Error()} }
