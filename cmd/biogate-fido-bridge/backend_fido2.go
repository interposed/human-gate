//go:build fido2

package main

import (
	"crypto/rand"
	"errors"

	libfido2 "github.com/keys-pub/go-libfido2"

	"github.com/interposed/nono-bio-gate/biogate/bridge"
)

type fidoBackend struct{}

func newBackend() backend { return fidoBackend{} }

func firstDevice() (*libfido2.Device, error) {
	locs, err := libfido2.DeviceLocations()
	if err != nil {
		return nil, err
	}
	if len(locs) == 0 {
		return nil, errors.New("no FIDO2 device connected - plug in your key")
	}
	return libfido2.NewDevice(locs[0].Path)
}

func (fidoBackend) list() ([]string, error) {
	locs, err := libfido2.DeviceLocations()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(locs))
	for _, l := range locs {
		out = append(out, l.Path)
	}
	return out, nil
}

func (fidoBackend) register(req bridge.Request) ([]byte, []byte, int, error) {
	d, err := firstDevice()
	if err != nil {
		return nil, nil, 0, err
	}
	defer d.Close()

	cdh := req.Challenge
	if len(cdh) != 32 {
		cdh = make([]byte, 32)
		_, _ = rand.Read(cdh)
	}
	uid := make([]byte, 16)
	_, _ = rand.Read(uid)
	rp := libfido2.RelyingParty{ID: req.RPID, Name: req.RPName}
	user := libfido2.User{ID: uid, Name: req.UserName, DisplayName: req.UserName}
	opts := &libfido2.MakeCredentialOpts{RK: libfido2.True}

	alg := req.Alg
	if alg == 0 {
		alg = bridge.AlgEdDSA
	}
	att, err := d.MakeCredential(cdh, rp, user, libfido2.CredentialType(alg), req.PIN, opts)
	if err != nil && alg == bridge.AlgEdDSA {
		// key may not support Ed25519 resident credentials; fall back to ES256
		alg = bridge.AlgES256
		att, err = d.MakeCredential(cdh, rp, user, libfido2.CredentialType(alg), req.PIN, opts)
	}
	if err != nil {
		return nil, nil, 0, err
	}
	return att.CredentialID, att.PubKey, alg, nil
}

func (fidoBackend) assert(req bridge.Request) ([]byte, []byte, error) {
	d, err := firstDevice()
	if err != nil {
		return nil, nil, err
	}
	defer d.Close()

	assn, err := d.Assertion(req.RPID, req.Challenge, [][]byte{req.CredentialID}, req.PIN,
		&libfido2.AssertionOpts{UP: libfido2.True})
	if err != nil {
		return nil, nil, err
	}
	authData, err := cborUnwrapBstr(assn.AuthDataCBOR)
	if err != nil {
		return nil, nil, err
	}
	return authData, assn.Sig, nil
}

// cborUnwrapBstr extracts the raw bytes from a CBOR byte-string (major type 2).
// libfido2 returns authenticator data CBOR-wrapped; the assertion signature is
// over the RAW authData, so we unwrap before returning it. If the input is not a
// byte-string it is returned unchanged.
func cborUnwrapBstr(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, errors.New("empty authData")
	}
	if b[0]>>5 != 2 { // not major type 2; assume already raw
		return b, nil
	}
	ai := b[0] & 0x1f
	i := 1
	var n int
	switch {
	case ai < 24:
		n = int(ai)
	case ai == 24:
		n = int(b[1])
		i = 2
	case ai == 25:
		n = int(b[1])<<8 | int(b[2])
		i = 3
	case ai == 26:
		n = int(b[1])<<24 | int(b[2])<<16 | int(b[3])<<8 | int(b[4])
		i = 5
	default:
		return nil, errors.New("unsupported CBOR length")
	}
	if i+n > len(b) {
		return nil, errors.New("truncated CBOR byte-string")
	}
	return b[i : i+n], nil
}
