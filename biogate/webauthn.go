package biogate

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/interposed/nono-bio-gate/biogate/bridge"
)

// verifyWebAuthn checks a hardware-key ApprovalToken: the assertion's challenge
// must equal sha256 of the approval's canonical core, the embedded public key
// must match KeyID, and the assertion signature must verify.
func verifyWebAuthn(t *ApprovalToken) error {
	w := t.WebAuthn
	if w == nil {
		return ErrBadToken
	}
	core, err := t.challengeCore()
	if err != nil {
		return err
	}
	h := sha256.Sum256(core)
	if !bytes.Equal(h[:], w.ClientHash) {
		return ErrBadSignature // the tap did not sign this approval
	}
	keyPub, err := hex.DecodeString(t.KeyID)
	if err != nil || !bytes.Equal(keyPub, w.PubKey) {
		return ErrBadToken // KeyID must be the credential public key
	}
	return verifyAssertion(w.Alg, w.PubKey, w.AuthData, w.ClientHash, w.Sig)
}

// verifyAssertion checks a CTAP2 assertion signature. Per the FIDO2 spec the key
// signs authenticatorData || clientDataHash; here clientDataHash is our approval
// challenge, so a valid signature binds the tap to this exact approval.
//
// EdDSA (Ed25519) is the primary, fully pure-Go path. ES256 (ECDSA P-256) is
// supported best-effort and should be validated against real hardware.
func verifyAssertion(alg int, pub, authData, clientHash, sig []byte) error {
	msg := make([]byte, 0, len(authData)+len(clientHash))
	msg = append(msg, authData...)
	msg = append(msg, clientHash...)

	switch alg {
	case bridge.AlgEdDSA:
		if len(pub) != ed25519.PublicKeySize {
			return ErrBadToken
		}
		if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
			return ErrBadSignature
		}
		return nil

	case bridge.AlgES256:
		x, y := parseP256(pub)
		if x == nil {
			return ErrBadToken
		}
		h := sha256.Sum256(msg)
		if !ecdsa.VerifyASN1(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, h[:], sig) {
			return ErrBadSignature
		}
		return nil

	default:
		return errors.New("biogate: unsupported credential algorithm")
	}
}

// parseP256 accepts an uncompressed P-256 point as 65 bytes (0x04||X||Y) or the
// bare 64-byte X||Y.
func parseP256(b []byte) (x, y *big.Int) {
	if len(b) == 65 && b[0] == 0x04 {
		b = b[1:]
	}
	if len(b) != 64 {
		return nil, nil
	}
	return new(big.Int).SetBytes(b[:32]), new(big.Int).SetBytes(b[32:])
}
