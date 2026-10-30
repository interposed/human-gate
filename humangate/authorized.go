package humangate

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"
)

// ParseAuthorizedKeys parses an authorized-keys file body: one hex ed25519
// public key per line, with blank lines and lines beginning with '#' ignored.
// It is the set of owner keys a verifier requires an approval to have come from
// (see ApprovalToken.SignerKey).
//
// The format matches interpose's policy-authority file
// (pkg/agentpolicy.ParseAuthorityKeys), so one file can drive both sides.
func ParseAuthorizedKeys(body []byte) ([]ed25519.PublicKey, error) {
	var out []ed25519.PublicKey
	for i, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		raw, err := hex.DecodeString(line)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("humangate: authorized-keys line %d: not a hex ed25519 public key", i+1)
		}
		out = append(out, ed25519.PublicKey(raw))
	}
	return out, nil
}
