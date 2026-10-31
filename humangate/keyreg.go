package humangate

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// EnrolledKey is one registered hardware credential. The public key is stored so
// approval assertions can be verified offline, without the device present.
type EnrolledKey struct {
	Label        string    `json:"label"`
	RPID         string    `json:"rp_id"`
	CredentialID []byte    `json:"credential_id"`
	PubKey       []byte    `json:"pub_key"`
	Alg          int       `json:"alg"` // COSE alg (-8 EdDSA, -7 ES256)
	AddedAt      time.Time `json:"added_at"`
}

// KeyRegistry is the local set of enrolled hardware keys (backups included).
type KeyRegistry struct {
	Keys []EnrolledKey `json:"keys"`
}

// ErrNoKeys means no hardware key is enrolled yet (run `humangate register`).
var ErrNoKeys = errors.New("humangate: no hardware key enrolled (run: humangate register)")

// LoadRegistry reads the registry, returning an empty one if the file is absent.
func LoadRegistry(path string) (*KeyRegistry, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &KeyRegistry{}, nil
	}
	if err != nil {
		return nil, err
	}
	var r KeyRegistry
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Save writes the registry (0600), creating the parent directory.
func (r *KeyRegistry) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// Add appends a key.
func (r *KeyRegistry) Add(k EnrolledKey) { r.Keys = append(r.Keys, k) }

// CredentialIDs returns every enrolled credential id (for the assertion allow-list).
func (r *KeyRegistry) CredentialIDs() [][]byte {
	out := make([][]byte, 0, len(r.Keys))
	for _, k := range r.Keys {
		out = append(out, k.CredentialID)
	}
	return out
}

// FindByCredentialID returns the enrolled key matching id, or nil.
func (r *KeyRegistry) FindByCredentialID(id []byte) *EnrolledKey {
	for i := range r.Keys {
		if string(r.Keys[i].CredentialID) == string(id) {
			return &r.Keys[i]
		}
	}
	return nil
}

// DefaultRegistryPath is where enrolled keys live.
func DefaultRegistryPath() string {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "humangate", "keys.json")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "humangate", "keys.json")
}
