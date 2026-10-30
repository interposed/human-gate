//go:build !fido2

package main

import (
	"errors"

	"github.com/interposed/human-gate/humangate/bridge"
)

var errNotBuilt = errors.New("humangate-fido-bridge built without libfido2; rebuild with -tags fido2 (brew install libfido2 / apt install libfido2-dev)")

type stubBackend struct{}

func newBackend() backend { return stubBackend{} }

func (stubBackend) list() ([]string, error) { return nil, errNotBuilt }

func (stubBackend) register(bridge.Request) ([]byte, []byte, int, error) {
	return nil, nil, 0, errNotBuilt
}

func (stubBackend) assert(bridge.Request) ([]byte, []byte, error) {
	return nil, nil, errNotBuilt
}
