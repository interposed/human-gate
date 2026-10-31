// Package humangatetest holds black-box tests for human-gate: they import the
// public API of github.com/interposed/human-gate/humangate (and its bridge
// protocol) and exercise it as a consumer would. Hardware is simulated with an
// in-process fake bridge, so the whole suite runs with no device attached.
package humangatetest
