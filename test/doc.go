// Package biogatetest holds black-box tests for nono-bio-gate: they import the
// public API of github.com/interposed/nono-biogate/biogate (and its bridge
// protocol) and exercise it as a consumer would. Hardware is simulated with an
// in-process fake bridge, so the whole suite runs with no device attached.
package biogatetest
