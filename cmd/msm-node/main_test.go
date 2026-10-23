package main

import "testing"

// Test_detach_mode checks the explicit flags. The terminal and systemd cases
// are environment-driven and covered by the live run, not here.
func Test_detach_mode(t *testing.T) {
	if detachMode(true, false, false) {
		t.Fatal("--foreground must never detach")
	}
	if detachMode(false, false, true) {
		t.Fatal("--debug must never detach")
	}
	if !detachMode(false, true, false) {
		t.Fatal("--detach must detach even without a terminal")
	}
	if detachMode(true, true, false) {
		t.Fatal("--foreground must win over --detach")
	}
}
