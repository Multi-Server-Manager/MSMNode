package proto

import (
	"bytes"
	"strings"
	"testing"
)

// Test_code_generate covers PROTOCOL.md §10 "code alphabet and length".
func Test_code_generate(t *testing.T) {
	seen := make(map[string]struct{})
	for i := 0; i < 200; i++ {
		code, err := GenerateCode(bytes.NewReader(bytes.Repeat([]byte{byte(i)}, 5)))
		if err != nil {
			t.Fatalf("GenerateCode: %v", err)
		}
		if len(code) != CodeLen {
			t.Fatalf("code %q has length %d, want %d", code, len(code), CodeLen)
		}
		for _, r := range code {
			if !strings.ContainsRune(Alphabet, r) {
				t.Fatalf("code %q has out-of-alphabet character %q", code, r)
			}
		}
		seen[code] = struct{}{}
	}
	if len(seen) != 200 {
		t.Fatalf("200 distinct inputs produced %d codes", len(seen))
	}

	// All zero bits encode to the first alphabet character, and all ones to the
	// last: this pins the bit order of the encoding.
	low, err := GenerateCode(bytes.NewReader(make([]byte, 5)))
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if low != "00000000" {
		t.Fatalf("all-zero code = %q, want 00000000", low)
	}
	high, err := GenerateCode(bytes.NewReader(bytes.Repeat([]byte{0xff}, 5)))
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if high != strings.Repeat("Z", CodeLen) {
		t.Fatalf("all-ones code = %q, want %s", high, strings.Repeat("Z", CodeLen))
	}
}

// Test_code_normalise covers PROTOCOL.md §10 "code normalisation and rejection".
func Test_code_normalise(t *testing.T) {
	accepted := map[string]string{
		"7K3M9QXA":    "7K3M9QXA",
		"7k3m9qxa":    "7K3M9QXA",
		"7K3M-9QXA":   "7K3M9QXA",
		" 7k3m 9qxa ": "7K3M9QXA",
		"7K3M9QXI":    "7K3M9QX1",
		"7K3M9QXL":    "7K3M9QX1",
		"7K3M9QXO":    "7K3M9QX0",
		"0000-0000":   "00000000",
		"zzzzzzzz":    "ZZZZZZZZ",
	}
	for input, want := range accepted {
		got, err := NormalizeCode(input)
		if err != nil {
			t.Fatalf("NormalizeCode(%q): %v", input, err)
		}
		if got != want {
			t.Fatalf("NormalizeCode(%q) = %q, want %q", input, got, want)
		}
	}

	rejected := []string{"", "7K3M9QX", "7K3M9QXAA", "7K3M9QXA!", "U7K3M9QX", "7K3M9QXA\tA"}
	for _, input := range rejected {
		if _, err := NormalizeCode(input); err == nil {
			t.Fatalf("NormalizeCode(%q) accepted invalid input", input)
		}
	}
}
