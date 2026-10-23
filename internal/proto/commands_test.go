package proto

import (
	"encoding/json"
	"strings"
	"testing"
)

// Test_command_roundtrip pins the exact bytes of every command message. The
// Rust implementation must produce the same field order (PROTOCOL.md §8.3).
func Test_command_roundtrip(t *testing.T) {
	cases := []struct {
		message Message
		want    string
	}{
		{&PkgUpdate{T: TypePkgUpdate, V: Version, ID: "a1"}, `{"t":"pkg.update","v":1,"id":"a1"}`},
		{&PkgInstall{T: TypePkgInstall, V: Version, ID: "a1", Name: "ripgrep"}, `{"t":"pkg.install","v":1,"id":"a1","name":"ripgrep"}`},
		{&SvcRestart{T: TypeSvcRestart, V: Version, ID: "a1", Unit: "sshd.service"}, `{"t":"svc.restart","v":1,"id":"a1","unit":"sshd.service"}`},
		{&HostReboot{T: TypeHostReboot, V: Version, ID: "a1", Confirm: "reboot"}, `{"t":"host.reboot","v":1,"id":"a1","confirm":"reboot"}`},
		{&MetricsSample{T: TypeMetricsSample, V: Version, ID: "a1"}, `{"t":"metrics.sample","v":1,"id":"a1"}`},
		{&LogsTail{T: TypeLogsTail, V: Version, ID: "a1", Lines: 20}, `{"t":"logs.tail","v":1,"id":"a1","lines":20}`},
		{&SSHAuthorize{T: TypeSSHAuthorize, V: Version, ID: "a1", Key: "ssh-ed25519 AAAA msm-console"}, `{"t":"ssh.authorize","v":1,"id":"a1","key":"ssh-ed25519 AAAA msm-console"}`},
		{&Result{T: TypeResult, V: Version, ID: "a1", OK: true}, `{"t":"result","v":1,"id":"a1","ok":true}`},
		{NewFailure("a1", CodeBadArgument, "nope"), `{"t":"result","v":1,"id":"a1","ok":false,"code":"bad_argument","detail":"nope"}`},
	}

	for _, testCase := range cases {
		encoded, err := json.Marshal(testCase.message)
		if err != nil {
			t.Fatalf("marshal %s: %v", testCase.message.Type(), err)
		}
		if string(encoded) != testCase.want {
			t.Fatalf("%s encoded as %s, want %s", testCase.message.Type(), encoded, testCase.want)
		}

		decoded, err := Decode(encoded)
		if err != nil {
			t.Fatalf("decode %s: %v", testCase.message.Type(), err)
		}
		if decoded.Type() != testCase.message.Type() {
			t.Fatalf("decoded type = %s, want %s", decoded.Type(), testCase.message.Type())
		}
	}
}

// Test_command_roundtrip_fields proves the payload fields survive a roundtrip.
func Test_command_roundtrip_fields(t *testing.T) {
	message, err := Decode([]byte(`{"t":"pkg.install","v":1,"id":"req-1","name":"aero"}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	install, ok := message.(*PkgInstall)
	if !ok {
		t.Fatalf("decoded %T, want *PkgInstall", message)
	}
	if install.ID != "req-1" || install.Name != "aero" {
		t.Fatalf("decoded %+v", install)
	}
}

// Test_command_result_envelope proves which members the envelope carries.
func Test_command_result_envelope(t *testing.T) {
	result := NewResult("req-1", &LogsResult{Lines: []string{"a", "b"}, Dropped: 3})
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"t":"result","v":1,"id":"req-1","ok":true,"data":{"lines":["a","b"],"dropped":3}}`
	if string(encoded) != want {
		t.Fatalf("encoded as %s, want %s", encoded, want)
	}
}

// Test_package_name_charset proves the charset rejects shell metacharacters
// and a leading dash (PROTOCOL.md §8.3).
func Test_package_name_charset(t *testing.T) {
	accepted := []string{"aero", "ripgrep-14", "libstdc++", "python3.11:amd64", "node_18", "a"}
	refused := []string{"", "-y", "--force", ".", "a b", "a;rm -rf /", "$(id)", "a|b", "a&b", "a/b", "../etc", "a\nb", "`id`", strings.Repeat("a", MaxPackageNameLen+1)}

	for _, name := range accepted {
		if !ValidPackageName(name) {
			t.Fatalf("ValidPackageName(%q) = false, want true", name)
		}
	}
	for _, name := range refused {
		if ValidPackageName(name) {
			t.Fatalf("ValidPackageName(%q) = true, want false", name)
		}
	}
}

// Test_unit_charset proves unit names cannot smuggle flags or paths.
func Test_unit_charset(t *testing.T) {
	accepted := []string{"sshd", "sshd.service", "getty@tty1.service", "msm-node"}
	refused := []string{"", "a b", "--now", "-1", "a/b", "a;b", "a$b", strings.Repeat("a", MaxUnitLen+1)}

	for _, unit := range accepted {
		if !ValidUnit(unit) {
			t.Fatalf("ValidUnit(%q) = false, want true", unit)
		}
	}
	for _, unit := range refused {
		if ValidUnit(unit) {
			t.Fatalf("ValidUnit(%q) = true, want false", unit)
		}
	}
}

// Test_request_id_charset keeps correlation ids to a printable alphabet.
func Test_request_id_charset(t *testing.T) {
	accepted := []string{"a", "req-1", "A_b-9", strings.Repeat("z", MaxRequestIDLen)}
	refused := []string{"", "a b", "a\"b", "a\tb", strings.Repeat("z", MaxRequestIDLen+1)}

	for _, id := range accepted {
		if !ValidRequestID(id) {
			t.Fatalf("ValidRequestID(%q) = false, want true", id)
		}
	}
	for _, id := range refused {
		if ValidRequestID(id) {
			t.Fatalf("ValidRequestID(%q) = true, want false", id)
		}
	}
}
