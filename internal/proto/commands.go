package proto

import "regexp"

// Command message types (PROTOCOL.md §8.3).
const (
	TypePkgUpdate     = "pkg.update"
	TypePkgInstall    = "pkg.install"
	TypeSvcRestart    = "svc.restart"
	TypeHostReboot    = "host.reboot"
	TypeMetricsSample = "metrics.sample"
	TypeLogsTail      = "logs.tail"
	TypeSSHAuthorize  = "ssh.authorize"
	TypeResult        = "result"
)

// Result codes that arrive inside a `result` (PROTOCOL.md §9).
const (
	CodeBadArgument          = "bad_argument"
	CodeUnsupported          = "unsupported"
	CodeConfirmationRequired = "confirmation_required"
	CodeFailed               = "failed"
	CodeBusy                 = "busy"
)

// Limits fixed by PROTOCOL.md §8.
const (
	MaxLogLines        = 500
	MaxLogBufferLines  = 2000
	MaxLogLineBytes    = 512
	MaxOutputBytes     = 32 << 10
	MaxOutputLines     = 40
	MaxPackageNameLen  = 64
	MaxUnitLen         = 64
	MaxRequestIDLen    = 64
	MaxSSHKeyLineLen   = 512
	RebootConfirmation = "reboot"
)

// A leading `-`, `+`, `.` or `:` is excluded from both names: the element after
// the verb is what a manager reads as a flag or a path, never as a name
// (PROTOCOL.md §8.3).
var (
	packageNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9._:+-]{0,63}$`)
	unitPattern        = regexp.MustCompile(`^[a-zA-Z0-9@_][a-zA-Z0-9@._:-]{0,63}$`)
	requestIDPattern   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

// PkgUpdate asks the node to upgrade every installed package.
type PkgUpdate struct {
	T  string `json:"t"`
	V  int    `json:"v"`
	ID string `json:"id"`
}

// Type implements Message.
func (m *PkgUpdate) Type() string { return TypePkgUpdate }

// PkgInstall asks the node to install one named package.
type PkgInstall struct {
	T    string `json:"t"`
	V    int    `json:"v"`
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Type implements Message.
func (m *PkgInstall) Type() string { return TypePkgInstall }

// SvcRestart asks the node to restart a service; an empty unit means itself.
type SvcRestart struct {
	T    string `json:"t"`
	V    int    `json:"v"`
	ID   string `json:"id"`
	Unit string `json:"unit"`
}

// Type implements Message.
func (m *SvcRestart) Type() string { return TypeSvcRestart }

// HostReboot asks the node to reboot the machine.
type HostReboot struct {
	T       string `json:"t"`
	V       int    `json:"v"`
	ID      string `json:"id"`
	Confirm string `json:"confirm"`
}

// Type implements Message.
func (m *HostReboot) Type() string { return TypeHostReboot }

// MetricsSample asks for one usage sample.
type MetricsSample struct {
	T  string `json:"t"`
	V  int    `json:"v"`
	ID string `json:"id"`
}

// Type implements Message.
func (m *MetricsSample) Type() string { return TypeMetricsSample }

// LogsTail asks for the node's own recent log lines.
type LogsTail struct {
	T     string `json:"t"`
	V     int    `json:"v"`
	ID    string `json:"id"`
	Lines int    `json:"lines"`
}

// Type implements Message.
func (m *LogsTail) Type() string { return TypeLogsTail }

// SSHAuthorize installs one authorized_keys line (PROTOCOL.md §8.11).
type SSHAuthorize struct {
	T   string `json:"t"`
	V   int    `json:"v"`
	ID  string `json:"id"`
	Key string `json:"key"`
}

// Type implements Message.
func (m *SSHAuthorize) Type() string { return TypeSSHAuthorize }

// Result is the single response envelope for every command (PROTOCOL.md §8.4).
type Result struct {
	T      string `json:"t"`
	V      int    `json:"v"`
	ID     string `json:"id"`
	OK     bool   `json:"ok"`
	Code   string `json:"code,omitempty"`
	Detail string `json:"detail,omitempty"`
	Data   any    `json:"data,omitempty"`
}

// Type implements Message.
func (m *Result) Type() string { return TypeResult }

// NewResult builds a successful result.
func NewResult(id string, data any) *Result {
	return &Result{T: TypeResult, V: Version, ID: id, OK: true, Data: data}
}

// NewFailure builds a refused result.
func NewFailure(id, code, detail string) *Result {
	return &Result{T: TypeResult, V: Version, ID: id, Code: code, Detail: detail}
}

// PackageResult is the payload of pkg.update and pkg.install (§8.5, §8.6).
type PackageResult struct {
	Manager  string     `json:"manager"`
	Commands [][]string `json:"commands"`
	ExitCode int        `json:"exit_code"`
	Output   string     `json:"output"`
}

// ServiceResult is the payload of svc.restart (§8.7).
type ServiceResult struct {
	Unit   string `json:"unit"`
	Method string `json:"method"`
}

// RebootResult is the payload of host.reboot (§8.8).
type RebootResult struct {
	Method string `json:"method"`
}

// MetricsResult is the payload of metrics.sample (§8.9).
type MetricsResult struct {
	Load1          float64 `json:"load1"`
	Load5          float64 `json:"load5"`
	Load15         float64 `json:"load15"`
	CPUCount       int     `json:"cpu_count"`
	MemTotalKB     uint64  `json:"mem_total_kb"`
	MemAvailableKB uint64  `json:"mem_available_kb"`
	UptimeS        uint64  `json:"uptime_s"`
	DiskTotalKB    uint64  `json:"disk_total_kb"`
	DiskAvailKB    uint64  `json:"disk_available_kb"`
}

// SSHAuthorizeResult is the payload of ssh.authorize (§8.11).
type SSHAuthorizeResult struct {
	Path  string `json:"path"`
	Added bool   `json:"added"`
}

// LogsResult is the payload of logs.tail (§8.10).
type LogsResult struct {
	Lines   []string `json:"lines"`
	Dropped int      `json:"dropped"`
}

// ValidPackageName reports whether a package name may be passed to a manager.
func ValidPackageName(name string) bool {
	return len(name) <= MaxPackageNameLen && packageNamePattern.MatchString(name)
}

// ValidUnit reports whether a service unit name is acceptable.
func ValidUnit(unit string) bool {
	return len(unit) <= MaxUnitLen && unitPattern.MatchString(unit)
}

// ValidRequestID reports whether a request id is acceptable.
func ValidRequestID(id string) bool {
	return len(id) <= MaxRequestIDLen && requestIDPattern.MatchString(id)
}
