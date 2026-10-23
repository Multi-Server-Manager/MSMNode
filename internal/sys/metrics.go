package sys

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
)

// Metrics is one usage sample (PROTOCOL.md §8.9).
type Metrics struct {
	Load1          float64
	Load5          float64
	Load15         float64
	CPUCount       int
	MemTotalKB     uint64
	MemAvailableKB uint64
	UptimeS        uint64
	DiskTotalKB    uint64
	DiskAvailKB    uint64
}

// Sample reads the kernel counters behind one usage sample.
//
// The load average and memory totals are required: a host without a readable
// /proc cannot report metrics, so the caller refuses with `unsupported` rather
// than inventing numbers.
func Sample() (Metrics, error) {
	metrics := Metrics{CPUCount: runtime.NumCPU()}

	loadavg, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return metrics, err
	}
	if _, err := fmt.Sscanf(string(loadavg), "%f %f %f", &metrics.Load1, &metrics.Load5, &metrics.Load15); err != nil {
		return metrics, err
	}

	meminfo, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return metrics, err
	}
	metrics.MemTotalKB, metrics.MemAvailableKB = parseMeminfo(string(meminfo))
	if metrics.MemTotalKB == 0 {
		return metrics, errors.New("meminfo reports no MemTotal")
	}

	if uptime, err := os.ReadFile("/proc/uptime"); err == nil {
		var seconds float64
		if _, err := fmt.Sscanf(string(uptime), "%f", &seconds); err == nil {
			metrics.UptimeS = uint64(seconds)
		}
	}

	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err == nil {
		metrics.DiskTotalKB = stat.Blocks * uint64(stat.Bsize) / 1024
		metrics.DiskAvailKB = stat.Bavail * uint64(stat.Bsize) / 1024
	}

	return metrics, nil
}

func parseMeminfo(text string) (total, available uint64) {
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			total = parseKilobytes(fields[1])
		case "MemAvailable:":
			available = parseKilobytes(fields[1])
		}
	}
	return total, available
}

func parseKilobytes(field string) uint64 {
	var value uint64
	_, _ = fmt.Sscanf(field, "%d", &value)
	return value
}
