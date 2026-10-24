package sys

import (
	"fmt"
	"regexp"
	"strings"
)

// A package run ends with an exit code, and an exit code is not an answer.
// "dnf exited with 0" tells an operator nothing they cannot already see; what
// they asked was whether anything changed. Every manager reports that in its
// own words — dnf and apt print a transaction summary, pacman and apk number
// each step — so the numbers below are read from those reports.
//
// This is display text only. Nothing here decides whether a command succeeded:
// the exit code does, and a summary that cannot be read falls back to a plain
// sentence rather than changing an outcome.

var (
	// dnf4: "Upgrade  22 Packages". dnf5: " Upgrading:         22 packages".
	dnfUpgrade = regexp.MustCompile(`(?mi)^\s*(?:Upgrading|Upgrade|Reinstalling|Reinstall|Downgrading|Downgrade):?\s+(\d+)\s+packages?\s*$`)
	// apt-get: "3 upgraded, 0 newly installed, 0 to remove and 0 not upgraded."
	aptSummary = regexp.MustCompile(`(?m)^(\d+) upgraded, (\d+) newly installed`)
	// pacman: "Packages (2) foo-1.1-1  bar-2.0-1".
	pacmanPackages = regexp.MustCompile(`(?m)^Packages \((\d+)\)`)
	// pacman and apk number each step: "(1/3) Upgrading foo (1.0 -> 1.1)".
	step = regexp.MustCompile(`(?mi)^\(\d+/\d+\) (Upgrading|Installing|Reinstalling|Downgrading) `)
	// An upgrade replaces or removes packages; only those steps count as an
	// update, so a dependency apk had to install does not inflate the number.
	upgradeStep = regexp.MustCompile(`(?mi)^\(\d+/\d+\) (Upgrading|Reinstalling|Downgrading) `)
)

// Summarize phrases what one package run did, in a sentence meant for the panel
// and the node's log. installName is empty for an update.
func (m Manager) Summarize(installName, output string) string {
	quiet := m.noChanges(output)

	if installName != "" {
		if quiet {
			return fmt.Sprintf("%s was already installed", installName)
		}
		return fmt.Sprintf("%s was installed", installName)
	}

	if quiet {
		return "there were no updates"
	}
	if count, ok := m.updated(output); ok {
		if count == 1 {
			return "1 package was updated"
		}
		return fmt.Sprintf("%d packages were updated", count)
	}
	// The manager's report was not in the tail we kept (a very large
	// transaction pushes the summary out of it). Say what is still true.
	return "the update finished"
}

// noChanges reports whether the manager said there was nothing to do.
func (m Manager) noChanges(output string) bool {
	switch m.Name {
	case "dnf":
		return strings.Contains(output, "Nothing to do.") ||
			strings.Contains(output, "There is nothing to do") ||
			strings.Contains(output, "is already installed")
	case "apt":
		match := aptSummary.FindStringSubmatch(output)
		return match != nil && match[1] == "0" && match[2] == "0"
	case "pacman":
		// "there is nothing to do" is pacman's own wording. Do not treat
		// "up to date -- reinstalling" as nothing: pacman really reinstalls
		// the package in that case.
		return strings.Contains(strings.ToLower(output), "there is nothing to do")
	case "apk":
		// apk always ends with an "OK: … in N packages" line, whether or not
		// it touched anything; the numbered steps are the only evidence of
		// work.
		return !step.MatchString(output)
	default:
		return false
	}
}

// updated reads how many packages an update changed.
func (m Manager) updated(output string) (int, bool) {
	switch m.Name {
	case "dnf":
		total := 0
		found := false
		for _, match := range dnfUpgrade.FindAllStringSubmatch(output, -1) {
			var count int
			if _, err := fmt.Sscanf(match[1], "%d", &count); err == nil {
				total += count
				found = true
			}
		}
		return total, found
	case "apt":
		match := aptSummary.FindStringSubmatch(output)
		if match == nil {
			return 0, false
		}
		var count int
		if _, err := fmt.Sscanf(match[1], "%d", &count); err != nil {
			return 0, false
		}
		return count, true
	case "pacman":
		match := pacmanPackages.FindStringSubmatch(output)
		if match == nil {
			count := len(upgradeStep.FindAllString(output, -1))
			return count, count > 0
		}
		var count int
		if _, err := fmt.Sscanf(match[1], "%d", &count); err != nil {
			return 0, false
		}
		return count, true
	case "apk":
		count := len(upgradeStep.FindAllString(output, -1))
		return count, count > 0
	default:
		return 0, false
	}
}
