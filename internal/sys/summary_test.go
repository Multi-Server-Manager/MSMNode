package sys

import "testing"

// The outputs below are the real closing lines of each manager (dnf5 5.4 is
// captured from a Fedora 44 host; the others are the documented formats).
// They are the only input Summarize gets, so each case pins the wording an
// operator will read.
func TestSummarizeUpdate(t *testing.T) {
	cases := []struct {
		name    string
		manager string
		output  string
		want    string
	}{
		{
			name:    "dnf nothing to do",
			manager: "dnf",
			output:  "Updating and loading repositories:\nRepositories loaded.\nNothing to do.\n",
			want:    "there were no updates",
		},
		{
			name:    "dnf one package",
			manager: "dnf",
			output: "Transaction Summary:\n Upgrading:         1 package\n\n" +
				"Total size of inbound packages is 139 KiB. Need to download 139 KiB.\n",
			want: "1 package was updated",
		},
		{
			name:    "dnf4 several packages",
			manager: "dnf",
			output: "Dependencies resolved.\nTransaction Summary\n============\nUpgrade  3 Packages\n\n" +
				"Total download size: 12 M\n",
			want: "3 packages were updated",
		},
		{
			name:    "apt several packages",
			manager: "apt",
			output: "Calculating upgrade...\nThe following packages will be upgraded:\n  foo bar baz\n" +
				"3 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n",
			want: "3 packages were updated",
		},
		{
			name:    "apt nothing to do",
			manager: "apt",
			output:  "Calculating upgrade... Done\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n",
			want:    "there were no updates",
		},
		{
			name:    "pacman several packages",
			manager: "pacman",
			output: ":: Starting full system upgrade...\nPackages (2) foo-1.1-1  bar-2.0-1\n\n" +
				"Total Download Size: 3.10 MiB\n(1/2) upgrading foo\n(2/2) upgrading bar\n",
			want: "2 packages were updated",
		},
		{
			name:    "pacman nothing to do",
			manager: "pacman",
			output:  ":: Synchronising package databases...\n:: Starting full system upgrade...\n there is nothing to do\n",
			want:    "there were no updates",
		},
		{
			name:    "pacman steps without a header",
			manager: "pacman",
			output:  "(1/1) upgrading cowsay\n",
			want:    "1 package was updated",
		},
		{
			name:    "apk several packages",
			manager: "apk",
			output: "fetch https://dl-cdn.alpinelinux.org/alpine/v3.20/main/x86_64/APKINDEX.tar.gz\n" +
				"(1/2) Upgrading foo (1.0-r0 -> 1.1-r0)\n(2/2) Upgrading bar (2.0-r1 -> 2.1-r0)\n" +
				"OK: 512 MiB in 300 packages\n",
			want: "2 packages were updated",
		},
		{
			name:    "apk nothing to do",
			manager: "apk",
			output:  "fetch https://dl-cdn.alpinelinux.org/alpine/v3.20/main/x86_64/APKINDEX.tar.gz\nOK: 512 MiB in 300 packages\n",
			want:    "there were no updates",
		},
		{
			name:    "an unreadable report still says something true",
			manager: "dnf",
			output:  "Downloading packages...\n[1/40] foo 12%\n",
			want:    "the update finished",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Manager{Name: tc.manager}.Summarize("", tc.output)
			if got != tc.want {
				t.Fatalf("Summarize(%q) = %q, want %q", tc.output, got, tc.want)
			}
		})
	}
}

func TestSummarizeInstall(t *testing.T) {
	cases := []struct {
		name    string
		manager string
		pkg     string
		output  string
		want    string
	}{
		{
			name:    "dnf installed it",
			manager: "dnf",
			pkg:     "figlet",
			output: "Package Arch   Version         Repository      Size\nInstalling:\n" +
				" figlet x86_64 0:2.2.5-39.fc44 fedora     668.7 KiB\n\n" +
				"Transaction Summary:\n Installing:         1 package\n",
			want: "figlet was installed",
		},
		{
			name:    "dnf already had it",
			manager: "dnf",
			pkg:     "cowsay",
			output: "Repositories loaded.\nPackage \"cowsay-3.8.4-5.fc44.noarch\" is already installed.\n\n" +
				"Nothing to do.\n",
			want: "cowsay was already installed",
		},
		{
			name:    "apt installed it",
			manager: "apt",
			pkg:     "cowsay",
			output: "The following NEW packages will be installed:\n  cowsay\n" +
				"0 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.\n",
			want: "cowsay was installed",
		},
		{
			name:    "apt already had it",
			manager: "apt",
			pkg:     "cowsay",
			output: "cowsay is already the newest version (3.03+dfsg2-8).\n" +
				"0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n",
			want: "cowsay was already installed",
		},
		{
			name:    "pacman installed it",
			manager: "pacman",
			pkg:     "cowsay",
			output:  "Packages (1) cowsay-3.7.0-2\n\n(1/1) installing cowsay\n",
			want:    "cowsay was installed",
		},
		{
			// pacman really does reinstall a package that is up to date, so
			// "already installed" would be a lie here.
			name:    "pacman reinstalled it",
			manager: "pacman",
			pkg:     "cowsay",
			output:  "warning: cowsay-3.7.0-2 is up to date -- reinstalling\n(1/1) reinstalling cowsay\n",
			want:    "cowsay was installed",
		},
		{
			name:    "apk installed it",
			manager: "apk",
			pkg:     "cowsay",
			output:  "(1/1) Installing cowsay (3.7.0-r0)\nOK: 512 MiB in 301 packages\n",
			want:    "cowsay was installed",
		},
		{
			name:    "apk already had it",
			manager: "apk",
			pkg:     "cowsay",
			output:  "OK: 512 MiB in 300 packages\n",
			want:    "cowsay was already installed",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Manager{Name: tc.manager}.Summarize(tc.pkg, tc.output)
			if got != tc.want {
				t.Fatalf("Summarize(%q, %q) = %q, want %q", tc.pkg, tc.output, got, tc.want)
			}
		})
	}
}
