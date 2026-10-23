# msm-node

The MSM node agent. A Go binary that pairs with one [MSM Console](https://github.com/Multi-Server-Manager/MSM).

The wire protocol is defined once, in the console repository:
`MSM/docs/PROTOCOL.md`. This implementation exists to match that document.

## Install

*Installs & stays updated via Nebuff Repo*

```sh
curl -sSL https://install.nebuff.xyz/msm | bash
```

## Build

```sh
go build -trimpath -ldflags "-s -w -X main.version=$(cat VERSION)" -o msm-node ./cmd/msm-node
```

## Run

```sh
msm-node                       # pair on 7334, then serve on 7333
msm-node --service system      # keep state in /var/lib/msm-node (system unit)
msm-node --state-dir /tmp/x    # alternate state directory
msm-node --pairing-ttl 2m      # shorter pairing window
msm-node --pairing-attempts 5  # more wrong codes per code
msm-node --advertise-host 100.74.163.8   # pin the announced host
msm-node --debug               # trace every TLS handshake and pairing step
msm-node --foreground          # stay in the terminal instead of detaching
msm-node --detach              # detach even when stdout is not a terminal
```

A node listens for pairing on the fixed port **7334**, which is what lets a
console on another network find it: mDNS stays on one LAN, so the console asks
each Tailscale peer on that port instead. Keep the default unless two nodes
share a host. `--advertise-host` defaults to every local address, **Tailscale
first**, because that is the one a remote console can dial; `--advertise-host
host1,host2` narrows it.

Output is one machine-readable line per event:

```
MSM-NODE id=<b64> version=<v> state=<dir>
PAIR code=<8 chars> addr=<host:port> [addrs=<host:port>,...] ttl=<duration>
PAIR code=<...> addr=<...> [addrs=...] ttl=<...> rotated=<expired|abuse>
PAIRED client=<b64> spki=<b64>
PAIRING closed
LISTEN addr=<host:port>
MDNS service=_msm-node._tcp.local. instance=<host> port=<port>
MDNS disabled=<reason>
BACKGROUND pid=<pid> log=<path>
UPGRADE binary=<path> version=<v> pid=<pid> restarting
COMMAND <argv, space separated>
COMMAND failed=<detail>
RESTART unit=<unit> method=<exec|systemctl>
REBOOT requested
SSH authorize path=<file> state=<added|already-present>
```

`addr=` is the address to try first (the Tailscale one when the host has it);
`addrs=` lists the rest, and is omitted when there is only one. Before the first
pairing the node advertises its *pairing* port over mDNS; once paired it
re-announces with the operational port, so a browse after pairing never hands
out the closed pairing port. Discovery is optional — a host without multicast
logs `MDNS disabled=` and keeps serving.

### Background and upgrades

Started from a terminal, the node prints `LISTEN`, pairs if it has to, then hands
itself to a background copy and returns the shell prompt:

```
MSM-NODE id=<b64> version=<v> state=<dir>
LISTEN addr=[::]:7333
PAIRING skipped=already-paired
BACKGROUND pid=8123 log=/home/nebuff/.msm-node/msm-node.log
```

That background copy is the node: its own session (`setsid`), stdin on
`/dev/null`, stdout/stderr appended to `msm-node.log` in the state directory, so
closing the terminal or logging out does not stop it. `--debug` never detaches:
the trace you are watching would go to a file instead. `--foreground` and
anything without a terminal (a pipe, a log redirect, a systemd unit) also stay in
the foreground; the packaged units pass `--foreground` explicitly.

One node per state directory: a second start exits instead of taking over the
ports, and says how to follow and restart the running one:

```
msm-node: another msm-node is already running (pid 8123); follow its log with:
  tail -f /home/nebuff/.msm-node/msm-node.log; restart it with: kill 8123 && msm-node
```

The check is an `flock` on `msm-node.lock`, so a crash never leaves a lock that
blocks the next start; `msm-node.pid` next to it is only a hint for the operator.

A package upgrade replaces `/usr/bin/msm-node` under the running process. The
node notices within ten seconds and re-execs itself onto the new binary: same
pid, same listeners, same pairing, new version. So `dnf upgrade msm-node` needs
no restart by hand — watch `msm-node.log` for the `UPGRADE` line. A `--debug` run
is the exception: it keeps serving the old image until you restart it yourself,
because a silent restart would cut the trace.

### `--debug`

`--debug` writes a timestamped trace to **stderr**, leaving the stdout events
above unchanged. It is the thing to run when a console says `pairing` and then
nothing happens, or pairing fails with no reason. Every connection is logged
with the peer address, the TLS version, the cipher and whether a client
certificate arrived; every pairing stage and every refusal is logged with its
cause:

```
2026-10-23T11:23:54.556-04:00 DEBUG pair 100.89.238.21:45664: connected
2026-10-23T11:23:54.557-04:00 DEBUG pair 100.89.238.21:45664: TLS 1.3, cipher TLS_AES_128_GCM_SHA256, client certificate presented
2026-10-23T11:23:54.557-04:00 DEBUG pair 100.89.238.21:45664: pair.hello
2026-10-23T11:23:54.557-04:00 DEBUG pair 100.89.238.21:45664: client spki=MCowBQYDK2VwAyEA...
2026-10-23T11:23:54.558-04:00 DEBUG pair 100.89.238.21:45664: challenge sent (trials=3 ttl=291s)
2026-10-23T11:23:54.558-04:00 DEBUG pair 100.89.238.21:45664: client MCowBQYD... pinned and acknowledged
2026-10-23T11:23:54.560-04:00 DEBUG command 100.89.238.21:50012: ssh.authorize
2026-10-23T11:23:54.560-04:00 DEBUG command 100.89.238.21:50012: result id=c-0b1ad6 ok=true code=
```

A refused proof is also printed without `--debug`, because that is the one line
an operator needs: `PAIRING failed from <addr>: the code did not verify`. The
trace never contains the pairing code or a private key.

### Firewall

A node that cannot be reached cannot pair, and the default firewall on Fedora
and RHEL rejects both ports before the agent ever sees the connection. The RPM
installs the `msm-node` firewalld service and opens it in `%post`, so a packaged
install is reachable at once. For a manual install, or another firewall, allow
TCP **7334** (pairing) and **7333** (commands):

```sh
sudo firewall-cmd --permanent --add-port=7333/tcp --add-port=7334/tcp
sudo firewall-cmd --reload
```

The operational port is safe to expose: it requires the pinned console
certificate before it reads a request.

## Commands

A paired console may ask for exactly these, and nothing else (PROTOCOL.md §8):

| request | what the node does |
|---|---|
| `pkg.update` | `dnf -y upgrade`, `apt-get update` then `apt-get -y upgrade`, `pacman -Syu --noconfirm` or `apk -U upgrade` |
| `pkg.install <name>` | the manager's install argv, with the name as one argv element |
| `svc.restart [unit]` | re-execs itself when the unit is empty/`self`/`msm-node`, else `systemctl restart <unit>` |
| `host.reboot` | `systemctl reboot`, only with `confirm="reboot"` |
| `metrics.sample` | `/proc/loadavg`, `/proc/meminfo`, `/proc/uptime`, `statfs("/")` |
| `logs.tail <n>` | the agent's own last `n` lines, 1-500 |
| `ssh.authorize <key>` | one validated `ssh-ed25519` line appended to `~/.ssh/authorized_keys` (0600), idempotently |

No shell is ever involved: every process starts from an argv slice, package and
unit names are validated against their charset first, and only one command runs
at a time (`busy` for the rest). Captured output is bounded to the last 40 lines
and 32 KiB.

State lives in `~/.msm-node/config.json` (mode 0600, directory 0700) and holds
the node identity plus the pinned console identities.

## Test

```sh
go test ./...
```
