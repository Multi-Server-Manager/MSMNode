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
```

## Test

```sh
go test ./...
```
