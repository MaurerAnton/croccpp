# croccpp — Secure File Transfer (C++ port of croc)

A zero-dependency C++ port of [croc](https://github.com/schollz/croc) — securely transfer files and folders between computers using relay-assisted peer-to-peer with end-to-end encryption.

## Why croccpp?

The original [croc](https://github.com/schollz/croc) requires the Go toolchain plus dozens of modules. croccpp compiles with a single `make` using only C++17 and standard Linux headers.

## Quick Start

```bash
make
./croccpp send <file>
./croccpp <code-phrase>
```

## Features

- End-to-end encryption (PAKE + AES)
- Code phrase authentication (no IP sharing)
- Resume interrupted transfers
- Relay mode for NAT traversal
- Folder transfer with auto-compression
- Proxy support
- Custom relay server support

## Build

```bash
make
```
Requires: GCC 10+ or Clang 12+, GNU Make
