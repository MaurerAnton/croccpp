# croccpp — P2P Encrypted File Transfer (C++ port of croc)

A C++ port of [croc](https://github.com/schollz/croc) — secure peer-to-peer file transfer using AES-256-GCM encryption and code phrase authentication.

## Why croccpp?

The original [croc](https://github.com/schollz/croc) requires Go plus dozens of modules. croccpp compiles with a single `make` using C++17 and OpenSSL (libcrypto).

## Quick Start

```bash
make
# Sender:
./croccpp send myfile.tar.gz
# Code phrase is printed — share it with the receiver

# Receiver:
./croccpp
# Enter the code phrase when prompted
```

## Features

- AES-256-GCM encryption via OpenSSL (libcrypto)
- Code phrase authentication (3 random words, no IP sharing needed)
- Direct TCP file transfer (sender listens, receiver connects)
- Optional relay mode with configurable relay host/port
- File metadata: name, size in human-readable format

## Limitations

- Single file transfer only (no folders)
- No resume support for interrupted transfers
- No PAKE (password-authenticated key exchange) — uses simpler key derivation

## Build

```bash
make
```
Requires: GCC 10+ or Clang 12+, GNU Make, OpenSSL (libcrypto)
