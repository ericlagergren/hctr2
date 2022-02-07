# hctr2

[![Go Reference](https://pkg.go.dev/badge/github.com/ericlagergren/hctr2.svg)](https://pkg.go.dev/github.com/ericlagergren/hctr2)

Length-preserving encryption algorithm https://eprint.iacr.org/2021/1441.pdf

## Installation

```bash
go get github.com/ericlagergren/hctr2@latest
```

## Performance

The performance of HCTR2 is determined by two things: XCTR and
POLYVAL. This module provides ARMv8 and x86-64 assembly XCTR
implementations and uses a hardware-accelerated POLYVAL
implementation (see [github.com/ericlagergren/polyval](https://pkg.go.dev/github.com/ericlagergren/polyval)).

The ARMv8 assembly implementation of XCTR-AES-256 with
hardware-accelerated POLYVAL runs at about 1 cycle per byte.

The x86-64 assembly implementation of XCTR-AES-256 with
hardware-accelerated POLYVAL runs at about 0.8 cycles per byte.

The `crypto/aes` implementation of XCTR-AES-256 with
hardware-accelerated POLYVAL runs at about 4 cycles per byte.

## Security

### Disclosure

This project uses full disclosure. If you find a security bug in
an implementation, please e-mail me or create a GitHub issue.

### Disclaimer

You should only use cryptography libraries that have been
reviewed by cryptographers or cryptography engineers. While I am
a cryptography engineer, I'm not your cryptography engineer, and
I have not had this project reviewed by any other cryptographers.
