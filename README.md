# hctr2

[![Go Reference](https://pkg.go.dev/badge/github.com/ericlagergren/hctr2.svg)](https://pkg.go.dev/github.com/ericlagergren/hctr2)

Length-preserving encryption algorithm https://eprint.iacr.org/2021/1441.pdf

## Installation

```bash
go get github.com/ericlagergren/hctr2@latest
```

## Performance

The performance of HCTR2 is primarily determined by the XCTR and
POLYVAL implementations. This module provides ARMv8 and x86-64 
assembly XCTR implementations and uses a hardware-accelerated
POLYVAL implementation (see [github.com/ericlagergren/polyval](https://pkg.go.dev/github.com/ericlagergren/polyval)).

### Results

| CPU     | ISA   | Frequency | Cycles per byte | API    |
| ---     | ---   | ---       | ---             | ---    |
| M1      | ARMv8 | 3.2 GHz   | 0.8             | NewAES |
| M1      | ARMv8 | 3.2 GHz   | 3.2             | New    |
| M1      | x86   | 2.5 GHz   | 0.7             | NewAES |
| RK3399  | ARMv8 | 1.8 GHz   | 2.7             | NewAES |
| RK3399  | ARMv8 | 1.8 GHz   | 6.1             | New    |
| Skylake | x86   | 3.9 GHz   | 1.4             | NewAES |
| Skylake | x86   | 3.9 GHz   | 6.1             | New    |

For reference, here are the numbers for the reference
C [implementation](https://github.com/google/hctr2).

| CPU     | ISA   | Frequency | Cycles per byte | API  |
| ---     | ---   | ---       | ---             | ---  |
| RK3399  | ARMv8 | 1.8 GHz   | 1.8             | simd |
| Skylake | x86   | 3.9 GHz   | 1.2             | simd |

#### Notes

- The table is computed for 8192-byte messages.
- The table is for encryption (decryption is equivalent).
- The `New` API uses the stdlib's `crypto/aes` package.
- The `NewAES` API uses this package's assembly XCTR
   implementation.
- CPU frequencies are approximate and always assume the maximum
   available frequency. E.g., benchmarks for big.LITTLE CPUs are
   assumed to only use the big cores.

## Security

### Disclosure

This project uses full disclosure. If you find a security bug in
an implementation, please e-mail me or create a GitHub issue.

### Disclaimer

You should only use cryptography libraries that have been
reviewed by cryptographers or cryptography engineers. While I am
a cryptography engineer, I'm not your cryptography engineer, and
I have not had this project reviewed by any other cryptographers.
