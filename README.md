# opam audit

The `opam-audit` command line utility keeps a local copy of the [OCaml security advisory database](https://github.com/ocaml/security-advisories) and checks whether any package in the active opam switch has a known security advisory.

When a vulnerable package is found, `opam-audit` reports the affected package together with the corresponding security advisory. It exits with an error (exit code = 124) if any vulnerability is detected, making it suitable for use in CI.

## Installation

`opam install opam-audit`

## Execution

`opam-audit`
