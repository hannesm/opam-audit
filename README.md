# opam audit

The `opam-audit` command line utility keeps a local copy of the [OCaml security advisory database](https://github.com/ocaml/security-advisories) and checks whether any package in the active opam switch has a known security advisory.

When a vulnerable package is found, `opam-audit` reports the affected package together with the corresponding security advisory. It exits with an error (exit code = 1) if any vulnerability is detected, making it suitable for use in CI.

## Installation

`opam install opam-audit`

## Execution

`opam-audit`

## License

It is licensed under the AGPL-3.0 or later.

## AI

Contributions involving AI must comply with the rules set out [here](./AI.md).
If they do not comply, we reserve the right to reject your contribution.
