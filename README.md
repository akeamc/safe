# Safe

_Safe_ is a gRPC-managed PKI server that uses [Shamir's secret sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing) to encrypt the private keys of the issuers. This means that the database is useless for an attacker unless they possess an additional client secret.

## Management

The management interface, inspired by [HCP Vault's PKI engine](https://developer.hashicorp.com/vault/api-docs/secret/pki), is gRPC-based, and the specification (with docs) can be found in the `./proto` directory. There is a Python client available in `./safe-py`.
