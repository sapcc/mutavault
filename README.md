# Mutavault
mutavault provides additional utilities for interacting with Hashicorp Vault.

## Installation
```sh
git clone github.com/sapcc/mutavault
cd mutavault
make
```

## Usage
The vault address is read from `VAULT_ADDR` the environment variable respectively.
The token is read from the `VAULT_TOKEN` the environment variable or the `~/.vault-token` file created by `vault login`.

### kv
The `kv` subcommand interacts with a kvv2 engine.
Use the `-mount=path` argument to specify the mountpoint.
The following subcommands are available:
- listall: List all accessible paths in a kv engine
- getcustommetas: Gets the custom metadata of provided paths to secrets
- setcustommetas: Takes custommetadata and paths on stdin and updates vault

These comannds can be combined to update the `custom_metadata` of multiple secrets in a single pipeline, e.g.:
```
mutavault kv -mount=path listall | grep secrets-i-care-about | xargs mutavault kv -mount=path getcustommetas | jq '.[].val = "banana"' | mutavault kv -mount=path setcustommetas
```
