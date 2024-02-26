# Mutavault
mutavault provides additional utilities for interacting with Hashicorp Vault.

## Installation
```sh
git clone github.com/sapcc/mutavault
cd mutavault
make
```

## Usage
The vault address and token are read from the `VAULT_ADDR` and `VAULT_TOKEN` environment variables respectively.

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
