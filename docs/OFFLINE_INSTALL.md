# Offline installation

The offline kit (attached to each GitHub release) installs NiFiMCP on a machine with no network access. It targets
**Linux x86_64 with CPython 3.12**. Other platforms are not yet tested; see the capability matrix.

## Contents

| Item | Purpose |
|---|---|
| `wheelhouse/` | The NiFiMCP wheel and every locked runtime dependency as binary wheels |
| `requirements.lock` | Runtime lock with a sha256 hash for every dependency |
| `SHA256SUMS` | Hash of every file in the kit |
| `sbom.cdx.json` | CycloneDX 1.5 software bill of materials |
| `license-inventory.json`, `LICENSES/` | Declared license and shipped license files for each wheel |
| `install.sh`, `verify.sh` | Verify then install into a virtual environment |
| `offline_acceptance.sh` | The acceptance run used for release qualification |
| `examples/` | A synthetic bundle and a bundle-mode configuration |

## Install

1. Copy the kit tarball and its `.sha256` file to the target machine through your approved transfer path.
2. Check the tarball: `sha256sum -c nifimcp-offline-<version>-linux-x86_64-cp312.tar.gz.sha256`
3. Unpack it and run the installer:

```sh
tar xzf nifimcp-offline-<version>-linux-x86_64-cp312.tar.gz
cd nifimcp-offline-<version>-linux-x86_64-cp312
./install.sh /opt/nifimcp/venv
```

`install.sh` verifies every file against `SHA256SUMS`, creates a virtual environment with `python3.12`,
installs dependencies with `pip --no-index --require-hashes` from the wheelhouse only, then installs NiFiMCP.
Set `PYTHON=/path/to/python3.12` if it is not on `PATH`.

## First run

```sh
/opt/nifimcp/venv/bin/nifimcp demo --output ./nifimcp-demo
```

The demo needs no NiFi, model or network. Open `nifimcp-demo/report.html` in a browser.

To review your own exported data, write a bundle-mode configuration (see `examples/operator.bundle.json`),
register a bundle and describe it:

```sh
nifimcp register --config operator.json --kind bundle --label my-flow ./my-bundle
nifimcp describe --config operator.json --scope <scope_id from the bundle manifest>
```

## Reproduce the acceptance run

```sh
docker run --rm --network none -v "$PWD":/kit:ro python:3.12-slim sh /kit/offline_acceptance.sh
```

The script first proves that outbound connections fail, then installs from the kit and runs the demo,
bundle registration, `doctor`, `describe` and `report`.
