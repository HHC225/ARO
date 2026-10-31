# Verification

This record describes checks actually run during the initial implementation. Native operating-system checks remain limited to the visible environment and configured scope.

## Local Linux checks

- The standard-library unittest suite covers source query contracts, lockfile and OS metadata, runtime records, cache and pagination failures, matching boundaries, state reconciliation, network evidence, patch approval and target-scope protections.
- `python tests/smoke_cli.py` verifies automatic first-run initialization, an unchanged rescan, an offline incomplete result and the platform launcher using a temporary application. It does not install a package.
- A native Linux inventory collected 779 components. Repeating the same scoped scan returned zero added, changed or removed components and an unchanged map fingerprint.
- Live public-coordinate queries exercised OSV, the PSF and Node.js sources, plus native Ubuntu source-package coordinates. HTTP failures remained coverage entries; the official CISA mirror was used after the canonical endpoint was denied.
- Approval, changed/tampered plans, environment drift, failed patch execution, native transaction changes, npm installation scope and Python virtual-environment identity were tested with harmless temporary fixtures and injected command runners. No live system patch was performed.

## Cross-platform CI

The [ARO validation workflow](https://github.com/HHC225/ARO/actions/workflows/ci.yml) runs Ubuntu and Windows with Python 3.11 and 3.13. Each job runs the unit/adapter tests, a native CLI/launcher smoke and Python compilation. A Windows-only read-only WUA probe is bounded and skips when the update service is disabled. A successful bounded probe does not imply an online Windows Update search completed or that a particular KB was installed. Consult the workflow run for the actual platform result.

## Explicit validation limits

Docker, Syft and Trivy adapters have structured fixture tests. Their behavior on a real Docker host, a particular installed scanner release, a private registry or a production deployment needs a scoped operator check. Tests do not establish complete support for every vendor/runtime or prove application health after an update.
