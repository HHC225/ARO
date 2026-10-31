# Security policy

ARO processes untrusted local package metadata and remote advisory data. Its
checks should remain read-only with respect to installed software and project
files. Patching should require approval of an intact, unexpired plan tied to
fresh inventory. Source/credential upload, command injection, unsafe path
handling, approval bypass and misleading clean results are security concerns.

## Reporting a vulnerability

Please use [GitHub's private vulnerability reporting](https://github.com/HHC225/ARO/security/advisories/new)
if it is enabled for this repository. If that page is unavailable, consult the
maintainer's [GitHub profile](https://github.com/HHC225) for a private contact
method. Do not disclose credentials or private infrastructure details in a
public issue. This repository does not promise a response deadline.

Include the affected revision, Linux/Windows version, Python version, minimal
reproduction with redacted fixture data, expected/actual behavior and security
impact. For an approval or injection issue, show the trust boundary crossed.
Do not run destructive payloads against systems you do not control.

## Operational limits

ARO is an aid for identifying known vulnerabilities, not a guarantee that a
machine is secure. It cannot discover every custom binary, inspect inaccessible
paths, infer external firewall/router policy or compensate for unavailable
advisory services. Coverage and stale data are part of the result. CGNAT does
not establish isolation.

Review update plans and their dependency effects before approval. Maintain
appropriate backups and maintenance procedures for your environment. ARO does
not automatically elevate privileges or trigger a separate restart/reboot.
Package/vendor installation hooks can restart services; approval must cover
downtime. Application health requires separately authorized checks. Local state
contains software and path details; keep it private and out of repositories.

The current development branch is the maintenance target. There is no promise
of backports to historical revisions. Review changes before updating an
installed skill.
