# ResearcherFinance — public release repository

Prepared for the authorized GitHub Pages project site:

https://dr-jwwu.github.io/researcher-finance/

**Preparation is not deployment.** At the time this initial README was prepared, the remote repository and Pages deployment had not been created. A successful workflow plus independent live identity checks are required before reporting the website online.

## Purpose and publication boundary

This repository is intended to hold only the Pages deployment workflow, a small standard-library Python verifier and its required modules, and this public explanation. The rendered website is distributed as a checked GitHub Release archive, not rebuilt from private data on a runner.

The private Researcher application, collectors, databases, raw source documents, original excerpts, review bases, evidence packets, logs, credentials and per-file private source inventories are **not** part of this repository or release. No new remote is added to the private project. The intended runner is GitHub-hosted, not self-hosted.

## Initial public data

The first formal snapshot contains **3 disclosure events, 3 versions, 1 reported revenue amount and 0 observations**. It is not a complete financing database and does not represent three financing rounds.

- Palladyne: Form 8-K Item 3.02 disclosure; no round or amount inferred.
- Serve Robotics: Form 8-K Item 2.02 results disclosure; not a financing transaction; amount not collected.
- Symbotic: reported revenue of **720,838,000 USD** for the original interval **2026-03-29 through 2026-06-27**, not investment or financing.

The three exact current versions were approved through an **automated/AI review process**, not human verification. Public review provenance is marked automated. Source permission gates remain separate; AI approval does not authorize access, satisfy conditional collection terms or upgrade old unreviewed records. Missing values are not zero and unlike periods/dimensions are not added together.

## Formal release identity

| Field | Expected value |
|---|---|
| Version / tag | `2026-10-12T10-16Z-final3` |
| Build ID | `rf-build-02881fc37a89e7cc` |
| Archive SHA-256 | `98e3adb33b9145461349d21f9a0a774bf0796a4711bd4b79b8b1cb7bb3568b24` |
| Site-content payload SHA-256 | `18813a14b6d0b1be6186e72fd6d3513bf97ea6dea11b6dacac0f0119693ee934` |
| Content-and-identity packaged SHA-256 | `7c635391e08db72b1b765c6dce1ec0395c4d8c8a805e46c0e577bc757343f272` |
| Export-bundle SHA-256 | `82a471fc831f363686361c022f8497cde0eabc612bfefad6761253ff44f91ff1` |
| Snapshot | `snp_9b42147946701cc6ede6` |
| Data cutoff | `2026-10-12T09:51:50Z` |

The archive contains 91 content files plus 2 identity files. The archive, payload and packaged digests are distinct. The in-archive manifest cannot include its own final archive digest; an external manifest, checksum file and workflow input bind those bytes.

Local stage results: independent data readiness 15/15; approved artifact browser checks 46/46; independent final package verdict **TECHNICAL PASS with a source-freeze process deviation**. Two unreported post-freeze packaging-tool repairs and three prepare attempts (failed / failed / succeeded) remain documented in the private audit record. The old source-equality failure was not upgraded or erased. All 91 final site-content files matched the approved artifact byte-for-byte.

## Intended publication layout

The following files must be installed and locally validated before any initial commit. Their absence is not a valid deployment configuration:

```text
.github/workflows/publish.yml
README.md
ops/deployment/public_artifact_verify.py
ops/deployment/researcher_finance_deploy/__init__.py
ops/deployment/researcher_finance_deploy/gates.py
ops/deployment/researcher_finance_deploy/manifest.py
ops/deployment/researcher_finance_deploy/safe_archive.py
```

The workflow is manually dispatched with expected version, archive SHA-256 and build ID. It downloads only four public assets from this repository's selected release:

```text
researcher-finance-site-2026-10-12T10-16Z-final3.tar.gz
SHA256SUMS
PUBLISH_MANIFEST.json
status.json
```

It refuses malformed inputs, wrong archive bytes, unsafe archive members and leaking/preview payloads, verifies identity, checks ordering against live status, and deploys only after those gates pass. Official top-level actions are commit-pinned. One composite action has an upstream tag-based nested dependency; pinning top-level actions does not remove all upstream supply-chain risk.

Pages must be explicitly enabled with GitHub Actions as its source. The workflow does not create repositories, enable Pages or request private application secrets.

## Operating limits

- Initial indexing policy: **noindex**. Public access and search-engine indexing are separate choices.
- No scheduled collector or update service has been installed; no continuous-running claim is made.
- The initial formal version has no previous formal release available for rollback. Rehearsal packages are not online rollback targets.
- Logical no-overwrite checks do not make repository/Release assets or local files physically immutable to their owner.
- Subsequent release changes must receive fresh data/review and archive identity checks; do not alter or repack this already-audited version.
