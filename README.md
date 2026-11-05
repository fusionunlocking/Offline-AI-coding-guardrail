# NEXUS Guardrail Lab V2 (offline prototype)

A standalone, **offline-only** engineering governance prototype: hash-chained failure history, duplicate-attempt prevention, and a conservative 17-node dependency/acceptance planner. It is a research utility, **not a NEXUS controller, trading system, maker launcher, reviewer, or approval authority**.

This version builds on the 3 November 2026 guardrail prototype. It adds a schema-validated, deterministic planner and isolated regression coverage. The original Execution Bridge V1 has been deliberately **excluded** because its paid-model execution mode has not passed live controller-ownership and process-supervision acceptance.

## Run offline

Requires Python 3.10+ only. No dependencies, API key, Git access, network access or NEXUS installation required.

```powershell
python -m unittest discover -s tests -p 'test_*.py' -v
python offline_planner.py examples/SYNTHETIC_NOT_AUTHORISED.json
```

Both commands operate locally. The CLI reads a JSON snapshot and prints a recommendation-only plan. Optional `--output path.json` uses exclusive creation and refuses overwrite.

## Core controls

- Fail-closed node schema: exactly N0 through N16, with explicit owner gate, work authorisation, quarantine, parents, acceptance requirement and pinned commit/tree.
- Dependency graph cycle and malformed parent detection.
- Closed states require pinned commit/tree and mandatory independent approval. A fallback decision must be expressed in the input policy, not invented by this tool.
- Pending, rejected, quarantined, unauthorised and dependent work never qualifies as eligible for controller consideration.
- Hash-chained failure ledger and no-repeat attempt logic reused from V1.
- Deterministic canonical input digest, useful for comparing two snapshots without presenting the digest as an authorisation signature.

## Limitations and threat model

- **No model or subprocess invocation, no engineering dispatch, no Git writes, no broker action and no production operation.**
- `eligible_for_controller_consideration` means only that the supplied *synthetic snapshot* clears the local checks; it does **not** prove real maker exclusivity, owner authorisation, controller delegation, approval or release readiness.
- Snapshot values are claims from whoever prepared the file. This prototype does not authenticate them or read the actual NEXUS Master Graph.
- SHA-256 hash chaining detects accidental corruption but does not prevent a privileged actor from rewriting the chain. Use signed, externally protected audit checkpoints for strong evidence.
- Do not put credentials, account details, proprietary NEXUS source, live owner ledgers or customer data into this repository.
- Any future execution bridge needs separately accepted Windows child-process supervision, PID reuse protection, exclusive maker ownership, immutable candidate review and independent acceptance.

## Public release safety

The included examples use invented data. This is an offline educational prototype, not an accepted NEXUS controller or an implementation of the live NEXUS system. No NEXUS production code, live owner ledgers, machine-specific paths or credentials are distributed. Do not submit real secrets or proprietary project content as issues or test inputs.

## License

No open-source license is included. All rights are reserved unless the repository owner explicitly chooses a license. Do not add an OSI license without an ownership decision.
