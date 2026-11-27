# Independent verification

Focused local regression: 23 passed. Independent four checks: three passed, one failed, then the same defect was confirmed after native MISP JSON load. No live MISP contacted. Missing optional template submodule failures were not scored.

Use the exact argv/cwd in regression-r1 and contract-r1 (plus contract-r2 for the JSON-roundtrip confirmation). All code is imported from the unchanged frozen replay-source. Temporary data stays in cache. Dependency versions are pinned in requirements-lock.txt.
