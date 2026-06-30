# PseudoForge General Binary Benchmark Fixtures

This directory is reserved for small synthetic JSON fixtures used by
`tools/pseudoforge_benchmark.py` and `tests/test_benchmark.py`.

Do not place real third-party binaries here. The benchmark harness must be able
to run in CI without IDA and without large corpus assets.
