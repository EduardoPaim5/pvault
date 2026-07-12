# Fuzzer seeds

These are Base64-encoded, synthetic starting inputs. `scripts/fuzz-smoke.sh`
decodes them into its private persistent corpus before invoking libFuzzer.

Never add a real vault, recovery code, password, clipboard capture, core dump,
or user-provided crash artifact here. A newly discovered crashing input may
describe an unpublished vulnerability; handle it according to `SECURITY.md`
before reducing or committing it.

The evolving local corpus lives under `.cache/fuzz/corpus/` by default. Crash,
timeout, OOM, and leak artifacts live separately under
`.cache/fuzz/artifacts/`. Both paths are ignored by Git.
