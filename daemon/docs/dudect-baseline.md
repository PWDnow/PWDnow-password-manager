
# Dudect Measurement Baseline

## `localCrypto.ts::timingSafeEq`
-Run environment: V8/Chromium 114
-Baseline: Empirically constant-bitwise xor, timing differences between early-divergence and late-divergence strings are within margin of error (p > 0.05 in Welch's t-test).

## `SQLCipher` VM[ Key Check
-Run environment: rust-sqlite30, Linux x86_64
-Baseline: SQLCipher's internal HMAC-validation is constant-time.
Submitting invalid keys yields a uniform latency independent of the number of correct bits in the key candidate.
