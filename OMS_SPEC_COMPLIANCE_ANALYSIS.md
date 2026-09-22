# OMS Spec v1.0 Compliance Analysis — model-transparency Python Package

**Date:** 2026-09-04
**Spec:** [OpenSSF Model Signing (OMS) Specification v1.0](https://github.com/ossf/model-signing-spec/blob/main/spec/v1.0.md)
**Implementation:** [sigstore/model-transparency](https://github.com/sigstore/model-transparency) — upstream `main` at commit `e7e2ae0`
**Method:** 5-agent parallel council review, each analyzing a different spec dimension, findings cross-validated and deduplicated

---

## Executive Summary

21 unique deviations identified across 7 Critical/High, 7 Medium, and 7 Low severity findings. The most impactful issues are a shard parsing bug that breaks filenames with colons, acceptance of expired certificates, a BLAKE2 round-trip failure, and silent skipping of key fingerprint verification for older bundles.

---

## Critical / High Severity

### 1. Shard name parsing uses naive `split(":")` — breaks filenames with colons

| Field | Detail |
|-------|--------|
| **Spec Section** | §6.3.2 (Shard Serialization) |
| **Requirement** | "parsers MUST identify the byte-range suffix by matching the *last two* colon-separated decimal integer components rather than splitting on the first colon." |
| **Implementation** | `_Shard.from_str()` at `manifest.py:156-158` and `_ShardSerialization.new_item()` at `manifest.py:408-413` both do `name.split(":")` and expect exactly 3 parts. |
| **Impact** | A filename like `meta:data.bin:0:1000` produces 4 parts and raises `ValueError`. Any model file with a colon in its name (legal on Linux/macOS) cannot be signed or verified with shard serialization. Breaks cross-implementation interoperability. |
| **Fix** | Use `rsplit(":", maxsplit=2)` to split from the right, matching the last two colon-delimited integers as byte-range offsets. |

### 2. Empty model not rejected — produces invalid bundle with 0 resources

| Field | Detail |
|-------|--------|
| **Spec Section** | §6.1 (File Enumeration), §5.2.1 (Resources) |
| **Requirement** | "The model MUST contain at least one regular file after exclusions are applied; an empty model MUST be rejected." / "The `resources` array MUST contain at least one entry." |
| **Implementation** | Neither `_serialization/file.py:103-155` nor `file_shard.py:114-189` check for empty enumeration results. An empty directory silently produces a bundle with `resources: []`. |
| **Impact** | Invalid bundles are produced and accepted. A trivially empty model "verifies" successfully. |
| **Fix** | Add a check after file enumeration (and after exclusions) that raises an error if no regular files remain. |

### 3. Certificate verifier accepts expired certificates

| Field | Detail |
|-------|--------|
| **Spec Section** | §8.2 (Signature Verification) |
| **Requirement** | "The leaf certificate MUST be within its validity period." |
| **Implementation** | `sign_certificate.py:220-221` pins the X509 store time to `signing_certificate.not_valid_before_utc` — the **start** of the cert's validity period. The `verify_certificate()` check then passes tautologically, because the cert is always valid at its own start time. |
| **Impact** | **Security vulnerability.** Models signed with expired certificates are accepted as valid. An attacker with a compromised expired certificate could sign malicious models that pass verification. |
| **Fix** | Use the current time (or the signature timestamp if available) instead of `not_valid_before_utc` when setting the X509 store time. Verify that the current time falls within `[not_valid_before_utc, not_valid_after_utc]`. |

### 4. BLAKE2 hash_type round-trip broken — verification fails for BLAKE2-signed bundles

| Field | Detail |
|-------|--------|
| **Spec Section** | §7 (Hashing Algorithms), §5.2.2 (Serialization) |
| **Requirement** | `hash_type` and `algorithm` fields MUST use consistent algorithm identifiers. |
| **Implementation** | The CLI accepts `"blake2"` as input (`hashing.py:199`), but the BLAKE2 hasher returns `digest_name = "blake2b"` (`memory.py:106`). The bundle stores `hash_type: "blake2b"`. On verification, `_guess_hashing_config` (`verifying.py:207`) passes `"blake2b"` to `use_file_serialization(hashing_algorithm=...)`, but the `match` statement (`hashing.py:196-204`) only accepts `"blake2"` — causing a `ValueError`. |
| **Impact** | Any model signed with BLAKE2 cannot be auto-verified. The sign path works, but the verify path rejects the algorithm name it produced. |
| **Fix** | Either accept `"blake2b"` as an alias in the `match` statement at `hashing.py:196-204`, or change the digest name in `memory.py:106` to `"blake2"`. The algorithm registry should be the source of truth. |

### 5. Pre-v1.1.0 bundles: `rawBytes`/`keyDetails` stripped, key verification silently skipped

| Field | Detail |
|-------|--------|
| **Spec Section** | §11.2 (Verifier Backward Compatibility), §4.1 (Signing Method) |
| **Requirement** | "Accept `rawBytes` (and optionally `keyDetails`) as an alternative to `hint` for key identification." |
| **Implementation** | `sign_sigstore_pb.py:119-124` deletes `rawBytes` and `keyDetails` from the parsed dict and sets `hint: None`. Then `sign_ec_key.py:173-187` checks `if bundle.verification_material.public_key.hint` — since `hint` is `None`, it prints a warning and proceeds **without any key fingerprint verification**. |
| **Impact** | **Security downgrade.** Pre-v1.1.0 bundles have no key identity verification — any public key is accepted without fingerprint matching. The `rawBytes` field that could have been used for verification is discarded. |
| **Fix** | Instead of deleting `rawBytes`, use it as an alternative verification mechanism. Compute the fingerprint from the provided public key and compare it against `rawBytes`, or compare the raw key bytes directly. |

### 6. `--ignore-unsigned-files` broken for shard serialization

| Field | Detail |
|-------|--------|
| **Spec Section** | §8.4, §8.5 (Unsigned File Handling) |
| **Requirement** | For shard resources, "extract the file path preceding the `:<start>:<end>` suffix." |
| **Implementation** | `verifying.py:114-118` builds file paths as `model_path / rd.identifier`. For shards, `rd.identifier` is `"weights.bin:0:1000000000"` — not a valid filesystem path. The file lookup fails. |
| **Impact** | `--ignore-unsigned-files` is completely unusable with shard-serialized bundles. |
| **Fix** | When building `files_to_hash` for shard manifests, extract the file path portion from shard identifiers (strip the `:<start>:<end>` suffix) before constructing the filesystem path. Deduplicate since multiple shards map to the same file. |

### 7. Compat deserialization uses string `"false"` instead of boolean `false` for `allow_symlinks`

| Field | Detail |
|-------|--------|
| **Spec Section** | §5.2.2 (Serialization) |
| **Requirement** | `allow_symlinks` is a REQUIRED **boolean**. |
| **Implementation** | `signing.py:153` constructs a fake serialization for v0.2 compat: `"allow_symlinks": "false"` — a Python **string**, not a boolean. Non-empty strings are truthy in Python, so any downstream `if args["allow_symlinks"]` evaluates to `True`. |
| **Impact** | v0.2 compat verification may incorrectly follow symlinks when it should not, potentially hashing symlink targets and producing incorrect verification results. |
| **Fix** | Change `"false"` to `False` (Python boolean). |

---

## Medium Severity

### 8. BLAKE3 shard serialization silently downgrades to file serialization

| Field | Detail |
|-------|--------|
| **Spec Section** | §6.3.2 (Shard Serialization) |
| **Requirement** | When shard serialization is requested, the bundle MUST record `method: "shards"`. |
| **Implementation** | `hashing.py:359-366` — when `use_shard_serialization()` is called with `hashing_algorithm="blake3"`, it silently calls `use_file_serialization()` instead. The bundle records `method: "files"`. |
| **Impact** | User expects shard serialization but gets file serialization with no error or warning. The resulting bundle is internally consistent but not what was requested. |
| **Fix** | Either implement BLAKE3 shard support or raise an explicit error stating that BLAKE3 is not supported with shard serialization. |

### 9. Verifier doesn't enforce `allow_symlinks` from bundle's serialization

| Field | Detail |
|-------|--------|
| **Spec Section** | §6.1.1 (Symbolic Link Handling) |
| **Requirement** | "The verifier MUST apply the same `allow_symlinks` policy recorded in `serialization.allow_symlinks` when enumerating the model for verification." |
| **Implementation** | When a user provides an explicit hashing config via CLI `--allow-symlinks`, it overrides the bundle's value silently (`verifying.py:100-107`, `_cli.py:766-770`). No warning or error about the mismatch. |
| **Impact** | Sign/verify mismatch can cause false failures (symlinks ignored during verify but followed during sign) or false acceptances (symlinks followed during verify but ignored during sign). |
| **Fix** | When the user provides an explicit `allow_symlinks` value, compare it against the bundle's `serialization.allow_symlinks` and warn on mismatch. Ideally, always use the bundle's value and ignore the CLI flag, or require the CLI flag to match. |

### 10. No warning for symlink target outside model root

| Field | Detail |
|-------|--------|
| **Spec Section** | §6.1.1 (Symbolic Link Handling) |
| **Requirement** | "If a symbolic link target is outside the model root, the signer MUST report a warning." |
| **Implementation** | `_serialization/serialization.py:44-55` — when `allow_symlinks=True`, the symlink check is simply skipped entirely. No target location validation is performed. |
| **Impact** | Symlinks pointing outside the model root are silently followed, potentially including unintended files in the manifest. |
| **Fix** | When `allow_symlinks=True`, resolve each symlink and check whether the target is within the model root. Log a warning if it is not. |

### 11. No symlink cycle detection

| Field | Detail |
|-------|--------|
| **Spec Section** | §6.1.1 (Symbolic Link Handling) |
| **Requirement** | "If resolving symbolic links produces a cycle, the signer MUST report a warning." |
| **Implementation** | No cycle detection is implemented. `model_path.glob("**/*")` will follow symlinks and could infinite-loop on circular symlinks, eventually raising an OS error. |
| **Impact** | Potential infinite loop or unhandled OS error when processing models with circular symlinks. |
| **Fix** | Track visited real paths during enumeration. If a resolved path has already been visited, log a warning and skip it. |

### 12. No UTF-8 validation on file paths

| Field | Detail |
|-------|--------|
| **Spec Section** | §6.1.2, rule 7 (Path Canonicalization) |
| **Requirement** | "All path components MUST be representable as valid UTF-8. If a filename contains byte sequences that are not valid UTF-8, the signer MUST reject the file." |
| **Implementation** | No explicit validation in `file.py:108-119` or `file_shard.py:142-153`. On Linux, filenames can contain arbitrary byte sequences. Python's `pathlib` may silently use surrogate escapes for non-UTF-8 bytes. |
| **Impact** | Non-UTF-8 filenames could produce bundles with invalid JSON paths, or cause verification mismatches across implementations. |
| **Fix** | Before including a file in the manifest, attempt to encode its relative path as UTF-8. Raise an error if encoding fails. |

### 13. CLI allows extra ignore paths during verification beyond what bundle specifies

| Field | Detail |
|-------|--------|
| **Spec Section** | §8.4 (Manifest Verification) |
| **Requirement** | The verifier uses `serialization.ignore_paths` (if present) combined with default exclusions. |
| **Implementation** | `verifying.py:108-112` merges bundle ignore_paths with user-supplied `--ignore-paths`. The CLI (`_cli.py:757-770`) independently passes its own ignore paths. |
| **Impact** | A verifier can hide missing files by specifying additional ignore paths not recorded in the bundle, silently masking unsigned files without using `--ignore-unsigned-files`. |
| **Fix** | During verification, the user-specified ignore paths should be limited to only those recorded in the bundle's `serialization.ignore_paths`, plus the default exclusions. Extra user-specified paths should at minimum trigger a warning. |

### 14. `ignore_paths` uses OS-native separators on Windows

| Field | Detail |
|-------|--------|
| **Spec Section** | §6.2.1 (Matching Semantics) |
| **Requirement** | "Entries MUST use `/` as the path separator." |
| **Implementation** | `manifest.py:326` does `str(p)` on `pathlib.Path` objects. On Windows, `pathlib.Path` uses `\` separators, so `str(p)` produces backslash-separated paths in `ignore_paths`. |
| **Impact** | Bundles produced on Windows contain backslash-separated ignore paths, breaking cross-platform verification. |
| **Fix** | Use `pathlib.PurePosixPath` or explicit `/` conversion when serializing ignore paths. |

---

## Low / Minor Severity

### 15. `shard_size` not rejected when present with `method: "files"`

| Field | Detail |
|-------|--------|
| **Spec Section** | §5.2.2 (Serialization) |
| **Requirement** | `shard_size` "MUST be absent when `method` is `"files"`." |
| **Implementation** | `manifest.py:342-347` (`_FileSerialization._from_args()`) silently ignores extra keys including `shard_size`. |
| **Fix** | Validate that `shard_size` is not present when `method` is `"files"` and raise an error if it is. |

### 16. No validation of ignore path entries for glob characters

| Field | Detail |
|-------|--------|
| **Spec Section** | §6.2.1 (Matching Semantics) |
| **Requirement** | "Ignore path entries MUST NOT contain glob characters (`*`, `?`, `[`), leading `/`, or `../` components." |
| **Implementation** | `_cli.py:168-180` resolves paths (which handles `../` functionally) but never rejects glob characters. A user passing `--ignore-paths '*.bin'` silently succeeds (treated as a literal filename). |
| **Fix** | Validate ignore path entries and reject any containing `*`, `?`, `[`, leading `/`, or `../`. |

### 17. Root digest verification doesn't independently sort resources

| Field | Detail |
|-------|--------|
| **Spec Section** | §6.5.1 (Root Digest Algorithm) |
| **Requirement** | Root digest computed over resources "in canonical order (sorted lexicographically by `name`)." |
| **Implementation** | `signing.py:109-119` iterates resources in JSON array order without sorting. This works only because compliant producers sort, but violates defense-in-depth — a bundle with out-of-order resources would produce an incorrect root digest comparison. |
| **Fix** | Sort resources by `name` before computing the root digest during verification. |

### 18. No JSON Schema validation of produced or verified bundles

| Field | Detail |
|-------|--------|
| **Spec Section** | §3.1 (Schemas) |
| **Requirement** | "Implementations that produce OMS bundles SHOULD validate the output against the bundle schema." |
| **Implementation** | No JSON Schema validation anywhere in the codebase. Individual fields are checked manually. |
| **Fix** | Integrate `jsonschema` validation against `schemas/v1.0/bundle.schema.json` as an optional validation step. |

### 19. Default git ignore paths — trailing slash inconsistency in source

| Field | Detail |
|-------|--------|
| **Spec Section** | §6.2 (Path Exclusion) |
| **Requirement** | Default exclusions are `.git`, `.gitignore`, `.gitattributes`, `.github` (no trailing slashes). |
| **Implementation** | `hashing.py:166-173` constructs `.git/` and `.github/` with trailing slashes. `PurePosixPath` normalizes these in output so the bundle is correct, but the source code is inconsistent with the spec. |
| **Fix** | Remove trailing slashes from the default git path constants for clarity. |

### 20. PAE encoding has subtle space-joining behavior

| Field | Detail |
|-------|--------|
| **Spec Section** | §6.7 (DSSE Signing) |
| **Requirement** | Compute PAE per DSSE-PROTO. |
| **Implementation** | `sign_sigstore_pb.py:62-66` uses `b" ".join(...)` to concatenate the header and payload. Functionally correct and consistent across sign/verify within this implementation, but the join mechanism could theoretically diverge from strict DSSE PAE implementations. |
| **Fix** | Consider using explicit byte concatenation matching the DSSE spec format exactly. Low priority since sign/verify are consistent. |

### 21. Generic error for unknown serialization method

| Field | Detail |
|-------|--------|
| **Spec Section** | §6.3.2 (Shard Serialization) |
| **Requirement** | "A verifier that does not implement shard serialization MUST reject the bundle with an informative error." |
| **Implementation** | `verifying.py:218` raises `ValueError("Cannot guess the hashing configuration")` — not informative about which method is unsupported. |
| **Fix** | Include the unrecognized `method` value in the error message: `f"Unsupported serialization method: '{method}'"`. |

---

## Appendix: Findings by Spec Section

| Spec Section | Finding # | Severity |
|---|---|---|
| §5.2.1 (Resources) | 2 | HIGH |
| §5.2.2 (Serialization) | 7, 8, 15 | HIGH, MEDIUM, LOW |
| §6.1 (File Enumeration) | 2 | HIGH |
| §6.1.1 (Symbolic Links) | 9, 10, 11 | MEDIUM, MEDIUM, MEDIUM |
| §6.1.2 (Path Canonicalization) | 12 | MEDIUM |
| §6.2 (Path Exclusion) | 13, 14, 16, 19 | MEDIUM, MEDIUM, LOW, LOW |
| §6.3.2 (Shard Serialization) | 1, 6, 8, 21 | CRITICAL, HIGH, MEDIUM, LOW |
| §6.5.1 (Root Digest) | 17 | LOW |
| §6.7 (DSSE Signing) | 20 | LOW |
| §7 (Hashing Algorithms) | 4 | HIGH |
| §8.2 (Signature Verification) | 3 | HIGH |
| §8.4/§8.5 (Manifest Verification) | 6, 13 | HIGH, MEDIUM |
| §11.2 (Backward Compatibility) | 5 | HIGH |
| §3.1 (Schemas) | 18 | LOW |

---

## Recommended Fix Priority

**Immediate (security + correctness):**
1. Finding #3 — Expired certificate acceptance (security vulnerability)
2. Finding #5 — rawBytes key verification skipped (security downgrade)
3. Finding #7 — String `"false"` for `allow_symlinks` in compat path (correctness)

**High priority (interoperability + correctness):**
4. Finding #1 — Shard colon parsing (interoperability, spec MUST)
5. Finding #4 — BLAKE2 round-trip (verification failure)
6. Finding #2 — Empty model rejection (spec MUST)
7. Finding #6 — `--ignore-unsigned-files` with shards (broken feature)

**Medium priority (spec compliance):**
8. Finding #9 — Enforce `allow_symlinks` from bundle
9. Finding #10 — Symlink outside root warning
10. Finding #11 — Symlink cycle detection
11. Finding #12 — UTF-8 path validation
12. Finding #13 — Extra ignore paths during verification
13. Finding #14 — Windows path separators
14. Finding #8 — BLAKE3 shard silent downgrade

**Low priority (hardening):**
15. Findings #15–21 — Validation improvements, schema checks, error messages
