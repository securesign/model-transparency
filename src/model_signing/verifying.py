# Copyright 2024 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""High level API for the verification interface of `model_signing` library.

This module supports configuring the verification method used to verify a model,
before performing the verification.

```python
model_signing.verifying.Config().use_sigstore_verifier(
    identity=identity, oidc_issuer=oidc_provider
).verify("finbert", "finbert.sig")
```

The same verification configuration can be used to verify multiple models:

```python
verifying_config = model_signing.verifying.Config().use_elliptic_key_verifier(
    public_key="key.pub"
)

for model in all_models:
    verifying_config.verify(model, f"{model}_sharded.sig")
```

## OCI Image Verification

The module supports verifying OCI container images signed in registries.

**Note:** OCI image verification currently supports Sigstore and elliptic key
verification only. Certificate-based verification is not yet supported.

```python
# Verify a Sigstore-signed image
model_signing.verifying.Config().use_sigstore_verifier(
    identity="user@example.com", oidc_issuer="https://accounts.google.com"
).verify_image("quay.io/user/model:latest")

# Verify a key-signed image
model_signing.verifying.Config().use_elliptic_key_verifier(
    public_key="key.pub"
).verify_image("quay.io/user/model:latest")

# Verify image AND check that local files match the signed layers
model_signing.verifying.Config().use_sigstore_verifier(
    identity="user@example.com", oidc_issuer="https://accounts.google.com"
).verify_image(
    "quay.io/user/model:latest", local_model_path="./downloaded-model"
)
```

Registry authentication uses existing Docker/Podman credentials from
`~/.docker/config.json` or `${XDG_RUNTIME_DIR}/containers/auth.json`.

The API defined here is stable and backwards compatible.
"""

from collections.abc import Iterable
import hashlib
import json
import pathlib
import sys

from model_signing import hashing
from model_signing import manifest
from model_signing._hashing import hashing as _hashing
from model_signing._oci import attachment as oci_attachment
from model_signing._oci import registry as oci_registry
from model_signing._signing import sign_certificate as certificate
from model_signing._signing import sign_ec_key as ec_key
from model_signing._signing import sign_sigstore as sigstore
from model_signing._signing import sign_sigstore_pb as sigstore_pb


if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


def _format_verification_error(
    missing: list[str], extra: list[str], mismatched: list[tuple[str, str, str]]
) -> str:
    """Format verification errors into a readable message.

    Args:
        missing: List of missing file paths.
        extra: List of extra file paths not in signature.
        mismatched: List of (path, expected_hash, actual_hash) tuples.

    Returns:
        Formatted error message.
    """
    sections = []

    if missing:
        items = [f"    {f}" for f in missing[:5]]
        if len(missing) > 5:
            items.append(f"    ... and {len(missing) - 5} more")
        header = f"  Missing files ({len(missing)}):"
        sections.append(header + "\n" + "\n".join(items))

    if extra:
        items = [f"    {f}" for f in extra[:5]]
        if len(extra) > 5:
            items.append(f"    ... and {len(extra) - 5} more")
        header = f"  Extra files ({len(extra)}):"
        sections.append(header + "\n" + "\n".join(items))

    if mismatched:
        items = []
        for path, expected, actual in mismatched[:5]:
            exp = expected[:16] + "..." if len(expected) > 16 else expected
            act = actual[:16] + "..." if len(actual) > 16 else actual
            items.append(f"    {path}: expected {exp}, got {act}")
        if len(mismatched) > 5:
            items.append(f"    ... and {len(mismatched) - 5} more")
        sections.append(
            f"  Hash mismatches ({len(mismatched)}):\n" + "\n".join(items)
        )

    return "\n".join(sections)


class Config:
    """Configuration to use when verifying models against signatures.

    The verification configuration is needed to determine how to read and verify
    the signature. Given we support multiple signing format, the verification
    settings must match the signing ones.

    The configuration also supports configuring the hashing configuration from
    `model_signing.hashing`. This should also match the configuration used
    during signing. However, by default, we can attempt to guess it from the
    signature.
    """

    def __init__(self):
        """Initializes the default configuration for verification."""
        self._hashing_config = None
        self._verifier = None
        self._uses_sigstore = False
        self._ignore_unsigned_files = False

    def verify(
        self, model_path: hashing.PathLike, signature_path: hashing.PathLike
    ):
        """Verifies that a model conforms to a signature.

        This method can verify signatures created from either:
        - Local files (normal verification)
        - Model manifests

        Args:
            model_path: The path to the model to verify.
            signature_path: The path to the signature file.

        Raises:
            ValueError: No verifier has been configured.
        """
        if self._verifier is None:
            raise ValueError("Attempting to verify with no configured verifier")

        if self._uses_sigstore:
            signature = sigstore.Signature.read(pathlib.Path(signature_path))
        else:
            signature = sigstore_pb.Signature.read(pathlib.Path(signature_path))

        expected_manifest = self._verifier.verify(signature)

        if self._hashing_config is None:
            self._guess_hashing_config(expected_manifest)
        if "ignore_paths" in expected_manifest.serialization_type:
            self._hashing_config.add_ignored_paths(
                model_path=model_path,
                paths=expected_manifest.serialization_type["ignore_paths"],
            )

        if self._ignore_unsigned_files:
            files_to_hash = [
                model_path / rd.identifier
                for rd in expected_manifest.resource_descriptors()
            ]
        else:
            files_to_hash = None

        actual_manifest = self._hashing_config.hash(
            model_path, files_to_hash=files_to_hash
        )

        if actual_manifest != expected_manifest:
            raise ValueError(
                self._get_manifest_diff(actual_manifest, expected_manifest)
            )

    _GIT_PATHS = frozenset([".git", ".gitattributes", ".github", ".gitignore"])

    def _verify_oci_layers_from_files(
        self,
        model_path: hashing.PathLike,
        expected_manifest: manifest.Manifest,
        ignore_git_paths: bool = True,
    ):
        """Verify local files match the signed model signing manifest.

        This compares local files against the model signing manifest extracted
        from the signature bundle. For ORAS-style artifacts where layers have
        file path annotations (org.opencontainers.image.title), it matches
        files by path and compares their SHA256 digests.

        Args:
            model_path: Path to local model directory containing files to verify
            expected_manifest: The model signing manifest extracted from the
                signature bundle, containing expected file paths and digests
            ignore_git_paths: Whether to ignore git-related files when checking
                for extra files (default True)

        Raises:
            ValueError: If local files don't match the expected digests
        """
        model_path = pathlib.Path(model_path)

        # Check if this is an ORAS-style manifest with file paths in
        # identifiers (not generic layer_*.tar.gz names)
        has_file_paths = False
        expected_file_digests = {}

        for rd in expected_manifest.resource_descriptors():
            identifier = str(rd.identifier)
            is_generic_layer = identifier.startswith(
                "layer_"
            ) and identifier.endswith(".tar.gz")
            if not is_generic_layer:
                has_file_paths = True
                expected_file_digests[identifier] = rd.digest

        if has_file_paths:
            return self._verify_oci_files_by_path(
                model_path, expected_file_digests, ignore_git_paths
            )
        else:
            print(
                "Verification failed: The signature bundle does not contain"
                "file path information."
                "Verification must be performed on an ORAS-style artifact.",
                file=sys.stderr,
            )
            sys.exit(1)

    def _is_git_path(self, rel_path_str: str) -> bool:
        """Check if a path is git-related."""
        parts = pathlib.PurePosixPath(rel_path_str).parts
        return any(p in self._GIT_PATHS or p.startswith(".git") for p in parts)

    def _verify_oci_files_by_path(
        self,
        model_path: pathlib.Path,
        expected_file_digests: dict[str, _hashing.Digest],
        ignore_git_paths: bool = True,
    ):
        """Verify local files match expected digests from signature bundle."""
        missing_files = []
        mismatched_files = []
        extra_files = []
        verified_files = []

        normalized_digests = {
            p.replace("\\", "/"): d for p, d in expected_file_digests.items()
        }

        for file_path_str, expected_digest in normalized_digests.items():
            path_parts = pathlib.PurePosixPath(file_path_str).parts
            local_file_path = model_path.joinpath(*path_parts)

            if not local_file_path.exists():
                missing_files.append(file_path_str)
                continue

            if not local_file_path.is_file():
                continue

            with open(local_file_path, "rb") as f:
                file_content = f.read()
                file_digest_value = hashlib.sha256(file_content).digest()
                file_digest = _hashing.Digest("sha256", file_digest_value)

            if file_digest == expected_digest:
                verified_files.append(file_path_str)
            else:
                mismatched_files.append(
                    (
                        file_path_str,
                        expected_digest.digest_hex,
                        file_digest.digest_hex,
                    )
                )

        expected_paths = set(normalized_digests.keys())
        for local_file in model_path.rglob("*"):
            if not local_file.is_file():
                continue
            rel_path = local_file.relative_to(model_path)
            rel_path_str = str(rel_path).replace("\\", "/")

            if ignore_git_paths and self._is_git_path(rel_path_str):
                continue

            if rel_path_str not in expected_paths:
                extra_files.append(rel_path_str)

        if missing_files or mismatched_files or extra_files:
            raise ValueError(
                _format_verification_error(
                    missing=missing_files,
                    extra=sorted(extra_files),
                    mismatched=mismatched_files,
                )
            )

    def verify_image(
        self,
        image_ref: str | oci_registry.ImageReference,
        local_model_path: hashing.PathLike | None = None,
        attachment_mode: str | None = None,
        ignore_git_paths: bool = True,
    ) -> None:
        """Verify an OCI image signature from the registry.

        Verification performs the following steps:

        1. Fetch the signature bundle from the registry (attached to the image
           via tag or referrers API)
        2. Cryptographically verify the signature bundle and extract the
           expected model signing manifest (list of file/layer digests)
        3. Fetch the OCI image manifest from the registry (the actual artifact)
        4. Convert the OCI image manifest layers into a model signing manifest
        5. Compare the expected vs actual model signing manifests
        6. Optionally verify local files match the signed digests

        Note:
            OCI image verification currently supports Sigstore and elliptic key
            verification only. Use `use_sigstore_verifier()` or
            `use_elliptic_key_verifier()` before calling this method.
            Certificate-based verification is not yet supported for images.

        Args:
            image_ref: OCI image reference as a string (e.g.,
              "quay.io/user/model:latest") or a parsed ImageReference object.
            local_model_path: Optional path to local model files. If provided,
              verification will also check that local files match the signed
              layer digests (for ORAS-style images with file path annotations).
            attachment_mode: Optional attachment mode to use for fetching the
              signature. If None (default), tries both referrers and tag-based.
              Use "tag" to force tag-based fetching when multiple signatures
              exist (e.g., when verifying key-based signatures alongside
              Sigstore signatures).
            ignore_git_paths: Whether to ignore git-related files (.git/,
              .gitattributes, .gitignore, .github/) when checking for extra
              files in local_model_path. Default is True.

        Raises:
            ValueError: If no verifier configured, signature not found, or
              verification fails.
        """
        if self._verifier is None:
            raise ValueError("Attempting to verify with no configured verifier")

        if isinstance(image_ref, oci_registry.ImageReference):
            parsed_ref = image_ref
        else:
            parsed_ref = oci_registry.ImageReference.parse(image_ref)

        client = oci_registry.OrasClient()

        image_digest = client.resolve_digest(parsed_ref)
        sig_type = "sigstore" if self._uses_sigstore else "key"

        if attachment_mode == "tag":
            tag_strategy = oci_attachment.TagAttachment()
            signature_bytes = tag_strategy.fetch(
                client, parsed_ref, image_digest, sig_type
            )
            if signature_bytes is None:
                raise ValueError(
                    f"No tag-based signature found for image {image_ref}. "
                    "Ensure the image was signed with --attachment-mode tag."
                )
        elif attachment_mode == "referrers":
            ref_strategy = oci_attachment.ReferrersAttachment()
            signature_bytes = ref_strategy.fetch(
                client, parsed_ref, image_digest, sig_type
            )
            if signature_bytes is None:
                raise ValueError(
                    f"No referrers-based signature for image {image_ref}. "
                    "Ensure the image was signed with referrers attachment."
                )
        else:
            result = oci_attachment.try_fetch_signature(
                client, parsed_ref, image_digest, sig_type
            )
            if result is None:
                raise ValueError(
                    f"No signature found for image {image_ref}. "
                    "Ensure the image has been signed and the signature is "
                    "attached to the registry."
                )
            signature_bytes, _ = result

        try:
            signature_json = signature_bytes.decode("utf-8")
        except UnicodeDecodeError as e:
            raise ValueError(
                f"Failed to decode signature for image {image_ref}: "
                f"signature data is not valid UTF-8. {e}"
            ) from e

        if self._uses_sigstore:
            from sigstore import models as sigstore_models

            try:
                bundle = sigstore_models.Bundle.from_json(signature_json)
                signature = sigstore.Signature(bundle)
            except json.JSONDecodeError as e:
                raise ValueError(
                    f"Failed to parse Sigstore signature for {image_ref}: "
                    f"invalid JSON. {e}"
                ) from e
            except Exception as e:
                raise ValueError(
                    f"Failed to decode Sigstore signature for {image_ref}: "
                    f"{type(e).__name__}: {e}"
                ) from e
        else:
            from sigstore_models.bundle import v1 as bundle_pb

            try:
                parsed_dict = json.loads(signature_json)
                signature = sigstore_pb.Signature(
                    bundle_pb.Bundle.from_dict(parsed_dict)
                )
            except json.JSONDecodeError as e:
                raise ValueError(
                    f"Failed to parse signature for image {image_ref}: "
                    f"invalid JSON. {e}"
                ) from e
            except Exception as e:
                raise ValueError(
                    f"Failed to decode signature for image {image_ref}: "
                    f"{type(e).__name__}: {e}"
                ) from e

        expected_manifest = self._verifier.verify(signature)

        ref_with_digest = parsed_ref.with_digest(image_digest)
        oci_manifest, _ = client.get_manifest(ref_with_digest)

        actual_manifest = hashing.create_manifest_from_oci_layers(
            oci_manifest, model_name=str(parsed_ref)
        )

        if actual_manifest != expected_manifest:
            raise ValueError(
                self._get_manifest_diff(actual_manifest, expected_manifest)
            )

        if local_model_path is not None:
            self._verify_oci_layers_from_files(
                local_model_path, expected_manifest, ignore_git_paths
            )

    def _get_manifest_diff(self, actual, expected) -> str:
        actual_hashes = {
            rd.identifier: rd.digest for rd in actual.resource_descriptors()
        }
        expected_hashes = {
            rd.identifier: rd.digest for rd in expected.resource_descriptors()
        }

        extra = sorted(set(actual_hashes.keys()) - set(expected_hashes.keys()))
        missing = sorted(
            set(expected_hashes.keys()) - set(actual_hashes.keys())
        )

        mismatched = []
        for identifier in sorted(
            set(actual_hashes.keys()) & set(expected_hashes.keys())
        ):
            if actual_hashes[identifier] != expected_hashes[identifier]:
                mismatched.append(
                    (
                        str(identifier),
                        str(expected_hashes[identifier]),
                        str(actual_hashes[identifier]),
                    )
                )

        return _format_verification_error(
            missing=[str(m) for m in missing],
            extra=[str(e) for e in extra],
            mismatched=mismatched,
        )

    def set_hashing_config(self, hashing_config: hashing.Config) -> Self:
        """Sets the new configuration for hashing models.

        After calling this method, the automatic guessing of the hashing
        configuration used during signing is no longer possible from within one
        instance of this class.

        Args:
            hashing_config: The new hashing configuration.

        Returns:
            The new signing configuration.
        """
        self._hashing_config = hashing_config
        return self

    def set_ignore_unsigned_files(self, ignore_unsigned_files: bool) -> Self:
        """Sets whether files that were not signed are to be ignored.

        This method allows to ignore those files that are not part of the
        manifest and therefor were not originally signed.

        Args:
            ignore_unsigned_files: whether to ignore unsigned files
        """
        self._ignore_unsigned_files = ignore_unsigned_files
        return self

    def _guess_hashing_config(self, source_manifest: manifest.Manifest) -> None:
        """Attempts to guess the hashing config from a manifest."""
        args = source_manifest.serialization_type
        method = args["method"]
        match method:
            case "files":
                self._hashing_config = hashing.Config().use_file_serialization(
                    hashing_algorithm=args["hash_type"],
                    allow_symlinks=args["allow_symlinks"],
                    ignore_paths=args.get("ignore_paths", frozenset()),
                )
            case "shards":
                self._hashing_config = hashing.Config().use_shard_serialization(
                    hashing_algorithm=args["hash_type"],
                    shard_size=args["shard_size"],
                    allow_symlinks=args["allow_symlinks"],
                    ignore_paths=args.get("ignore_paths", frozenset()),
                )
            case _:
                raise ValueError("Cannot guess the hashing configuration")

    def use_sigstore_verifier(
        self,
        *,
        identity: str,
        oidc_issuer: str,
        use_staging: bool = False,
        trust_config: pathlib.Path | None = None,
    ) -> Self:
        """Configures the verification of signatures produced by Sigstore.

        The verifier in this configuration is changed to one that performs
        verification of Sigstore signatures (sigstore bundles signed by
        keyless signing via Sigstore).

        Args:
            identity: The expected identity that has signed the model.
            oidc_issuer: The expected OpenID Connect issuer that provided the
              certificate used for the signature.
            use_staging: Use staging configurations, instead of production. This
              is supposed to be set to True only when testing. Default is False.
            trust_config: A path to a custom trust configuration. When provided,
              the signature verification process will rely on the supplied
              PKI and trust configurations, instead of the default Sigstore
              setup. If not specified, the default Sigstore configuration
              is used.

        Return:
            The new verification configuration.
        """
        self._uses_sigstore = True
        self._verifier = sigstore.Verifier(
            identity=identity,
            oidc_issuer=oidc_issuer,
            use_staging=use_staging,
            trust_config=trust_config,
        )
        return self

    def use_elliptic_key_verifier(
        self, *, public_key: hashing.PathLike
    ) -> Self:
        """Configures the verification of signatures generated by a private key.

        The verifier in this configuration is changed to one that performs
        verification of sgistore bundles signed by an elliptic curve private
        key. The public key used in the configuration must match the private key
        used during signing.

        Args:
            public_key: The path to the public key to verify with.

        Return:
            The new verification configuration.
        """
        self._uses_sigstore = False
        self._verifier = ec_key.Verifier(pathlib.Path(public_key))
        return self

    def use_certificate_verifier(
        self,
        *,
        certificate_chain: Iterable[hashing.PathLike] = frozenset(),
        log_fingerprints: bool = False,
    ) -> Self:
        """Configures the verification of signatures generated by a certificate.

        The verifier in this configuration is changed to one that performs
        verification of sgistore bundles signed by a signing certificate.

        Args:
            certificate_chain: Certificate chain to establish root of trust. If
              empty, the operating system's one is used.
            log_fingerprints: Log certificates' SHA256 fingerprints

        Return:
            The new verification configuration.
        """
        self._uses_sigstore = False
        self._verifier = certificate.Verifier(
            [pathlib.Path(c) for c in certificate_chain],
            log_fingerprints=log_fingerprints,
        )
        return self
