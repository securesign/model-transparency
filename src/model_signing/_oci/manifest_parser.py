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

"""Unified OCI manifest parser for model signing.

Parses OCI manifests from different formats (OCI artifacts, ModelCar) into
a unified model signing manifest. The resulting manifest is interoperable -
the same model produces identical manifests regardless of OCI format.
"""

from __future__ import annotations

import hashlib
import io
import pathlib
import tarfile
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from model_signing import manifest
from model_signing._hashing import hashing
from model_signing._oci.annotations import DEFAULT_MODEL_PATH_PREFIX
from model_signing._oci.annotations import OCI
from model_signing._oci.annotations import OLOT


if TYPE_CHECKING:
    from model_signing._oci.registry import ImageReference


@runtime_checkable
class BlobPuller(Protocol):
    """Protocol for pulling blobs from an OCI registry."""

    def pull_blob(self, image_ref: ImageReference, digest: str) -> bytes:
        """Pull a blob from the registry by digest."""
        ...


def _parse_digest_string(digest_str: str) -> hashing.Digest:
    """Parse a digest string (sha256:abc...) into a Digest object."""
    if ":" in digest_str:
        algorithm, hex_value = digest_str.split(":", 1)
        algorithm = algorithm.lower()
    else:
        algorithm = "sha256"
        hex_value = digest_str

    return hashing.Digest(algorithm, bytes.fromhex(hex_value))


def _is_modelcar_layer(layer: dict) -> bool:
    """Check if a layer has ModelCar annotations."""
    annotations = layer.get("annotations", {})
    return OLOT.content_type in annotations


def _strip_path_prefix(path: str, prefix: str) -> str:
    """Strip a prefix from a path, handling leading slashes."""
    if path.startswith(prefix):
        path = path[len(prefix) :]
    elif path.startswith(prefix.lstrip("/")):
        path = path[len(prefix.lstrip("/")) :]
    return path.lstrip("/")


def _hash_tar_entries(
    blob: bytes, path_prefix: str
) -> list[tuple[str, hashing.Digest]]:
    """Extract and hash files from a tar archive.

    Args:
        blob: The tar archive bytes (may be compressed).
        path_prefix: Prefix to strip from file paths.

    Returns:
        List of (relative_path, digest) tuples for each file in the tar.
    """
    results = []
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as tar:
        for member in tar:
            if not member.isfile():
                continue
            f = tar.extractfile(member)
            if f is None:
                continue
            hasher = hashlib.sha256()
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                hasher.update(chunk)
            rel_path = _strip_path_prefix(member.name, path_prefix)
            if not rel_path:
                continue
            digest = hashing.Digest("sha256", hasher.digest())
            results.append((rel_path, digest))
    return results


def _process_modelcar_layer(
    layer: dict,
    path_prefix: str,
    oci_client: BlobPuller | None,
    image_ref: ImageReference | None,
) -> list[manifest.FileManifestItem]:
    """Process a ModelCar format layer.

    For file layers: uses the content digest annotation.
    For directory layers: decompresses tar and hashes each file.
    """
    annotations = layer.get("annotations", {})
    content_type = annotations.get(OLOT.content_type)
    items = []

    if content_type == "file":
        content_digest = annotations.get(OLOT.content_digest)
        content_path = annotations.get(OLOT.content_path)
        if content_digest and content_path:
            rel_path = _strip_path_prefix(content_path, path_prefix)
            if rel_path:
                digest = _parse_digest_string(content_digest)
                items.append(
                    manifest.FileManifestItem(
                        path=pathlib.PurePosixPath(rel_path), digest=digest
                    )
                )

    elif content_type == "directory":
        if oci_client is None or image_ref is None:
            raise ValueError(
                "OCI client and image reference required for directory layers"
            )
        layer_digest = layer.get("digest")
        if not layer_digest:
            return items
        blob = oci_client.pull_blob(image_ref, layer_digest)
        for rel_path, digest in _hash_tar_entries(blob, path_prefix):
            items.append(
                manifest.FileManifestItem(
                    path=pathlib.PurePosixPath(rel_path), digest=digest
                )
            )

    return items


def _process_oci_artifact_layer(
    layer: dict, layer_index: int
) -> manifest.FileManifestItem | None:
    """Process a standard OCI artifact layer.

    Uses layer digest and title annotation for path.
    """
    if "digest" not in layer:
        return None

    layer_digest = _parse_digest_string(layer["digest"])
    annotations = layer.get("annotations", {})
    title = annotations.get(OCI.image_title)

    if title:
        layer_path = pathlib.PurePosixPath(title)
    else:
        layer_path = pathlib.PurePosixPath(f"layer_{layer_index:03d}.tar.gz")

    return manifest.FileManifestItem(path=layer_path, digest=layer_digest)


def parse_oci_manifest(
    oci_manifest: dict,
    model_name: str | None = None,
    include_config: bool = True,
    oci_client: BlobPuller | None = None,
    image_ref: ImageReference | None = None,
    model_path_prefix: str = DEFAULT_MODEL_PATH_PREFIX,
) -> manifest.Manifest:
    """Parse an OCI manifest into a model signing manifest.

    Automatically detects the format (OCI artifact vs ModelCar) and extracts
    file paths and original content digests. The resulting manifest is
    interoperable with local file hashing.

    Args:
        oci_manifest: The OCI image manifest dictionary.
        model_name: Optional name for the model.
        include_config: Whether to include config blob (for OCI artifacts).
        oci_client: OCI registry client (required for ModelCar directories).
        image_ref: Image reference (required for ModelCar directories).
        model_path_prefix: Prefix to strip from ModelCar paths.

    Returns:
        A model signing Manifest ready for signing or verification.
    """
    if "layers" not in oci_manifest:
        raise ValueError("OCI manifest missing 'layers' field")

    manifest_items: list[manifest.FileManifestItem] = []
    has_modelcar_layers = any(
        _is_modelcar_layer(layer) for layer in oci_manifest["layers"]
    )

    if has_modelcar_layers:
        for layer in oci_manifest["layers"]:
            if not _is_modelcar_layer(layer):
                continue
            items = _process_modelcar_layer(
                layer, model_path_prefix, oci_client, image_ref
            )
            manifest_items.extend(items)
    else:
        layer_paths = set()
        for layer in oci_manifest["layers"]:
            annotations = layer.get("annotations", {})
            title = annotations.get(OCI.image_title)
            if title:
                layer_paths.add(title)

        if include_config and "config" in oci_manifest:
            config = oci_manifest["config"]
            if "digest" in config and "config.json" not in layer_paths:
                config_digest = _parse_digest_string(config["digest"])
                manifest_items.append(
                    manifest.FileManifestItem(
                        path=pathlib.PurePosixPath("config.json"),
                        digest=config_digest,
                    )
                )

        for i, layer in enumerate(oci_manifest["layers"]):
            item = _process_oci_artifact_layer(layer, i)
            if item:
                manifest_items.append(item)

    if not manifest_items:
        raise ValueError("No file entries found in OCI manifest")

    if model_name is None:
        annotations = oci_manifest.get("annotations", {})
        model_name = (
            annotations.get("org.opencontainers.image.name")
            or annotations.get("org.opencontainers.image.base.name")
            or "oci-image"
        )

    serialization_type = manifest._FileSerialization(
        hash_type="sha256", allow_symlinks=False, ignore_paths=frozenset()
    )

    return manifest.Manifest(model_name, manifest_items, serialization_type)
