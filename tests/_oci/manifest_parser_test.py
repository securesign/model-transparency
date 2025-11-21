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

"""Tests for OCI manifest parser supporting multiple formats."""

import hashlib
import io
import tarfile

import pytest

from model_signing._oci import manifest_parser
from model_signing._oci.annotations import OCI
from model_signing._oci.annotations import OLOT


DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64
DIGEST_E = "e" * 64


def _get_manifest_items(manifest):
    """Extract items from manifest as {identifier: digest_hex} dict."""
    return {
        rd.identifier: rd.digest.digest_hex
        for rd in manifest.resource_descriptors()
    }


class MockOrasClient:
    """Mock OCI client for testing."""

    def __init__(self):
        self.blobs: dict[str, bytes] = {}

    def pull_blob(self, image_ref, digest: str) -> bytes:
        if digest not in self.blobs:
            raise Exception(f"Blob not found: {digest}")
        return self.blobs[digest]


class TestOCIArtifactParsing:
    """Tests for standard OCI artifact format parsing."""

    def test_parse_simple_oci_artifact(self):
        oci_manifest = {
            "layers": [
                {
                    "digest": f"sha256:{DIGEST_A}",
                    "annotations": {OCI.image_title: "model.safetensors"},
                },
                {
                    "digest": f"sha256:{DIGEST_B}",
                    "annotations": {OCI.image_title: "config.json"},
                },
            ]
        }

        result = manifest_parser.parse_oci_manifest(oci_manifest)

        items = _get_manifest_items(result)
        assert "model.safetensors" in items
        assert items["model.safetensors"] == DIGEST_A
        assert "config.json" in items
        assert items["config.json"] == DIGEST_B

    def test_parse_oci_artifact_without_title(self):
        oci_manifest = {
            "layers": [
                {"digest": f"sha256:{DIGEST_A}"},
                {"digest": f"sha256:{DIGEST_B}"},
            ]
        }

        result = manifest_parser.parse_oci_manifest(oci_manifest)

        items = _get_manifest_items(result)
        assert "layer_000.tar.gz" in items
        assert "layer_001.tar.gz" in items

    def test_parse_oci_artifact_with_config(self):
        oci_manifest = {
            "config": {"digest": f"sha256:{DIGEST_C}"},
            "layers": [
                {
                    "digest": f"sha256:{DIGEST_A}",
                    "annotations": {OCI.image_title: "model.bin"},
                }
            ],
        }

        result = manifest_parser.parse_oci_manifest(oci_manifest)

        items = _get_manifest_items(result)
        assert "config.json" in items
        assert items["config.json"] == DIGEST_C

    def test_parse_oci_artifact_config_conflict(self):
        oci_manifest = {
            "config": {"digest": f"sha256:{DIGEST_C}"},
            "layers": [
                {
                    "digest": f"sha256:{DIGEST_A}",
                    "annotations": {OCI.image_title: "config.json"},
                }
            ],
        }

        result = manifest_parser.parse_oci_manifest(oci_manifest)

        items = _get_manifest_items(result)
        assert items["config.json"] == DIGEST_A
        assert len(items) == 1


class TestModelCarFileParsing:
    """Tests for ModelCar format file layer parsing."""

    def test_parse_modelcar_file_layer(self):
        oci_manifest = {
            "layers": [
                {
                    "digest": f"sha256:{DIGEST_A}",
                    "annotations": {
                        OLOT.content_type: "file",
                        OLOT.content_digest: f"sha256:{DIGEST_B}",
                        OLOT.content_path: "/models/model.safetensors",
                        OLOT.content_name: "model.safetensors",
                    },
                }
            ]
        }

        result = manifest_parser.parse_oci_manifest(oci_manifest)

        items = _get_manifest_items(result)
        assert "model.safetensors" in items
        assert items["model.safetensors"] == DIGEST_B

    def test_parse_modelcar_multiple_files(self):
        oci_manifest = {
            "layers": [
                {
                    "digest": f"sha256:{DIGEST_A}",
                    "annotations": {
                        OLOT.content_type: "file",
                        OLOT.content_digest: f"sha256:{DIGEST_B}",
                        OLOT.content_path: "/models/README.md",
                    },
                },
                {
                    "digest": f"sha256:{DIGEST_C}",
                    "annotations": {
                        OLOT.content_type: "file",
                        OLOT.content_digest: f"sha256:{DIGEST_D}",
                        OLOT.content_path: "/models/config.json",
                    },
                },
                {
                    "digest": f"sha256:{DIGEST_E}",
                    "annotations": {
                        OLOT.content_type: "file",
                        OLOT.content_digest: f"sha256:{'f' * 64}",
                        OLOT.content_path: "/models/model.safetensors",
                    },
                },
            ]
        }

        result = manifest_parser.parse_oci_manifest(oci_manifest)

        items = _get_manifest_items(result)
        assert len(items) == 3
        assert items["README.md"] == DIGEST_B
        assert items["config.json"] == DIGEST_D
        assert items["model.safetensors"] == "f" * 64

    def test_parse_modelcar_nested_path(self):
        oci_manifest = {
            "layers": [
                {
                    "digest": f"sha256:{DIGEST_A}",
                    "annotations": {
                        OLOT.content_type: "file",
                        OLOT.content_digest: f"sha256:{DIGEST_B}",
                        OLOT.content_path: "/models/subdir/nested/file.txt",
                    },
                }
            ]
        }

        result = manifest_parser.parse_oci_manifest(oci_manifest)

        items = _get_manifest_items(result)
        assert "subdir/nested/file.txt" in items

    def test_parse_modelcar_custom_prefix(self):
        oci_manifest = {
            "layers": [
                {
                    "digest": f"sha256:{DIGEST_A}",
                    "annotations": {
                        OLOT.content_type: "file",
                        OLOT.content_digest: f"sha256:{DIGEST_B}",
                        OLOT.content_path: "/custom/prefix/file.txt",
                    },
                }
            ]
        }

        result = manifest_parser.parse_oci_manifest(
            oci_manifest, model_path_prefix="/custom/prefix/"
        )

        items = _get_manifest_items(result)
        assert "file.txt" in items


class TestModelCarDirectoryParsing:
    """Tests for ModelCar format directory layer parsing."""

    @staticmethod
    def _create_tar_blob(files: dict[str, bytes]) -> bytes:
        """Create a tar archive from a dict of {path: content}."""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            for path, content in files.items():
                info = tarfile.TarInfo(name=path)
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
        return buf.getvalue()

    def test_parse_modelcar_directory_layer(self):
        client = MockOrasClient()
        tar_content = self._create_tar_blob(
            {
                "/models/dir1/file1.txt": b"content1",
                "/models/dir1/file2.txt": b"content2",
            }
        )
        tar_digest = f"sha256:{hashlib.sha256(tar_content).hexdigest()}"
        client.blobs[tar_digest] = tar_content

        oci_manifest = {
            "layers": [
                {
                    "digest": tar_digest,
                    "annotations": {
                        OLOT.content_type: "directory",
                        OLOT.content_path: "/models/dir1",
                    },
                }
            ]
        }

        from model_signing._oci.registry import ImageReference

        image_ref = ImageReference.parse("quay.io/test/model:latest")

        result = manifest_parser.parse_oci_manifest(
            oci_manifest, oci_client=client, image_ref=image_ref
        )

        items = _get_manifest_items(result)
        assert "dir1/file1.txt" in items
        assert "dir1/file2.txt" in items
        expected1 = hashlib.sha256(b"content1").hexdigest()
        expected2 = hashlib.sha256(b"content2").hexdigest()
        assert items["dir1/file1.txt"] == expected1
        assert items["dir1/file2.txt"] == expected2

    def test_parse_modelcar_directory_without_client_raises(self):
        oci_manifest = {
            "layers": [
                {
                    "digest": f"sha256:{DIGEST_A}",
                    "annotations": {
                        OLOT.content_type: "directory",
                        OLOT.content_path: "/models/dir1",
                    },
                }
            ]
        }

        with pytest.raises(ValueError, match="OCI client.*required"):
            manifest_parser.parse_oci_manifest(oci_manifest)


class TestMixedFormatParsing:
    """Tests for manifests with mixed layer types."""

    def test_parse_modelcar_mixed_files_and_dirs(self):
        client = MockOrasClient()
        tar_content = TestModelCarDirectoryParsing._create_tar_blob(
            {"/models/dir1/nested.txt": b"nested content"}
        )
        tar_digest = f"sha256:{hashlib.sha256(tar_content).hexdigest()}"
        client.blobs[tar_digest] = tar_content

        oci_manifest = {
            "layers": [
                {
                    "digest": f"sha256:{DIGEST_A}",
                    "annotations": {
                        OLOT.content_type: "file",
                        OLOT.content_digest: f"sha256:{DIGEST_B}",
                        OLOT.content_path: "/models/model.bin",
                    },
                },
                {
                    "digest": tar_digest,
                    "annotations": {
                        OLOT.content_type: "directory",
                        OLOT.content_path: "/models/dir1",
                    },
                },
            ]
        }

        from model_signing._oci.registry import ImageReference

        image_ref = ImageReference.parse("quay.io/test/model:latest")

        result = manifest_parser.parse_oci_manifest(
            oci_manifest, oci_client=client, image_ref=image_ref
        )

        items = _get_manifest_items(result)
        assert "model.bin" in items
        assert items["model.bin"] == DIGEST_B
        assert "dir1/nested.txt" in items

    def test_modelcar_skips_base_image_layers(self):
        oci_manifest = {
            "layers": [
                {
                    "digest": f"sha256:{DIGEST_A}",
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                },
                {
                    "digest": f"sha256:{DIGEST_B}",
                    "annotations": {
                        OLOT.content_type: "file",
                        OLOT.content_digest: f"sha256:{DIGEST_C}",
                        OLOT.content_path: "/models/model.bin",
                    },
                },
            ]
        }

        result = manifest_parser.parse_oci_manifest(oci_manifest)

        items = _get_manifest_items(result)
        assert len(items) == 1
        assert "model.bin" in items


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_missing_layers_raises(self):
        with pytest.raises(ValueError, match="missing 'layers'"):
            manifest_parser.parse_oci_manifest({})

    def test_empty_layers_raises(self):
        with pytest.raises(ValueError, match="No file entries"):
            manifest_parser.parse_oci_manifest({"layers": []})

    def test_modelcar_missing_content_digest_skips(self):
        oci_manifest = {
            "layers": [
                {
                    "digest": f"sha256:{DIGEST_A}",
                    "annotations": {
                        OLOT.content_type: "file",
                        OLOT.content_path: "/models/file.txt",
                    },
                }
            ]
        }

        with pytest.raises(ValueError, match="No file entries"):
            manifest_parser.parse_oci_manifest(oci_manifest)

    def test_model_name_from_annotations(self):
        oci_manifest = {
            "annotations": {"org.opencontainers.image.name": "my-model"},
            "layers": [
                {
                    "digest": f"sha256:{DIGEST_A}",
                    "annotations": {OCI.image_title: "model.bin"},
                }
            ],
        }

        result = manifest_parser.parse_oci_manifest(oci_manifest)
        assert result.model_name == "my-model"

    def test_model_name_fallback(self):
        oci_manifest = {
            "layers": [
                {
                    "digest": f"sha256:{DIGEST_A}",
                    "annotations": {OCI.image_title: "model.bin"},
                }
            ]
        }

        result = manifest_parser.parse_oci_manifest(oci_manifest)
        assert result.model_name == "oci-image"


class TestCompressedTarHandling:
    """Tests for compressed tar archives (gzip)."""

    @staticmethod
    def _create_gzip_tar_blob(files: dict[str, bytes]) -> bytes:
        """Create a gzip-compressed tar archive."""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for path, content in files.items():
                info = tarfile.TarInfo(name=path)
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
        return buf.getvalue()

    def test_parse_gzip_compressed_directory(self):
        client = MockOrasClient()
        tar_content = self._create_gzip_tar_blob(
            {"/models/compressed/file.txt": b"compressed content"}
        )
        tar_digest = f"sha256:{hashlib.sha256(tar_content).hexdigest()}"
        client.blobs[tar_digest] = tar_content

        oci_manifest = {
            "layers": [
                {
                    "digest": tar_digest,
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "annotations": {
                        OLOT.content_type: "directory",
                        OLOT.content_path: "/models/compressed",
                    },
                }
            ]
        }

        from model_signing._oci.registry import ImageReference

        image_ref = ImageReference.parse("quay.io/test/model:latest")

        result = manifest_parser.parse_oci_manifest(
            oci_manifest, oci_client=client, image_ref=image_ref
        )

        items = _get_manifest_items(result)
        assert "compressed/file.txt" in items
        expected = hashlib.sha256(b"compressed content").hexdigest()
        assert items["compressed/file.txt"] == expected


class TestDigestParsing:
    """Tests for digest string parsing edge cases."""

    def test_digest_without_algorithm_prefix(self):
        """Test parsing digest without sha256: prefix (lines 56-57)."""
        oci_manifest = {
            "layers": [
                {
                    "digest": DIGEST_A,  # No sha256: prefix
                    "annotations": {OCI.image_title: "model.bin"},
                }
            ]
        }

        result = manifest_parser.parse_oci_manifest(oci_manifest)

        items = _get_manifest_items(result)
        assert items["model.bin"] == DIGEST_A


class TestPathPrefixStripping:
    """Tests for path prefix stripping edge cases."""

    def test_strip_prefix_without_leading_slash(self):
        """Test stripping prefix when path has no leading slash."""
        client = MockOrasClient()
        # Tar paths without leading slash (like real ModelCar tars)
        tar_content = TestModelCarDirectoryParsing._create_tar_blob(
            {"models/subdir/file.txt": b"content"}
        )
        tar_digest = f"sha256:{hashlib.sha256(tar_content).hexdigest()}"
        client.blobs[tar_digest] = tar_content

        oci_manifest = {
            "layers": [
                {
                    "digest": tar_digest,
                    "annotations": {
                        OLOT.content_type: "directory",
                        OLOT.content_path: "/models/subdir",
                    },
                }
            ]
        }

        from model_signing._oci.registry import ImageReference

        image_ref = ImageReference.parse("quay.io/test/model:latest")

        result = manifest_parser.parse_oci_manifest(
            oci_manifest, oci_client=client, image_ref=image_ref
        )

        items = _get_manifest_items(result)
        assert "subdir/file.txt" in items


class TestTarEdgeCases:
    """Tests for tar archive edge cases."""

    @staticmethod
    def _create_tar_with_directory(files: dict[str, bytes]) -> bytes:
        """Create tar with explicit directory entries (line 93)."""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            # Add directory entry
            dir_info = tarfile.TarInfo(name="models/dir1")
            dir_info.type = tarfile.DIRTYPE
            tar.addfile(dir_info)
            # Add files
            for path, content in files.items():
                info = tarfile.TarInfo(name=path)
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
        return buf.getvalue()

    @staticmethod
    def _create_tar_with_symlink() -> bytes:
        """Create tar with symlink (extractfile returns None, line 96)."""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            # Add a regular file
            info = tarfile.TarInfo(name="models/file.txt")
            content = b"content"
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
            # Add a symlink (extractfile returns None for symlinks)
            link_info = tarfile.TarInfo(name="models/link.txt")
            link_info.type = tarfile.SYMTYPE
            link_info.linkname = "file.txt"
            tar.addfile(link_info)
        return buf.getvalue()

    def test_tar_skips_symlinks(self):
        """Test that symlinks in tar are skipped."""
        client = MockOrasClient()
        tar_content = self._create_tar_with_symlink()
        tar_digest = f"sha256:{hashlib.sha256(tar_content).hexdigest()}"
        client.blobs[tar_digest] = tar_content

        oci_manifest = {
            "layers": [
                {
                    "digest": tar_digest,
                    "annotations": {
                        OLOT.content_type: "directory",
                        OLOT.content_path: "/models",
                    },
                }
            ]
        }

        from model_signing._oci.registry import ImageReference

        image_ref = ImageReference.parse("quay.io/test/model:latest")

        result = manifest_parser.parse_oci_manifest(
            oci_manifest, oci_client=client, image_ref=image_ref
        )

        items = _get_manifest_items(result)
        # Only regular file should be present, not symlink
        assert len(items) == 1
        assert "file.txt" in items
        assert "link.txt" not in items

    def test_tar_skips_unextractable_files(self):
        """Test that files where extractfile returns None are skipped."""
        from unittest.mock import patch

        client = MockOrasClient()
        tar_content = TestModelCarDirectoryParsing._create_tar_blob(
            {"models/file1.txt": b"content1", "models/file2.txt": b"content2"}
        )
        tar_digest = f"sha256:{hashlib.sha256(tar_content).hexdigest()}"
        client.blobs[tar_digest] = tar_content

        oci_manifest = {
            "layers": [
                {
                    "digest": tar_digest,
                    "annotations": {
                        OLOT.content_type: "directory",
                        OLOT.content_path: "/models",
                    },
                }
            ]
        }

        from model_signing._oci.registry import ImageReference

        image_ref = ImageReference.parse("quay.io/test/model:latest")

        # Patch extractfile to return None for file1.txt
        original_open = tarfile.open

        def patched_open(*args, **kwargs):
            tar = original_open(*args, **kwargs)
            original_extractfile = tar.extractfile

            def patched_extractfile(member):
                if "file1" in member.name:
                    return None  # Simulate unextractable file
                return original_extractfile(member)

            tar.extractfile = patched_extractfile
            return tar

        with patch.object(tarfile, "open", patched_open):
            result = manifest_parser.parse_oci_manifest(
                oci_manifest, oci_client=client, image_ref=image_ref
            )

        items = _get_manifest_items(result)
        # Only file2.txt should be present
        assert len(items) == 1
        assert "file2.txt" in items
        assert "file1.txt" not in items

    def test_tar_skips_directory_entries(self):
        """Test that directory entries in tar are skipped (line 93)."""
        client = MockOrasClient()
        tar_content = self._create_tar_with_directory(
            {"models/dir1/file.txt": b"content"}
        )
        tar_digest = f"sha256:{hashlib.sha256(tar_content).hexdigest()}"
        client.blobs[tar_digest] = tar_content

        oci_manifest = {
            "layers": [
                {
                    "digest": tar_digest,
                    "annotations": {
                        OLOT.content_type: "directory",
                        OLOT.content_path: "/models/dir1",
                    },
                }
            ]
        }

        from model_signing._oci.registry import ImageReference

        image_ref = ImageReference.parse("quay.io/test/model:latest")

        result = manifest_parser.parse_oci_manifest(
            oci_manifest, oci_client=client, image_ref=image_ref
        )

        items = _get_manifest_items(result)
        # Only file should be present, not directory
        assert len(items) == 1
        assert "dir1/file.txt" in items

    def test_tar_skips_empty_path_after_strip(self):
        """Test that files with empty path after stripping are skipped."""
        client = MockOrasClient()
        # File at exactly the prefix path
        tar_content = TestModelCarDirectoryParsing._create_tar_blob(
            {"/models/": b"content"}  # Path equals prefix
        )
        tar_digest = f"sha256:{hashlib.sha256(tar_content).hexdigest()}"
        client.blobs[tar_digest] = tar_content

        oci_manifest = {
            "layers": [
                {
                    "digest": tar_digest,
                    "annotations": {
                        OLOT.content_type: "directory",
                        OLOT.content_path: "/models",
                    },
                },
                # Add another layer so we don't get "No file entries" error
                {
                    "digest": f"sha256:{DIGEST_A}",
                    "annotations": {
                        OLOT.content_type: "file",
                        OLOT.content_digest: f"sha256:{DIGEST_B}",
                        OLOT.content_path: "/models/valid.txt",
                    },
                },
            ]
        }

        from model_signing._oci.registry import ImageReference

        image_ref = ImageReference.parse("quay.io/test/model:latest")

        result = manifest_parser.parse_oci_manifest(
            oci_manifest, oci_client=client, image_ref=image_ref
        )

        items = _get_manifest_items(result)
        # Should only have valid.txt, not the empty path entry
        assert "valid.txt" in items


class TestDirectoryLayerEdgeCases:
    """Tests for directory layer edge cases."""

    def test_directory_layer_without_digest(self):
        """Test directory layer without digest returns empty (line 146)."""
        oci_manifest = {
            "layers": [
                {
                    "annotations": {
                        OLOT.content_type: "directory",
                        OLOT.content_path: "/models/dir1",
                    }
                    # No digest field
                },
                # Add a valid layer to avoid "No file entries" error
                {
                    "digest": f"sha256:{DIGEST_A}",
                    "annotations": {
                        OLOT.content_type: "file",
                        OLOT.content_digest: f"sha256:{DIGEST_B}",
                        OLOT.content_path: "/models/file.txt",
                    },
                },
            ]
        }

        from model_signing._oci.registry import ImageReference

        client = MockOrasClient()
        image_ref = ImageReference.parse("quay.io/test/model:latest")

        result = manifest_parser.parse_oci_manifest(
            oci_manifest, oci_client=client, image_ref=image_ref
        )

        items = _get_manifest_items(result)
        # Only the file layer should be present
        assert len(items) == 1
        assert "file.txt" in items


class TestOCIArtifactEdgeCases:
    """Tests for OCI artifact edge cases."""

    def test_oci_layer_without_digest_skipped(self):
        """Test OCI layer without digest is skipped (line 166)."""
        oci_manifest = {
            "layers": [
                {
                    "annotations": {OCI.image_title: "no-digest.bin"}
                    # No digest field
                },
                {
                    "digest": f"sha256:{DIGEST_A}",
                    "annotations": {OCI.image_title: "valid.bin"},
                },
            ]
        }

        result = manifest_parser.parse_oci_manifest(oci_manifest)

        items = _get_manifest_items(result)
        assert len(items) == 1
        assert "valid.bin" in items
        assert "no-digest.bin" not in items
