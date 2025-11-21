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

"""OCI layer annotation constants for model signing.

Defines annotation keys used to extract file metadata from OCI manifests.
Supports both standard OCI artifacts and ModelCar format images.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class OLOTAnnotations:
    """OLOT (OCI Layers On Tar) annotations for ModelCar format."""

    content_digest: str = "olot.layer.content.digest"
    content_type: str = "olot.layer.content.type"
    content_path: str = "olot.layer.content.inlayerpath"
    content_name: str = "olot.layer.content.name"


@dataclass(frozen=True)
class OCIAnnotations:
    """Standard OCI image annotations."""

    image_title: str = "org.opencontainers.image.title"


OLOT = OLOTAnnotations()
OCI = OCIAnnotations()

DEFAULT_MODEL_PATH_PREFIX = "/models/"
