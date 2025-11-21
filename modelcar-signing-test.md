# ModelCar Format Signing Test

This document demonstrates the ModelCar signing feature, which extracts original file hashes from OLOT annotations for interoperable signing.

## Test Image

```
quay.io/asiek/model-signing-test:modelcar-mixed
quay.io/asiek/model-signing-test@sha256:d7d6543cb9cc797ff034cc5f821bb4ffb67382fc2d45a9a2c61159fe459a9c4e (amd64)
```

## 1. Manifest Parsing

The parser correctly extracts original file hashes from `olot.layer.content.digest` annotations:

```python
from model_signing._oci.registry import OrasClient, ImageReference
from model_signing._oci.manifest_parser import parse_oci_manifest

client = OrasClient()
image_ref = ImageReference.parse('quay.io/asiek/model-signing-test@sha256:d7d6543cb9cc797ff034cc5f821bb4ffb67382fc2d45a9a2c61159fe459a9c4e')
oci_manifest, _ = client.get_manifest(image_ref)
result = parse_oci_manifest(oci_manifest, oci_client=client, image_ref=image_ref)

for rd in sorted(result.resource_descriptors(), key=lambda x: x.identifier):
    print(f'{rd.identifier}: sha256:{rd.digest.digest_hex}')
```

**Output:**
```
README.md: sha256:9a572054d777a1380b67740844abf986e5e077f53e518afbf7dd2193935f4de7
config.json: sha256:002050231a9b1ec3ac77aa6b9b3bbdc4d923f4068a7dd33b8da72a9bd6ad9a43
dir1/file1_in_dir1.md: sha256:1d59358c9b7564ff277ea8caf0db828a7b71a8d78fba42b933fa96f346f3c2f8
dir2/file1_in_dir2.md: sha256:4387f779df16132dd1f20add4f79d19445ca44a88bdfe208192577c4e8df0fdc
model.safetensors: sha256:ebfa4e2f18696ebd83716a0d39fe2c025f2ff8483f72a83ca59c475692fc9d15
special_tokens_map.json: sha256:6f50ab5a5a509a1c309d6171f339b196a900dc9c99ad0408ff23bb615fdae7ad
tokenizer.json: sha256:c24618a1b3e6a38167beff1c72cffd126c3a66254347304b50547d12c5f25624
tokenizer_config.json: sha256:70e38394e494931c6f773ba41e19460dd4436526b852207367f04341b4066d3f
```

**Key observations:**
- File layers use `olot.layer.content.digest` (original file hash), not layer digest
- Directory layers (`dir1`, `dir2`) are decompressed and each file is hashed individually
- `/models/` prefix is stripped from all paths

## 2. Sign the ModelCar Image

```bash
model_signing sign sigstore "quay.io/asiek/model-signing-test@sha256:d7d6543cb9cc797ff034cc5f821bb4ffb67382fc2d45a9a2c61159fe459a9c4e"
```

**Output:**
```
Pushing signature to: quay.io/asiek/model-signing-test@sha256:d7d6543cb9cc797ff034cc5f821bb4ffb67382fc2d45a9a2c61159fe459a9c4e (referrers API)
Waiting for browser interaction...
Signature pushed: sha256:478c71d060272c16ce9a78289db4d24e5b1e3934d24a4581c1241e18d1704a81
```

## 3. Verify the ModelCar Image

```bash
model_signing verify sigstore "quay.io/asiek/model-signing-test@sha256:d7d6543cb9cc797ff034cc5f821bb4ffb67382fc2d45a9a2c61159fe459a9c4e" \
  --identity "asiek@redhat.com" \
  --identity-provider "https://accounts.google.com"
```

**Output:**
```
Verifying: quay.io/asiek/model-signing-test@sha256:d7d6543cb9cc797ff034cc5f821bb4ffb67382fc2d45a9a2c61159fe459a9c4e
Fetching signature from registry...

The following checks were performed:
  - Signature verified against Sigstore bundle
  - Signing identity matched
  - OIDC issuer matched

Verification succeeded
```

## 4. Inspect Signature Referrers

```bash
oras discover quay.io/asiek/model-signing-test@sha256:d7d6543cb9cc797ff034cc5f821bb4ffb67382fc2d45a9a2c61159fe459a9c4e
```

**Output:**
```
quay.io/asiek/model-signing-test@sha256:d7d6543cb9cc797ff034cc5f821bb4ffb67382fc2d45a9a2c61159fe459a9c4e
└── application/vnd.model-signing.signature.v0.1
    └── sha256:478c71d060272c16ce9a78289db4d24e5b1e3934d24a4581c1241e18d1704a81
```

## 5. Inspect the Signed Manifest

```bash
oras copy quay.io/asiek/model-signing-test@sha256:478c71d060272c16ce9a78289db4d24e5b1e3934d24a4581c1241e18d1704a81 \
  --to-oci-layout /tmp/sig-inspect

cat /tmp/sig-inspect/blobs/sha256/fdd3e11c8478961fbbbd1b944db4e5927379e97e56ef64e7d887c57613c4d3e4 \
  | jq '.dsseEnvelope.payload' -r | base64 -d | jq .
```

**Output:**
```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "quay.io/asiek/model-signing-test@sha256:d7d6543cb9cc797ff034cc5f821bb4ffb67382fc2d45a9a2c61159fe459a9c4e",
      "digest": {
        "sha256": "6804120d2d07449efb4d01a6d97c2eb68c871bbd74c689253987d3e803509748"
      }
    }
  ],
  "predicateType": "https://model_signing/signature/v1.0",
  "predicate": {
    "serialization": {
      "method": "files",
      "hash_type": "sha256",
      "allow_symlinks": false
    },
    "resources": [
      {"digest": "9a572054d777a1380b67740844abf986e5e077f53e518afbf7dd2193935f4de7", "algorithm": "sha256", "name": "README.md"},
      {"digest": "002050231a9b1ec3ac77aa6b9b3bbdc4d923f4068a7dd33b8da72a9bd6ad9a43", "algorithm": "sha256", "name": "config.json"},
      {"digest": "1d59358c9b7564ff277ea8caf0db828a7b71a8d78fba42b933fa96f346f3c2f8", "algorithm": "sha256", "name": "dir1/file1_in_dir1.md"},
      {"digest": "4387f779df16132dd1f20add4f79d19445ca44a88bdfe208192577c4e8df0fdc", "algorithm": "sha256", "name": "dir2/file1_in_dir2.md"},
      {"digest": "ebfa4e2f18696ebd83716a0d39fe2c025f2ff8483f72a83ca59c475692fc9d15", "algorithm": "sha256", "name": "model.safetensors"},
      {"digest": "6f50ab5a5a509a1c309d6171f339b196a900dc9c99ad0408ff23bb615fdae7ad", "algorithm": "sha256", "name": "special_tokens_map.json"},
      {"digest": "c24618a1b3e6a38167beff1c72cffd126c3a66254347304b50547d12c5f25624", "algorithm": "sha256", "name": "tokenizer.json"},
      {"digest": "70e38394e494931c6f773ba41e19460dd4436526b852207367f04341b4066d3f", "algorithm": "sha256", "name": "tokenizer_config.json"}
    ]
  }
}
```

## 6. Cross-Format Verification (Interoperability)

Extract files locally and verify using the remote signature:

```bash
# Extract files from ModelCar tar layers
mkdir -p /tmp/local-model
tar -xf /tmp/sig-inspect/blobs/sha256/2543884b77311a4730a8bc8ee84b3223cd92814a9bba340d089b9e2e9d4dd034 -C /tmp/local-model --strip-components=1  # README.md
tar -xf /tmp/sig-inspect/blobs/sha256/a447b1ba0648a4b7cfedb77375738f1a939a8bc1bd5cbf2dcae85af9f07143a4 -C /tmp/local-model --strip-components=1  # config.json
tar -xf /tmp/sig-inspect/blobs/sha256/d45975ee089153843027e8c8db015ca803d3e437f741028e8c165b86b05d6946 -C /tmp/local-model --strip-components=1  # model.safetensors
tar -xf /tmp/sig-inspect/blobs/sha256/c5007759b9b172e5a3eaa773f5856470c8276e7178b183aa0f37d11818dbe68f -C /tmp/local-model --strip-components=1  # special_tokens_map.json
tar -xf /tmp/sig-inspect/blobs/sha256/2beb6287e11fa8b8103b5822f957b5171c77479eb9820a951015d6577379a759 -C /tmp/local-model --strip-components=1  # tokenizer.json
tar -xf /tmp/sig-inspect/blobs/sha256/c81d375a9dc0ccbb171f4b6f64f90eb382d8de7efcd05582508e9a4da996f331 -C /tmp/local-model --strip-components=1  # tokenizer_config.json
tar -xf /tmp/sig-inspect/blobs/sha256/aa1dffb93a8f58f0506c0bf1a2942e156cb190e10bf7077651600cf2db5d0c99 -C /tmp/local-model --strip-components=1  # dir1
tar -xf /tmp/sig-inspect/blobs/sha256/cf72e1a2fc72e1114fe81f83a1cc3862b96d39f008401f17e15e2bbbeab5b459 -C /tmp/local-model --strip-components=1  # dir2

# Verify local hashes match
sha256sum /tmp/local-model/*
```

**Output:**
```
9a572054d777a1380b67740844abf986e5e077f53e518afbf7dd2193935f4de7  README.md
002050231a9b1ec3ac77aa6b9b3bbdc4d923f4068a7dd33b8da72a9bd6ad9a43  config.json
ebfa4e2f18696ebd83716a0d39fe2c025f2ff8483f72a83ca59c475692fc9d15  model.safetensors
6f50ab5a5a509a1c309d6171f339b196a900dc9c99ad0408ff23bb615fdae7ad  special_tokens_map.json
c24618a1b3e6a38167beff1c72cffd126c3a66254347304b50547d12c5f25624  tokenizer.json
70e38394e494931c6f773ba41e19460dd4436526b852207367f04341b4066d3f  tokenizer_config.json
1d59358c9b7564ff277ea8caf0db828a7b71a8d78fba42b933fa96f346f3c2f8  dir1/file1_in_dir1.md
4387f779df16132dd1f20add4f79d19445ca44a88bdfe208192577c4e8df0fdc  dir2/file1_in_dir2.md
```

**Verify local model using the ModelCar signature:**

```bash
# Copy signature bundle locally
cp /tmp/sig-inspect/blobs/sha256/fdd3e11c8478961fbbbd1b944db4e5927379e97e56ef64e7d887c57613c4d3e4 /tmp/local-model/model.sig

# Verify
model_signing verify sigstore /tmp/local-model \
  --signature /tmp/local-model/model.sig \
  --identity "asiek@redhat.com" \
  --identity-provider "https://accounts.google.com"
```

**Output:**
```
Verifying: /tmp/local-model
Signature: /tmp/local-model/model.sig

The following checks were performed:
  - Signature verified against Sigstore bundle
  - Signing identity matched
  - OIDC issuer matched

Verification succeeded
```

## Summary

The ModelCar signing feature enables **interoperable verification**:

This works because the signature captures **original file content hashes**, not OCI layer digests.
