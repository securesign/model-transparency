#!/bin/bash

# Usage: ./generate-trust-config.sh <trusted_root_input.json> <output.json> [caUrl] [oidcUrl] [tlogUrl] [tsaUrl]
#
# Creates a Sigstore client trust configuration by wrapping a trusted root
# with signing configuration. URLs can be provided via CLI args or environment variables.
#
# Environment variables (used as fallbacks):
#   CA_URL    - Certificate Authority URL (default: fulcio)
#   OIDC_URL  - OIDC provider URL (default: oauth)
#   TLOG_URL  - Rekor transparency log URL (default: rekor)
#   TSA_URL   - Timestamp Authority base URL (default: https://timestamp.example.com)
#
# Getting URLs from Trusted Artifact Signer (OpenShift):
#   export CA_URL=$(oc get fulcio -o jsonpath='{.items[0].status.url}' -n trusted-artifact-signer)
#   export TLOG_URL=$(oc get rekor -o jsonpath='{.items[0].status.url}' -n trusted-artifact-signer)
#   export TSA_URL=$(oc get timestampauthorities -o jsonpath='{.items[0].status.url}' -n trusted-artifact-signer)
#   export OIDC_URL="<your-oidc-issuer-url>"

set -euo pipefail

show_usage() {
    echo "Usage: $0 <trusted_root_input.json> <output.json> [caUrl] [oidcUrl] [tlogUrl] [tsaUrl]"
    echo ""
    echo "Arguments:"
    echo "  trusted_root_input.json  - Input trusted root JSON file"
    echo "  output.json              - Output client trust config file"
    echo "  caUrl                    - Certificate Authority URL (optional)"
    echo "  oidcUrl                  - OIDC provider URL (optional)"
    echo "  tlogUrl                  - Transparency log URL (optional)"
    echo "  tsaUrl                   - Timestamp Authority base URL (optional, /api/v1/timestamp appended)"
    echo ""
    echo "URLs can also be set via environment variables: CA_URL, OIDC_URL, TLOG_URL, TSA_URL"
}

if [ "$#" -lt 2 ] || [ "$#" -gt 6 ]; then
    show_usage
    if [ "$#" -gt 6 ]; then
        echo ""
        echo "Error: Too many arguments."
    fi
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo "Error: 'jq' is required but not installed."
    exit 1
fi

INPUT_FILE="$1"
OUTPUT_FILE="$2"
CA_URL="${3:-${CA_URL:-fulcio}}"
OIDC_URL="${4:-${OIDC_URL:-oauth}}"
TLOG_URL="${5:-${TLOG_URL:-rekor}}"
TSA_URL_BASE="${6:-${TSA_URL:-https://timestamp.example.com}}"
TSA_URL="${TSA_URL_BASE%/}/api/v1/timestamp"

if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: Input file '$INPUT_FILE' not found."
    exit 1
fi

# Transform checkpointKeyId to logId in the trusted root
# If 'checkpointKeyId' exists, rename it to 'logId'; otherwise leave as-is (1.3 trust root issue)
transform_checkpoint() {
    jq 'walk(if type == "object" and has("checkpointKeyId") then
        .logId = .checkpointKeyId | del(.checkpointKeyId)
    else . end)'
}

jq -n \
  --argjson trustedRoot "$(transform_checkpoint < "$INPUT_FILE")" \
  --arg caUrl "$CA_URL" \
  --arg oidcUrl "$OIDC_URL" \
  --arg tlogUrl "$TLOG_URL" \
  --arg tsaUrl "$TSA_URL" \
  '{
    mediaType: "application/vnd.dev.sigstore.clienttrustconfig.v0.1+json",
    trustedRoot: $trustedRoot,
    signingConfig: {
      mediaType: "application/vnd.dev.sigstore.signingconfig.v0.2+json",
      caUrls: [{
        url: $caUrl,
        majorApiVersion: 1,
        validFor: { start: "2023-04-14T21:38:40Z" },
        operator: "example.com"
      }],
      oidcUrls: [{
        url: $oidcUrl,
        majorApiVersion: 1,
        validFor: { start: "2025-04-16T00:00:00Z" },
        operator: "example.com"
      }],
      rekorTlogUrls: [{
        url: $tlogUrl,
        majorApiVersion: 1,
        validFor: { start: "2021-01-12T11:53:27Z" },
        operator: "example.com"
      }],
      tsaUrls: [{
        url: $tsaUrl,
        majorApiVersion: 1,
        validFor: { start: "2025-04-09T00:00:00Z" },
        operator: "example.com"
      }],
      rekorTlogConfig: { selector: "ANY" },
      tsaConfig: { selector: "ANY" }
    }
  }' > "$OUTPUT_FILE"

echo "Configuration written to $OUTPUT_FILE"
