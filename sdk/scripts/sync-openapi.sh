#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mkdir -p "$repo_root/sdk/openapi"
cp "$repo_root"/openapi/openapi*.json "$repo_root/sdk/openapi/"
