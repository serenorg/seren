#!/usr/bin/env python3
"""Fail when the committed seren-cloud OpenAPI snapshot has drifted from the
deployed Core for the content-addressed deployment-bundle contract.

The MCP producer tools `register_agent_bundle` / `complete_agent_bundle_upload`
(issue #226) depend on Core keeping the bundle register/complete ops and the
`agent_bundle` source-kind variant stable. This comparator extracts the same
contract subset the in-repo Rust guard pins (`sdk/tests/deployment_bundle_contract.rs`)
from both the committed snapshot and a reference spec fetched from the deployed
Core, and exits non-zero when they diverge — turning "snapshot behind Core" into a
red build here rather than a silently broken tool in production.

Usage:
    check_bundle_contract_drift.py --committed <path> --reference <path>

The extractor is path-prefix- and enum-order-agnostic: it locates ops by
operationId and schemas by name, so it works whether the reference is a per-service
spec (relative paths) or the merged Core spec (absolute paths).
"""

from __future__ import annotations

import argparse
import json
import sys


def bundle_contract(spec: dict) -> dict:
    """Normalized subset of the bundle producer contract. Keep in lockstep with
    `bundle_contract` in sdk/tests/deployment_bundle_contract.rs."""
    schemas = spec.get("components", {}).get("schemas", {})
    ops: dict[str, dict] = {}
    for _path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for _method, op in item.items():
            if isinstance(op, dict) and "operationId" in op:
                ops[op["operationId"]] = op

    contract: dict = {}
    create = ops.get("seren_cloud_create_deployment_bundle")
    contract["create_present"] = create is not None
    if create is not None:
        ref = (
            create.get("requestBody", {})
            .get("content", {})
            .get("application/json", {})
            .get("schema", {})
            .get("$ref", "")
        )
        contract["create_request_schema"] = ref.rsplit("/", 1)[-1]
    contract["complete_present"] = (
        "seren_cloud_complete_deployment_bundle_upload" in ops
    )

    required = schemas.get("CreateCloudDeploymentBundleRequest", {}).get("required")
    contract["create_request_required"] = (
        sorted(required) if isinstance(required, list) else required
    )
    enum = schemas.get("CloudDeploymentBundleSourceKind", {}).get("enum")
    contract["source_kind_enum"] = sorted(enum) if isinstance(enum, list) else enum
    return contract


def load(path: str) -> dict:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--committed", required=True, help="committed snapshot path")
    parser.add_argument("--reference", required=True, help="deployed Core spec path")
    args = parser.parse_args()

    committed = bundle_contract(load(args.committed))
    reference = bundle_contract(load(args.reference))

    if committed == reference:
        print("OK: committed seren-cloud bundle contract matches deployed Core.")
        return 0

    print(
        "DRIFT: the committed seren-cloud snapshot has diverged from the deployed "
        "Core for the deployment-bundle producer contract.",
        file=sys.stderr,
    )
    print(f"  committed: {json.dumps(committed, sort_keys=True)}", file=sys.stderr)
    print(f"  deployed : {json.dumps(reference, sort_keys=True)}", file=sys.stderr)
    print(
        "  Re-sync sdk/openapi/openapi-seren-cloud.json from Core and reconcile the "
        "register_agent_bundle / complete_agent_bundle_upload tools.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
