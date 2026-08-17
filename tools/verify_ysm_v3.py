#!/usr/bin/env python3
"""Regression checks for the current ysm v3 static-analysis landmarks."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze_ysm_v3 import build_report  # noqa: E402

EXPECTED_SHA256 = "5bb1dc65600331fee38e11a1815054a1b14ace93c206ce19521b42abb5560ba1"
EXPECTED_RESOLVER = {
    "0x63e0e0": "il2cpp_assembly_get_image",
    "0x63e0d8": "il2cpp_domain_get",
    "0x63e0d0": "il2cpp_domain_get_assemblies",
    "0x63e0e8": "il2cpp_image_get_name",
    "0x63e110": "il2cpp_class_from_name",
    "0x63e128": "il2cpp_class_get_field_from_name",
    "0x63e140": "il2cpp_class_get_method_from_name",
    "0x63e168": "il2cpp_field_get_offset",
    "0x63e130": "il2cpp_field_static_get_value",
    "0x63e138": "il2cpp_field_static_set_value",
    "0x63e120": "il2cpp_array_new",
    "0x63e170": "il2cpp_string_chars",
    "0x63e0c0": "il2cpp_string_new",
    "0x63e0c8": "il2cpp_string_new_utf16",
    "0x63e160": "il2cpp_type_get_name",
    "0x63e158": "il2cpp_method_get_param",
    "0x63e148": "il2cpp_class_get_methods",
    "0x63e150": "il2cpp_method_get_name",
    "0x63e118": "il2cpp_object_new",
}


def check(binary: Path) -> None:
    report = build_report(binary)
    assert report["sha256"] == EXPECTED_SHA256, (
        f"sample fingerprint mismatch: {report['sha256']}"
    )

    resolver = {row["slot"]: row["name"] for row in report["resolver"]}
    assert resolver == EXPECTED_RESOLVER, "IL2CPP resolver map changed"

    wrappers = report["wrappers"]
    assert len(wrappers["find_class_cached"]["xrefs"]) == 2
    methods = wrappers["resolve_method_pointer"]["xrefs"]
    fields = wrappers["resolve_field_offset"]["xrefs"]
    assert len(methods) == 27, f"expected 27 method xrefs, got {len(methods)}"
    assert len(fields) == 8, f"expected 8 field xrefs, got {len(fields)}"
    assert wrappers["init_il2cpp_api"]["xrefs"] == []

    by_pc = {row["callsite"]: row for row in methods}
    assert by_pc["0x25f944"]["x3"] == "0x537a68", "MOV propagation regressed"
    assert by_pc["0x25f944"]["decoded"]["member"] == "get_HeadCollider"
    assert by_pc["0x25fad8"]["decoded"]["class"] == "HPFKOGPDBBE"
    assert by_pc["0x25fad8"]["decoded"]["member"] == "FOHHPOKDOND"
    assert by_pc["0x26000c"]["decoded"]["member"] == "get_transform"
    assert by_pc["0x2603c0"]["decoded"]["member"] == "get_main"
    assert by_pc["0x260768"]["decoded"]["member"] == "get_IsDieing"
    assert by_pc["0x260b0c"]["decoded"]["member"] == "IsLocalTeammate"

    field_by_pc = {row["callsite"]: row for row in fields}
    assert field_by_pc["0x2615e8"]["decoded"]["member"] == "PDBGEOANOEP"
    assert field_by_pc["0x261768"]["decoded"]["member"] == "MMECELKLHFC"
    assert (
        field_by_pc["0x2619e0"]["decoded"]["member"]
        == "<NNFKGNCILNK>k__BackingField"
    )
    assert len(report["managed_targets"]) == 12


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("binary", type=Path)
    ns = ap.parse_args()
    check(ns.binary)
    print("OK: ysm v3 fingerprint and static-analysis landmarks match")


if __name__ == "__main__":
    main()
