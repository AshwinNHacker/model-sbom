"""
cli.py
======
Command-line entry point: `msbom`.

The Python builder API (`msbom.builder.SBOMBuilder`) is how you *generate*
an SBOM as part of a training pipeline. This CLI operates on already-saved
SBOM JSON files: validating them, diffing two versions, exporting to other
formats, rendering lineage, and verifying checksums against artifacts on
disk.

Examples
--------
  msbom validate sbom.json
  msbom validate sbom.json --schema
  msbom summary sbom.json
  msbom lineage sbom.json --component adapter-abc123
  msbom diff old_sbom.json new_sbom.json
  msbom export sbom.json --format mermaid --out lineage.mmd
  msbom export sbom.json --format cyclonedx --out sbom.cdx.json
  msbom verify sbom.json --component-id basemodel-xyz --path ./weights/
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import io as msbom_io
from .diff import diff_sboms
from .exporters import to_cyclonedx, to_dot, to_mermaid
from .hashing import verify_checksum
from .lineage import LineageGraph
from .validator import validate, validate_schema


def _cmd_validate(args: argparse.Namespace) -> int:
    sbom = msbom_io.load(args.path)
    report = validate(sbom)
    if args.schema:
        schema_report = validate_schema(sbom.as_dict())
        report.issues.extend(schema_report.issues)

    print(report if report.issues else "No issues found.")
    print()
    print(f"{len(report.errors)} error(s), {len(report.warnings)} warning(s)")
    return 1 if not report.is_valid else 0


def _cmd_summary(args: argparse.Namespace) -> int:
    sbom = msbom_io.load(args.path)
    print(f"ModelSBOM {sbom.bom_format} v{sbom.spec_version}  (doc version {sbom.version})")
    print(f"Serial: {sbom.serial_number}")
    print(f"Organization: {sbom.metadata.organization or '(none)'}")
    print(f"Generated: {sbom.metadata.timestamp}")
    print()
    by_type: dict[str, int] = {}
    for c in sbom.components:
        by_type[c.type.value] = by_type.get(c.type.value, 0) + 1
    print("Components:")
    for t, n in sorted(by_type.items()):
        print(f"  {t:<15} {n}")
    print(f"Relationships: {len(sbom.relationships)}")
    return 0


def _cmd_lineage(args: argparse.Namespace) -> int:
    sbom = msbom_io.load(args.path)
    graph = LineageGraph(sbom)
    comp = sbom.get_component(args.component)
    if not comp:
        print(f"error: no component with id '{args.component}' in {args.path}", file=sys.stderr)
        return 1

    print(f"Lineage for {comp.name} (v{comp.version}) [{comp.type.value}] — id={comp.id}")
    print()
    ancestors = graph.ancestors(comp.id)
    print(f"Ancestors ({len(ancestors)}) — everything this was built from:")
    for aid in sorted(ancestors):
        a = sbom.get_component(aid)
        label = f"{a.name} v{a.version} [{a.type.value}]" if a else aid
        print(f"  - {label}")

    print()
    descendants = graph.descendants(comp.id)
    print(f"Descendants ({len(descendants)}) — everything (transitively) built from this:")
    for did in sorted(descendants):
        d = sbom.get_component(did)
        label = f"{d.name} v{d.version} [{d.type.value}]" if d else did
        print(f"  - {label}")
    return 0


def _cmd_diff(args: argparse.Namespace) -> int:
    old = msbom_io.load(args.old_path)
    new = msbom_io.load(args.new_path)
    d = diff_sboms(old, new)
    print(d.summary())
    if args.verbose:
        print()
        for c in d.added_components:
            print(f"  + added:   {c.name} v{c.version} [{c.type.value}] ({c.id})")
        for c in d.removed_components:
            print(f"  - removed: {c.name} v{c.version} [{c.type.value}] ({c.id})")
        for change in d.changed_components:
            marker = "⚠" if change.checksum_changed else "~"
            print(f"  {marker} changed:  {change.name} ({change.component_id})")
            for field_name, (old_val, new_val) in change.changed_fields.items():
                print(f"        {field_name}: {old_val!r} -> {new_val!r}")
    if d.has_checksum_changes and args.fail_on_checksum_change:
        return 2
    return 0


def _cmd_export(args: argparse.Namespace) -> int:
    sbom = msbom_io.load(args.path)
    if args.format == "mermaid":
        output = to_mermaid(sbom, direction=args.direction)
    elif args.format == "dot":
        output = to_dot(sbom, rankdir=args.direction)
    elif args.format == "cyclonedx":
        import json
        output = json.dumps(to_cyclonedx(sbom), indent=2)
    else:  # pragma: no cover - argparse choices prevents this
        raise ValueError(f"unknown format {args.format}")

    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"Wrote {args.out}")
    else:
        print(output)
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    sbom = msbom_io.load(args.path)
    comp = sbom.get_component(args.component_id)
    if not comp:
        print(f"error: no component with id '{args.component_id}'", file=sys.stderr)
        return 1
    if not comp.checksum:
        print(f"error: component '{comp.name}' has no recorded checksum to verify against", file=sys.stderr)
        return 1

    ok = verify_checksum(args.artifact_path, comp.checksum.algorithm, comp.checksum.value)
    if ok:
        print(f"OK: {args.artifact_path} matches recorded {comp.checksum.algorithm} checksum for '{comp.name}'")
        return 0
    else:
        print(
            f"MISMATCH: {args.artifact_path} does NOT match recorded "
            f"{comp.checksum.algorithm} checksum for '{comp.name}'. "
            f"The artifact may have been modified or replaced since the SBOM was generated.",
            file=sys.stderr,
        )
        return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="msbom", description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p_val = sub.add_parser("validate", help="Validate an SBOM document (structural + optional JSON Schema).")
    p_val.add_argument("path")
    p_val.add_argument("--schema", action="store_true", help="Also run JSON Schema validation (requires `jsonschema`).")
    p_val.set_defaults(func=_cmd_validate)

    p_sum = sub.add_parser("summary", help="Print a human-readable summary of an SBOM document.")
    p_sum.add_argument("path")
    p_sum.set_defaults(func=_cmd_summary)

    p_lin = sub.add_parser("lineage", help="Show ancestors/descendants of a component.")
    p_lin.add_argument("path")
    p_lin.add_argument("--component", required=True, help="Component ID to trace.")
    p_lin.set_defaults(func=_cmd_lineage)

    p_diff = sub.add_parser("diff", help="Compare two SBOM documents.")
    p_diff.add_argument("old_path")
    p_diff.add_argument("new_path")
    p_diff.add_argument("--verbose", "-v", action="store_true")
    p_diff.add_argument("--fail-on-checksum-change", action="store_true",
                         help="Exit code 2 if any component's checksum changed (for CI gating).")
    p_diff.set_defaults(func=_cmd_diff)

    p_exp = sub.add_parser("export", help="Export an SBOM to another format.")
    p_exp.add_argument("path")
    p_exp.add_argument("--format", choices=["mermaid", "dot", "cyclonedx"], required=True)
    p_exp.add_argument("--direction", default="TD", help="Graph direction for mermaid/dot (e.g. TD, LR, TB).")
    p_exp.add_argument("--out", help="Output file path. Prints to stdout if omitted.")
    p_exp.set_defaults(func=_cmd_export)

    p_ver = sub.add_parser("verify", help="Verify a component's recorded checksum against an artifact on disk.")
    p_ver.add_argument("path", help="Path to the SBOM JSON document.")
    p_ver.add_argument("--component-id", required=True)
    p_ver.add_argument("--artifact-path", required=True, help="File or directory to hash and compare.")
    p_ver.set_defaults(func=_cmd_verify)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
