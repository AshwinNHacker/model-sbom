import json
import subprocess
import sys

import pytest

from msbom import io as msbom_io
from msbom.cli import main


@pytest.fixture
def sbom_file(tmp_path, sample_sbom):
    sbom, comps = sample_sbom
    path = tmp_path / "sbom.json"
    msbom_io.save(sbom, path)
    return path, comps


def test_validate_command_exits_zero_for_valid_doc(sbom_file, capsys):
    path, _ = sbom_file
    code = main(["validate", str(path)])
    out = capsys.readouterr().out
    assert code == 0
    assert "0 error(s)" in out


def test_validate_command_exits_nonzero_for_invalid_doc(tmp_path, capsys):
    bad = {
        "bom_format": "ModelSBOM", "spec_version": "1.0.0",
        "serial_number": "urn:uuid:x", "version": 1,
        "metadata": {"tool_name": "t", "tool_version": "1", "authors": [],
                      "organization": "", "timestamp": "now", "description": ""},
        "components": [{
            "id": "adapter-1", "type": "adapter", "name": "orphan", "version": "1.0",
            "supplier": "unknown", "license": "UNKNOWN", "license_note": "",
            "checksum": None, "external_refs": [], "created_at": "now",
            "notes": "", "properties": {},
        }],
        "relationships": [],
    }
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(bad))
    code = main(["validate", str(path)])
    out = capsys.readouterr().out
    assert code == 1
    assert "ADAPTER_MISSING_BASE_MODEL" in out


def test_summary_command(sbom_file, capsys):
    path, _ = sbom_file
    code = main(["summary", str(path)])
    out = capsys.readouterr().out
    assert code == 0
    assert "base_model" in out
    assert "adapter" in out


def test_lineage_command(sbom_file, capsys):
    path, comps = sbom_file
    code = main(["lineage", str(path), "--component", comps["adapter"].id])
    out = capsys.readouterr().out
    assert code == 0
    assert "Ancestors" in out
    assert comps["base"].name in out


def test_lineage_command_unknown_component(sbom_file, capsys):
    path, _ = sbom_file
    code = main(["lineage", str(path), "--component", "does-not-exist"])
    err = capsys.readouterr().err
    assert code == 1
    assert "does-not-exist" in err


def test_diff_command(sbom_file, tmp_path, capsys):
    path, _comps = sbom_file
    sbom = msbom_io.load(path)
    sbom.version = 2
    new_path = tmp_path / "sbom_v2.json"
    msbom_io.save(sbom, new_path)

    code = main(["diff", str(path), str(new_path)])
    out = capsys.readouterr().out
    assert code == 0
    assert "0 components added" in out


def test_export_mermaid_to_stdout(sbom_file, capsys):
    path, _ = sbom_file
    code = main(["export", str(path), "--format", "mermaid"])
    out = capsys.readouterr().out
    assert code == 0
    assert "flowchart TD" in out


def test_export_to_file(sbom_file, tmp_path, capsys):
    path, _ = sbom_file
    out_path = tmp_path / "out.dot"
    code = main(["export", str(path), "--format", "dot", "--out", str(out_path)])
    assert code == 0
    assert out_path.exists()
    assert "digraph ModelSBOM" in out_path.read_text()


def test_verify_command_matching_artifact(sbom_file, tmp_path, capsys):
    path, comps = sbom_file
    artifact = tmp_path / "weights.bin"
    from msbom.hashing import sha256_file
    artifact.write_bytes(b"fake weights content")
    digest = sha256_file(artifact)

    sbom = msbom_io.load(path)
    comp = sbom.get_component(comps["base"].id)
    comp.checksum.value = digest
    msbom_io.save(sbom, path)

    code = main(["verify", str(path), "--component-id", comps["base"].id, "--artifact-path", str(artifact)])
    out = capsys.readouterr().out
    assert code == 0
    assert "OK" in out


def test_verify_command_mismatched_artifact(sbom_file, tmp_path, capsys):
    path, comps = sbom_file
    artifact = tmp_path / "weights.bin"
    artifact.write_bytes(b"different content than recorded checksum")

    code = main(["verify", str(path), "--component-id", comps["base"].id, "--artifact-path", str(artifact)])
    err = capsys.readouterr().err
    assert code == 2
    assert "MISMATCH" in err


def test_cli_installed_entrypoint_runs():
    """Smoke test that the console_scripts entry point (`msbom`) is wired up."""
    result = subprocess.run(
        [sys.executable, "-m", "msbom.cli", "--help"],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0
    assert "msbom" in result.stdout.lower()
