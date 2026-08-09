#!/usr/bin/env python3
"""
run_cli.py
==========
Convenience wrapper so `python scripts/run_cli.py [...args]` works without
installing the package first (adds src/ to sys.path). Forwards all
arguments to the same CLI as the installed `msbom` entry point.

Examples:
    python scripts/run_cli.py validate examples/llama-finetune-lora/sbom.json
    python scripts/run_cli.py summary examples/llama-finetune-lora/sbom.json
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from msbom.cli import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
