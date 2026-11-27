"""Every engine must match the schema and form a DAG with known dependencies."""
import json
from pathlib import Path

import jsonschema
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1] / "engines"
SCHEMA = json.loads((ROOT / "schema" / "engine.schema.json").read_text())
ENGINES = sorted(ROOT.glob("*.yaml"))


@pytest.mark.parametrize("path", ENGINES, ids=lambda p: p.name)
def test_engine_valid(path):
    eng = yaml.safe_load(path.read_text())
    jsonschema.validate(eng, SCHEMA)
    assert path.stem == eng["id"]
    ids = [s["id"] for s in eng["steps"]]
    assert len(ids) == len(set(ids)), "duplicate step id"
    seen = set()
    for step in eng["steps"]:  # steps must be listed in dependency order
        for dep in step.get("needs", []):
            assert dep in seen, f"{step['id']} needs unknown or later step {dep}"
        seen.add(step["id"])


@pytest.mark.parametrize("path", ENGINES, ids=lambda p: p.name)
def test_active_engines_require_verification(path):
    eng = yaml.safe_load(path.read_text())
    if any(s["risk"] != "passive" for s in eng["steps"]):
        assert eng["requires_verified_target"]


def test_no_engine_enables_dos_templates():
    for path in ENGINES:
        for step in yaml.safe_load(path.read_text())["steps"]:
            if step["tool"] == "nuclei":
                assert "dos" not in step.get("args", {}).get("tags", [])
