"""Offline-Tests (kein Netzwerk noetig) fuer Parser, Anomalie und DB."""
import os
import tempfile
from pathlib import Path

os.environ["GUARDAI_HOME"] = tempfile.mkdtemp(prefix="guardai_test_")

from guardai import anomaly, database, manifests  # noqa: E402


def test_requirements_parsing():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "requirements.txt").write_text("requests==2.19.0\nflask\n# comment\n")
        deps = manifests.discover(root)
        assert ("PyPI", "requests", "2.19.0") in deps
        assert ("PyPI", "flask", None) in deps


def test_package_json_parsing():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "package.json").write_text(
            '{"dependencies": {"lodash": "^4.17.19"}, "devDependencies": {"jest": "29.0.0"}}'
        )
        deps = manifests.discover(root)
        assert ("npm", "lodash", "4.17.19") in deps
        assert ("npm", "jest", "29.0.0") in deps


def test_anomaly_flags_suspicious_file():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        # 10 harmlose Dateien ...
        for i in range(10):
            (root / f"mod{i}.py").write_text(f"def f{i}(x):\n    return x + {i}\n")
        # ... und eine offensichtlich verschleierte.
        (root / "evil.py").write_text(
            "import base64,os\n" + "exec(base64.b64decode('" + "A" * 4000 + "'))\n"
        )
        results = anomaly.scan(root, top=3)
        top_paths = [Path(a.path).name for a in results]
        assert "evil.py" == top_paths[0]
        assert results[0].reasons


def test_database_roundtrip():
    database.init()
    n = database.upsert_cves([{
        "id": "CVE-2099-0001", "published": "2099-01-01T00:00:00",
        "modified": "2099-01-02T00:00:00", "severity": "CRITICAL",
        "cvss": 9.8, "summary": "test remote code execution", "refs": ["http://x"],
    }])
    assert n == 1
    rows = database.search("remote code execution")
    assert any(r["id"] == "CVE-2099-0001" for r in rows)


if __name__ == "__main__":
    test_requirements_parsing()
    test_package_json_parsing()
    test_anomaly_flags_suspicious_file()
    test_database_roundtrip()
    print("Alle Tests bestanden.")
