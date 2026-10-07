from pathlib import Path
from polymer.core.targets import parse_targets


def test_targets_expand(tmp_path: Path):
    p = tmp_path / "targets.txt"
    p.write_text("192.168.1.10\n192.168.1.8/30\n")
    result = parse_targets(p)
    assert result == ["192.168.1.9", "192.168.1.10"]
