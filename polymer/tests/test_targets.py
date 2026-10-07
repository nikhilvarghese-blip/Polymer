from pathlib import Path
import pytest

from polymer.core.targets import parse_targets


def test_targets_expand(tmp_path: Path):
    p = tmp_path / "targets.txt"
    p.write_text("192.168.1.10\n192.168.1.8/30\n")
    result = parse_targets(p)
    assert result == ["192.168.1.9", "192.168.1.10"]


def test_empty_targets_are_rejected(tmp_path: Path):
    path = tmp_path / "targets.txt"
    path.write_text("# no targets\n")
    with pytest.raises(ValueError, match="contains no targets"):
        parse_targets(path)


def test_large_network_stops_at_scope_limit(tmp_path: Path):
    path = tmp_path / "targets.txt"
    path.write_text("10.0.0.0/8\n")
    with pytest.raises(ValueError, match="exceeds max_hosts=4"):
        parse_targets(path, max_hosts=4)
