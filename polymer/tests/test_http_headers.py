import pytest

from polymer.core.http_headers import api_headers


def test_api_headers_load_json_object_from_environment(monkeypatch):
    monkeypatch.setenv(
        "POLYMER_API_HEADERS",
        '{"Authorization":"Bearer fixture","X-API-Key":"secret"}',
    )

    headers = api_headers({"headers_env": "POLYMER_API_HEADERS"})

    assert headers == ["Authorization: Bearer fixture", "X-API-Key: secret"]


def test_api_headers_reject_newlines(monkeypatch):
    monkeypatch.setenv("POLYMER_API_HEADERS", '{"X-Test":"safe\\r\\ninjected"}')

    with pytest.raises(ValueError, match="unsafe"):
        api_headers({"headers_env": "POLYMER_API_HEADERS"})
