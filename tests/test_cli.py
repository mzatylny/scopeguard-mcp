import json

from scopeguard_mcp import cli


class FakeService:
    def __init__(self, settings):
        self.settings = settings

    def health(self):
        return {"command": "doctor"}

    def verify_audit(self):
        return {"command": "verify"}

    def create_engagement(self, **kwargs):
        return {"command": "create", **kwargs}

    def revoke_engagement(self, engagement_id):
        return {"command": "revoke", "id": engagement_id}


def _patch_service(monkeypatch):
    monkeypatch.setattr(cli.Settings, "from_env", lambda: object())
    monkeypatch.setattr(cli, "ScopeGuardService", FakeService)


def test_cli_doctor_and_verify(monkeypatch, capsys):
    _patch_service(monkeypatch)
    cli.main(["doctor"])
    assert json.loads(capsys.readouterr().out)["command"] == "doctor"
    cli.main(["verify-audit"])
    assert json.loads(capsys.readouterr().out)["command"] == "verify"


def test_cli_create_and_revoke(monkeypatch, capsys):
    _patch_service(monkeypatch)
    cli.main(
        [
            "create-engagement",
            "--title",
            "Review",
            "--ticket",
            "SEC-9",
            "--target",
            "file:.",
            "--capability",
            "scan:repository",
            "--mode",
            "execute",
            "--expires-in-minutes",
            "30",
        ]
    )
    created = json.loads(capsys.readouterr().out)
    assert created["mode"] == "execute"
    assert created["expires_in_minutes"] == 30
    cli.main(["revoke-engagement", "eng-1"])
    assert json.loads(capsys.readouterr().out)["id"] == "eng-1"
