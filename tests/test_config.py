from pathlib import Path

from vigilloo.graph import load_project
from vigilloo.laravel.config import parse_env_file


def test_parse_env_file(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("""
# Comment line
APP_NAME=Vigilloo
APP_DEBUG=true
DB_PASSWORD="secret_pass_123"
KEY_WITH_QUOTES='single_quoted'
EMPTY_LINE=
""")

    env_vars = parse_env_file(env_file)
    assert env_vars["APP_NAME"] == "Vigilloo"
    assert env_vars["APP_DEBUG"] == "true"
    assert env_vars["DB_PASSWORD"] == "secret_pass_123"
    assert env_vars["KEY_WITH_QUOTES"] == "single_quoted"


def test_config_facts_extraction_with_env_defaults(tmp_path: Path) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "routes").mkdir()

    (tmp_path / ".env").write_text("""
APP_ENV=local
APP_DEBUG=true
DB_PASSWORD=super_secret
APP_KEY=base64:secretkey123
""")

    (tmp_path / "config/app.php").write_text("""<?php
return [
    'name' => env('APP_NAME', 'DefaultName'),
    'env' => env('APP_ENV', 'production'),
    'debug' => (bool) env('APP_DEBUG', false),
    'key' => env('APP_KEY'),
];
""")

    (tmp_path / "config/session.php").write_text("""<?php
return [
    'driver' => env('SESSION_DRIVER', 'file'),
    'lifetime' => 120,
];
""")

    (tmp_path / "routes/web.php").write_text("<?php\n")

    project = load_project(tmp_path)
    cfg = project.config

    assert cfg.env_file_exists is True
    assert cfg.get("app.name") == "DefaultName"
    assert cfg.get("app.env") == "local"
    assert cfg.get("app.debug") is True
    assert cfg.get("session.driver") == "file"
    assert cfg.get("session.lifetime") == 120

    # Secret redaction check: raw value is base64:secretkey123, safe_value is [REDACTED]
    key_obj = cfg.get_value_object("app.key")
    assert key_obj is not None
    assert key_obj.is_secret is True
    assert key_obj.value == "base64:secretkey123"
    assert key_obj.safe_value == "[REDACTED]"
