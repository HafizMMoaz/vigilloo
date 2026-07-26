from pathlib import Path

from vigilloo.laravel.models import Protection, is_model, model_config, privileged_columns
from vigilloo.parser import parse_php
from vigilloo.symbols import extract_symbols


def _classes(tmp_path: Path, body: str) -> dict:
    path = tmp_path / "Thing.php"
    path.write_text(
        f"<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\n{body}\n"
    )
    return extract_symbols(parse_php(path)).classes


def test_guarded_empty_is_open(tmp_path: Path) -> None:
    classes = _classes(tmp_path, "class Thing extends Model { protected $guarded = []; }")
    config = model_config(classes, "App\\Models\\Thing")
    assert config is not None
    assert config.protection is Protection.OPEN
    assert config.reason_prop == "guarded"
    assert config.reason_span is not None


def test_narrow_fillable_is_guarded(tmp_path: Path) -> None:
    classes = _classes(
        tmp_path, "class Thing extends Model { protected $fillable = ['title', 'body']; }"
    )
    config = model_config(classes, "App\\Models\\Thing")
    assert config is not None
    assert config.protection is Protection.GUARDED


def test_privileged_fillable_names_the_column(tmp_path: Path) -> None:
    classes = _classes(
        tmp_path, "class Thing extends Model { protected $fillable = ['name', 'is_admin']; }"
    )
    config = model_config(classes, "App\\Models\\Thing")
    assert config is not None
    assert config.protection is Protection.PRIVILEGED_FILLABLE
    assert config.privileged_column == "is_admin"


def test_model_configuring_nothing_is_guarded(tmp_path: Path) -> None:
    """Eloquent's own $guarded defaults to ['*'], so nothing is assignable.

    Reading "unconfigured" as "open" would fire on almost every model ever
    written, which is the failure mode that gets a rule switched off.
    """
    classes = _classes(tmp_path, "class Thing extends Model { public function x() {} }")
    config = model_config(classes, "App\\Models\\Thing")
    assert config is not None
    assert config.protection is Protection.GUARDED


def test_unreadable_guarded_array_is_not_treated_as_empty(tmp_path: Path) -> None:
    classes = _classes(
        tmp_path, "class Thing extends Model { protected $guarded = [self::LOCKED]; }"
    )
    config = model_config(classes, "App\\Models\\Thing")
    assert config is not None
    assert config.protection is Protection.GUARDED


def test_a_plain_class_is_not_a_model(tmp_path: Path) -> None:
    classes = _classes(tmp_path, "class Thing { protected $guarded = []; }")
    assert not is_model(classes, "App\\Models\\Thing")
    assert model_config(classes, "App\\Models\\Thing") is None


def test_privileged_columns_are_matched_whole_never_as_substrings() -> None:
    """`user_id` as a substring makes `contributor_id_hash` a hit."""
    assert privileged_columns(("role", "is_admin", "user_id", "balance")) == (
        "role",
        "is_admin",
        "user_id",
        "balance",
    )
    assert privileged_columns(("contributor_id_hash", "role_name", "adminstrator")) == ()
