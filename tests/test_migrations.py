from pathlib import Path

from vigilloo.laravel.migrations import extract_schema
from vigilloo.laravel.models import Protection, model_config
from vigilloo.models import Span
from vigilloo.parser import parse_source
from vigilloo.symbols import ClassInfo


def test_extract_migration_schema() -> None:
    code = b"""<?php
use Illuminate\\Database\\Migrations\\Migration;
use Illuminate\\Database\\Schema\\Blueprint;
use Illuminate\\Support\\Facades\\Schema;

return new class extends Migration {
    public function up(): void {
        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            $table->string('email')->unique();
            $table->boolean('is_admin')->default(false);
            $table->foreignId('role_id');
            $table->timestamps();
        });

        Schema::table('posts', function (Blueprint $table) {
            $table->id();
            $table->string('title');
            $table->text('content');
            $table->softDeletes();
        });
    }
};
"""
    parsed = parse_source(Path("database/migrations/2026_01_01_000000_create_tables.php"), code)
    files = {parsed.path: parsed}
    schema = extract_schema(files)

    assert "users" in schema
    assert schema["users"] == {
        "id",
        "name",
        "email",
        "is_admin",
        "role_id",
        "created_at",
        "updated_at",
    }

    assert "posts" in schema
    assert schema["posts"] == {"id", "title", "content", "deleted_at"}


def test_model_config_cross_checks_with_migrations() -> None:
    dummy_span = Span(
        file=Path("app/Models/User.php"), start_line=1, start_col=1, end_line=1, end_col=1
    )
    classes = {
        "App\\Models\\User": ClassInfo(
            fqn="App\\Models\\User",
            span=dummy_span,
            parent="Illuminate\\Database\\Eloquent\\Model",
            array_props={"fillable": ("name", "is_admin")},
        ),
        "App\\Models\\Post": ClassInfo(
            fqn="App\\Models\\Post",
            span=dummy_span,
            parent="Illuminate\\Database\\Eloquent\\Model",
            array_props={"fillable": ("title", "is_admin")},
        ),
        "App\\Models\\OpenUser": ClassInfo(
            fqn="App\\Models\\OpenUser",
            span=dummy_span,
            parent="Illuminate\\Database\\Eloquent\\Model",
            array_props={"guarded": ()},
            properties={"table": "'users'"},
        ),
        "App\\Models\\OpenPost": ClassInfo(
            fqn="App\\Models\\OpenPost",
            span=dummy_span,
            parent="Illuminate\\Database\\Eloquent\\Model",
            array_props={"guarded": ()},
            properties={"table": "'posts'"},
        ),
    }

    schema = {
        "users": {"id", "name", "email", "is_admin"},
        "posts": {"id", "title", "content"},  # is_admin absent from posts table
    }

    # User fillable has is_admin, and is_admin IS in users table -> PRIVILEGED_FILLABLE
    cfg_user = model_config(classes, "App\\Models\\User", schema)
    assert cfg_user is not None
    assert cfg_user.protection == Protection.PRIVILEGED_FILLABLE
    assert cfg_user.privileged_column == "is_admin"

    # Post fillable has is_admin, BUT is_admin is ABSENT from posts table
    # -> GUARDED (no phantom finding)
    cfg_post = model_config(classes, "App\\Models\\Post", schema)
    assert cfg_post is not None
    assert cfg_post.protection == Protection.GUARDED

    # OpenUser has guarded = [] and users table HAS is_admin -> OPEN
    cfg_open_user = model_config(classes, "App\\Models\\OpenUser", schema)
    assert cfg_open_user is not None
    assert cfg_open_user.protection == Protection.OPEN

    # OpenPost has guarded = [] BUT posts table has NO privileged columns
    # -> GUARDED (no phantom finding)
    cfg_open_post = model_config(classes, "App\\Models\\OpenPost", schema)
    assert cfg_open_post is not None
    assert cfg_open_post.protection == Protection.GUARDED
