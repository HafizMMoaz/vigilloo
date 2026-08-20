from pathlib import Path

from vigilloo.laravel.models import extract_model_metadata
from vigilloo.parser import collect_nodes, parse_source
from vigilloo.symbols import extract_symbols


def test_extract_model_metadata() -> None:
    code = b"""<?php
namespace App\\Models;

use Illuminate\\Database\\Eloquent\\Model;
use Illuminate\\Database\\Eloquent\\SoftDeletes;
use App\\Models\\Post;

class User extends Model {
    use SoftDeletes;

    protected $table = 'custom_users';
    public $timestamps = false;

    protected $fillable = ['name', 'email'];
    protected $guarded = ['id'];
    protected $hidden = ['password', 'remember_token'];
    protected $appends = ['full_name'];

    protected $casts = [
        'email_verified_at' => 'datetime',
        'is_admin' => 'boolean',
    ];

    public function posts() {
        return $this->hasMany(Post::class);
    }

    public function scopeActive($query) {
        return $query->where('active', 1);
    }

    public function getFirstNameAttribute() {
        return ucfirst($this->name);
    }

    public function setFirstNameAttribute($value) {
        $this->attributes['name'] = strtolower($value);
    }
}
"""
    parsed = parse_source(Path("app/Models/User.php"), code)
    symbols = extract_symbols(
        collect_nodes(parsed.tree.root_node).namespaces,
        collect_nodes(parsed.tree.root_node).imports,
        collect_nodes(parsed.tree.root_node).classes,
        collect_nodes(parsed.tree.root_node).traits,
        parsed,
    )

    meta = extract_model_metadata(parsed, symbols, "App\\Models\\User")
    assert meta is not None

    assert meta.fqn == "App\\Models\\User"
    assert meta.table == "custom_users"
    assert meta.timestamps is False
    assert meta.soft_deletes is True
    assert meta.fillable == ("name", "email")
    assert meta.guarded == ("id",)
    assert meta.hidden == ("password", "remember_token")
    assert meta.appends == ("full_name",)
    assert meta.casts == {
        "email_verified_at": "datetime",
        "is_admin": "boolean",
    }
    assert meta.relationships == {
        "posts": ("hasMany", "App\\Models\\Post"),
    }
    assert meta.scopes == ("scopeActive",)
    assert meta.accessors == ("getFirstNameAttribute",)
    assert meta.mutators == ("setFirstNameAttribute",)
