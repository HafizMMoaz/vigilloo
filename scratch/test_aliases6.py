from pathlib import Path
from vigilloo.graph import parse_php
from vigilloo.laravel.facades import app_aliases
tmp_path = Path("scratch/tmp6")
tmp_path.mkdir(exist_ok=True)
config_dir = tmp_path / "config"
config_dir.mkdir(exist_ok=True)
(config_dir / "app.php").write_text(
"""<?php
return [
    'aliases' => [
        'App' => Illuminate\\Support\\Facades\\App::class,
        'Auth' => Illuminate\\Support\\Facades\\Auth::class,
        'Custom' => App\\Facades\\Custom::class,
        'StringAlias' => 'App\\\\Facades\\\\StringAlias',
    ],
];
"""
)
print(app_aliases(tmp_path))
