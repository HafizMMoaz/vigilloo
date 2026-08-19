<?php
namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;

class VulnerableCommand extends Command
{
    public $payload;

    public function handle()
    {
        DB::statement("DELETE FROM users WHERE id = " . $this->payload);
    }
}
