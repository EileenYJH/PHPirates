<?php
// Shared helper (not vulnerable). Returns a PDO SQLite connection.
function get_db(): PDO {
    static $db = null;
    if ($db !== null) {
        return $db;
    }
    $db = new PDO('sqlite:' . __DIR__ . '/../data/app.db');
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->exec('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)');
    // Fictional demo account.
    $db->exec("INSERT OR IGNORE INTO users (username, password) VALUES ('admin', 'parrot-treasure-42')");
    return $db;
}
