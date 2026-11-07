<?php
require_once __DIR__ . '/../lib/db.php';

$message = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    $db = get_db();
    $sql = "SELECT username FROM users WHERE username = '" . $username . "' AND password = '" . $password . "'";
    $row = $db->query($sql)->fetch(PDO::FETCH_ASSOC);
    if ($row) {
        $message = 'Welcome, ' . htmlspecialchars($row['username'], ENT_QUOTES, 'UTF-8') . '!';
    } else {
        $message = 'Invalid credentials.';
    }
}
?>
<!doctype html>
<html>
<head><meta charset="utf-8"><title>Crew login</title></head>
<body>
<h1>Crew login</h1>
<?php if ($message !== ''): ?>
<p class="message"><?= $message ?></p>
<?php endif; ?>
<form method="post">
  <label>Username <input name="username"></label>
  <label>Password <input name="password" type="password"></label>
  <button type="submit">Log in</button>
</form>
</body>
</html>
