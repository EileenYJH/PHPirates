<?php
$q = $_GET['q'] ?? '';
$items = ['Pirate hat', 'Parrot', 'Treasure map', 'Foam cutlass', 'Spyglass', 'Ship in a bottle'];
$results = array_filter($items, function ($item) use ($q) {
    return $q === '' || stripos($item, $q) !== false;
});
?>
<!doctype html>
<html>
<head><meta charset="utf-8"><title>Search the hold</title></head>
<body>
<h1>Search the hold</h1>
<form method="get">
  <input name="q">
  <button type="submit">Search</button>
</form>
<?php if ($q !== ''): ?>
<h2>Results for <?= $q ?></h2>
<?php endif; ?>
<ul>
<?php foreach ($results as $item): ?>
  <li><?= htmlspecialchars($item, ENT_QUOTES, 'UTF-8') ?></li>
<?php endforeach; ?>
</ul>
</body>
</html>
