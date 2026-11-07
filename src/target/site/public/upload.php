<?php
$message = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $file = $_FILES['file'];
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $message = 'Upload failed.';
    } else {
        $name = basename($file['name']);
        $target = __DIR__ . '/uploads/' . $name;
        if (move_uploaded_file($file['tmp_name'], $target)) {
            $safe = htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
            $message = 'Uploaded: <a href="uploads/' . $safe . '">uploads/' . $safe . '</a>';
        } else {
            $message = 'Could not save file.';
        }
    }
}
?>
<!doctype html>
<html>
<head><meta charset="utf-8"><title>Share a picture</title></head>
<body>
<h1>Share a picture of your parrot</h1>
<?php if ($message !== ''): ?>
<p class="message"><?= $message ?></p>
<?php endif; ?>
<form method="post" enctype="multipart/form-data">
  <input type="file" name="file">
  <button type="submit">Upload</button>
</form>
</body>
</html>
