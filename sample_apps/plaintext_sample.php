<?php
$pdo->prepare("INSERT INTO users (password) VALUES (?)")->execute([$password]);
?>
