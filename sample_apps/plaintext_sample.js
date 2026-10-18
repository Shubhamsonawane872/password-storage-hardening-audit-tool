function store(password) {
  database.query("INSERT INTO users (password) VALUES (?)", [password]);
}
