void store(String password) {
    statement.executeUpdate("INSERT INTO users (password) VALUES (?)");
}
