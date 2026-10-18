def save_user(password):
    cursor.execute("INSERT INTO users (password) VALUES (?)", (password,))
