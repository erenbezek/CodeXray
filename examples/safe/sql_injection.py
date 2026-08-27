def get_user(request, cursor):
    username = request.args["username"]
    safe = escape_sql(username)
    query = f"SELECT * FROM users WHERE name = '{safe}'"
    cursor.execute(query)
