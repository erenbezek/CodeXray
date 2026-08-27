def get_user(request, cursor):
    username = request.args["username"]
    query = f"SELECT * FROM users WHERE name = '{username}'"
    cursor.execute(query)
