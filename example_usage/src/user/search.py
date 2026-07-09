"""Customer search API — contains SQL injection vulnerability for demo purposes."""
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)


def search_users(keyword):
    """Search users by name keyword.

    VULNERABLE: user input concatenated into SQL query string.
    An attacker can inject SQL via the 'keyword' parameter.
    """
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # VULNERABLE LINE 14: string concatenation bypasses parameterized query guard
    sql = "SELECT id, name, email FROM users WHERE name LIKE '%" + keyword + "%'"
    cursor.execute(sql)

    results = cursor.fetchall()
    conn.close()
    return results


@app.route("/users/search")
def search():
    q = request.args.get("q", "")
    users = search_users(q)
    return jsonify({
        "users": [{"id": u[0], "name": u[1], "email": u[2]} for u in users]
    })


if __name__ == "__main__":
    app.run(debug=True)
