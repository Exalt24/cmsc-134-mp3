import secrets
import sqlite3

from flask import Flask, request, render_template, redirect, session, abort

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
con = sqlite3.connect("app.db", check_same_thread=False)
con.row_factory = sqlite3.Row

@app.before_request
def ensure_csrf_token():
    # Generate CSRF token per session if missing
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)

@app.route("/login", methods=["GET", "POST"])
def login():
    cur = con.cursor()
    if request.method == "GET":
        token = request.cookies.get("session_token")
        if token:
            cur.execute("SELECT 1 FROM sessions WHERE token = ?", (token,))
            if cur.fetchone():
                return redirect("/home")
            
        return render_template("login.html",
                               error=None,
                               csrf_token=session['csrf_token'])
    else:
        if request.form.get("csrf_token") != session.get("csrf_token"):
            abort(400)

        username = request.form["username"]
        password = request.form["password"]

        cur.execute(
            "SELECT id FROM users WHERE username = ? AND password = ?",
            (username, password)
        )
        row = cur.fetchone()
        if not row:
            return render_template("login.html",
                                error="Invalid username and/or password!",
                                csrf_token=session['csrf_token'])
        else:
            # Successful login
            user_id   = row["id"]
            new_token = secrets.token_hex()
            cur.execute(
                "INSERT INTO sessions (user, token) VALUES (?, ?)",
                (user_id, new_token)
            )
            con.commit()

            resp = redirect("/home")
            resp.set_cookie("session_token", new_token,
                            httponly=True, samesite="Lax")
            return resp

@app.route("/")
@app.route("/home")
def home():
    cur = con.cursor()
    token = request.cookies.get("session_token")
    if not token:
        return redirect("/login")
    
    cur.execute(
        "SELECT users.id, users.username FROM users "
        "JOIN sessions ON users.id = sessions.user "
        "WHERE sessions.token = ?",
        (token,)
    )
    row = cur.fetchone()
    if not row:
        return redirect("/login")

    user_id, username = row["id"], row["username"]

    cur.execute(
        "SELECT message FROM posts WHERE user = ?",
        (user_id,)
    )
    posts = cur.fetchall()

    return render_template("home.html",
                           username=username,
                           posts=posts,
                           csrf_token=session['csrf_token'])


@app.route("/posts", methods=["POST"])
def posts():
    # CSRF check
    if request.form.get("csrf_token") != session.get("csrf_token"):
        abort(400)

    token = request.cookies.get("session_token")
    if not token:
        return redirect("/login")
    
    # Verify session → get user_id
    cur = con.cursor()
    cur.execute(
        "SELECT users.id FROM users "
        "JOIN sessions ON users.id = sessions.user "
        "WHERE sessions.token = ?",
        (token,)
    )
    row = cur.fetchone()
    if not row:
        return redirect("/login", error="test")
    user_id = row["id"]

    message = request.form["message"]
    cur.execute(
        "INSERT INTO posts (message, user) VALUES (?, ?)",
        (message, user_id)
    )
    con.commit()

    return redirect("/home")


@app.route("/logout", methods=["GET"])
def logout():
    token = request.cookies.get("session_token")
    if token:
        cur = con.cursor()
        cur.execute(
            "DELETE FROM sessions WHERE token = ?",
            (token,)
        )
        con.commit()

    response = redirect("/login")
    response.set_cookie("session_token", "", expires=0)

    return response