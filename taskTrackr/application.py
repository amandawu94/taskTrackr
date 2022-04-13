import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from helpers import apology, login_required
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///tasklists.db")


@app.route("/")
@login_required
def index():
    """Show tasks in To-DO List"""
    rows = db.execute("SELECT task, due_date FROM tasks WHERE userID = ?", session["user_id"])

    return render_template("index.html", rows=rows)


@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    """Add new tasks"""
    # Get User Input via POST
    if request.method == "POST":
        task = request.form.get("task")
        due_date = request.form.get("due_date")

        if not task:
            return apology("Please submit a task!", 400)
        if not due_date:
            return apology("Please submit a valid time!", 400)

        # Add task to database
        db.execute(
            "INSERT INTO tasks (userID, task, due_date) VALUES (:user_id, :task, :due_date);",
            user_id=session["user_id"],
            task=task,
            due_date=due_date,
        )

        return redirect("/")

    else:
        return render_template("add.html")


@app.route("/history")
@login_required
def history():
    """Show history of tasks"""
    tasks = db.execute("SELECT * FROM tasks WHERE userID = ?", session["user_id"])
    return render_template("history.html", tasks=tasks)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Check for username
        if not request.form.get("username"):
            return apology("Must provide username", 403)

        # Check for password
        elif not request.form.get("password"):
            return apology("Must provide password", 403)

        # Check DB for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Check that username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("Invalid username and/or password", 403)

        # Log user session
        session["user_id"] = rows[0]["id"]

        # Redirect to home page
        return redirect("/")

    # User reached route via GET (by link or redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""
    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        # Get User Input
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Check for username
        if not username:
            return apology("Must provide username", 400)
        # Check username doesn't exist
        elif len(rows) != 0:
            return apology("Username already exists", 400)

        # Check for password
        elif not password:
            return apology("Must provide password", 400)

        # Check password was provided
        elif not request.form.get("confirmation"):
            return apology("Must provide a confirmation password", 400)

        # Check that passwords match
        elif not password == confirmation:
            return apology("Passwords must match", 400)

        else:
            # Generate the hash of the password
            hash = generate_password_hash(
                password, method="pbkdf2:sha256", salt_length=8
            )
            # Create new user
            db.execute(
                "INSERT INTO users (username, hash) VALUES (?, ?) ", username, hash
            )
            # Redirect user
            return redirect("/")

    # User reached route via GET (by link or redirect)
    else:
        return render_template("register.html")


@app.route("/delete", methods=["GET", "POST"])
@login_required
def delete():
    """Delete tasks"""
    if request.method == "POST":
        # Get user input
        task = request.form.get("task")

        if not task:
            return apology("Please input a task!", 400)

        task = db.execute("SELECT * FROM tasks WHERE task = ?", task)

        if task == task:
            rm(task)

        flash("Deleted!")
        return redirect("/")

    # User reached route via GET (by link or redirect)
    else:

        return render_template("delete.html", task=task)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
