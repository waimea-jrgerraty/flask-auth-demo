# ===========================================================
# App Creation and Launch
# ===========================================================

from flask import Flask, render_template, flash, redirect, session, request
from werkzeug.security import generate_password_hash, check_password_hash
import html

from app.helpers.session import init_session
from app.helpers.db import connect_db
from app.helpers.errors import register_error_handlers, not_found_error


# Create the app
app = Flask(__name__)

# Setup a session for messages, etc.
init_session(app)

# Handle 404 and 500 errors
register_error_handlers(app)


# -----------------------------------------------------------
# Home page route
# -----------------------------------------------------------
@app.get("/")
def index():
    return render_template("pages/home.jinja")


# -----------------------------------------------------------
# About page route
# -----------------------------------------------------------
@app.get("/about/")
def about():
    return render_template("pages/about.jinja")


# -----------------------------------------------------------
# Things page route - Show all the things, and new thing form
# -----------------------------------------------------------
@app.get("/things/")
def show_all_things():
    with connect_db() as client:
        # Get all the things from the DB
        sql = "SELECT id, name FROM things ORDER BY name ASC"
        result = client.execute(sql)
        things = result.rows

        # And show them on the page
        return render_template("pages/things.jinja", things=things)


# -----------------------------------------------------------
# Thing page route - Show details of a single thing
# -----------------------------------------------------------
@app.get("/thing/<int:id>")
def show_one_thing(id):
    with connect_db() as client:
        # Get the thing details from the DB
        sql = """
            SELECT 
                things.id,
                things.name,
                users.id AS userid,
                users.username AS owner
            FROM things 
            JOIN users ON things.userid = users.id
            WHERE things.id=?    
        """
        values = [id]
        result = client.execute(sql, values)

        # Did we get a result?
        if result.rows:
            # yes, so show it on the page
            thing = result.rows[0]
            return render_template("pages/thing.jinja", thing=thing)

        else:
            # No, so show error
            return not_found_error()


# -----------------------------------------------------------
# Thing page route - Show details of a single thing
# -----------------------------------------------------------
@app.get("/signup/")
def signup():
    return render_template("pages/signup.jinja")


@app.get("/signin/")
def signin():
    return render_template("pages/signin.jinja")


# -----------------------------------------------------------
# Route for adding a thing, using data posted from a form
# -----------------------------------------------------------
@app.post("/add")
def add_a_thing():
    # Get the data from the form
    name = request.form.get("name")

    # Sanitise the inputs
    name = html.escape(name)

    assert session["userid"]

    with connect_db() as client:
        # Add the thing to the DB
        sql = "INSERT INTO things (name, userid) VALUES (?, ?)"
        values = [name, session["userid"]]
        client.execute(sql, values)

        # Go back to the home page
        flash(f"Thing '{name}' added", "success")
        return redirect("/things")


# -----------------------------------------------------------
# Route for deleting a thing, Id given in the route
# -----------------------------------------------------------
@app.get("/delete/<int:id>")
def delete_a_thing(id):
    with connect_db() as client:
        # Attempt to delete only if the current user owns the thing
        sql = "DELETE FROM things WHERE id = ? AND userid = ?"
        values = [id, session["userid"]]
        result = client.execute(sql, values)

        # Check if anything was actually deleted
        if result.rows_affected == 0:
            flash("Not authorized or item not found.", "error")
            return redirect(f"/thing/{id}")

        # Go back to the home page
        flash("Thing deleted", "warning")
        return redirect("/things")


@app.post("/register/")
def register_user():
    if session["userid"] != None:
        return redirect("/")

    # Get the data from the form
    name = request.form.get("name")
    username = request.form.get("username")
    password = request.form.get("password")

    # Sanitise the inputs
    name = html.escape(name)
    username = html.escape(username)

    # Hash the password
    hash = generate_password_hash(password)

    with connect_db() as client:
        # Add the thing to the DB
        sql = "INSERT OR IGNORE INTO users (name, username, hash) VALUES (?, ?, ?)"
        values = [name, username, hash]
        result = client.execute(sql, values)
        if result.rows_affected == 0:
            flash("Username already taken.", "error")
            return redirect("/signup/")
        else:
            # Handle session
            session["userid"] = result.last_insert_rowid
            session["username"] = username

            flash(f"User {username} registered successfully", "success")
            return redirect("/")


@app.post("/login/")
def login():
    if session["userid"] != None:
        return redirect("/")

    # Get the data from the form
    username = request.form.get("username")
    password = request.form.get("password")

    # Sanitise the inputs
    username = html.escape(username)

    with connect_db() as client:
        sql = "SELECT id, hash FROM users WHERE username=?"
        values = [username]
        result = client.execute(sql, values)

        if result.rows:
            user = result.rows[0]
            hash = user["hash"]

            if check_password_hash(hash, password):
                # Handle session
                session["userid"] = user["id"]
                session["username"] = username

                flash(f"Welcome {username}!", "success")
                return redirect("/")
            else:
                flash("Incorrect credentials.", "error")
                return redirect("/login/")
        else:
            flash(f"Account with username {username} not found!", "error")
            return redirect("/login/")


@app.get("/logout/")
def logout():
    session["userid"] = None
    session["username"] = None
    return redirect("/")
