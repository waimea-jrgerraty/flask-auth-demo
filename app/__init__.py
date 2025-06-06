# ===========================================================
# App Creation and Launch
# ===========================================================

from flask import Flask, render_template, request, flash, redirect
from werkzeug.security import generate_password_hash, check_password_hash
import html

from app.helpers.session import init_session
from app.helpers.db import connect_db, handle_db_errors
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
@handle_db_errors
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
@handle_db_errors
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
        print("AAAAAAAAAAA:", result)

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
@handle_db_errors
def add_a_thing():
    # Get the data from the form
    name = request.form.get("name")

    # Sanitise the inputs
    name = html.escape(name)

    with connect_db() as client:
        # Add the thing to the DB
        sql = "INSERT INTO things (name) VALUES (?)"
        values = [name]
        client.execute(sql, values)

        # Go back to the home page
        flash(f"Thing '{name}' added", "success")
        return redirect("/things")


# -----------------------------------------------------------
# Route for deleting a thing, Id given in the route
# -----------------------------------------------------------
@app.get("/delete/<int:id>")
@handle_db_errors
def delete_a_thing(id):
    with connect_db() as client:
        # Delete the thing from the DB
        sql = "DELETE FROM things WHERE id=?"
        values = [id]
        client.execute(sql, values)

        # Go back to the home page
        flash("Thing deleted", "warning")
        return redirect("/things")


@app.post("/register/")
@handle_db_errors
def register_user():
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
            flash("Username already taken.")
            return redirect("/signup/")
        else:
            flash(f"User {username} registered successfully")
            return redirect("/")


@app.post("/login/")
@handle_db_errors
def login():
    flash("Not implemented yet")
    return redirect("/")
