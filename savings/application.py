import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, usd

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

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///savings.db")

@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    cash = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])
    food = db.execute("SELECT fand as foodd FROM users WHERE id = :user_id", user_id=session["user_id"])
    cat = db.execute("SELECT bills as savee FROM users WHERE id = :user_id", user_id=session["user_id"])
    trave = db.execute("SELECT travel as travee FROM users WHERE id = :user_id", user_id=session["user_id"])
    others = db.execute("SELECT other as otherr FROM users WHERE id = :user_id", user_id=session["user_id"])
    trans = db.execute("SELECT transport as transs FROM users WHERE id = :user_id", user_id=session["user_id"])
    shops = db.execute("SELECT shop as shopp FROM users WHERE id = :user_id", user_id=session["user_id"])

    name = db.execute("SELECT username FROM users WHERE id = :user_id", user_id=session["user_id"])
    hoto = db.execute("SELECT username FROM users WHERE id = :user_id", user_id=session["user_id"])

    return render_template("index.html", cash=cash, cat=cat, food=food, trave=trave, others=others, trans=trans, shops=shops, name=name)


@app.route("/save", methods=["GET", "POST"])
@login_required
def save():
    """Save money"""
    savename = request.form.get("savename")
    saveamt = request.form.get("saveamt")
    category = request.form.get("category")



    if request.method == "POST":
        if not savename:
            return apology("Name your savings Please", 400)
        elif not int(saveamt):
            return apology("Enter an amount boss", 400)
        elif category == 'catt':
            return apology("Pick a category", 400)

        if category == 'Other':
            db.execute("UPDATE users SET other = other + :saveamt WHERE id = :user_id", user_id=session["user_id"], saveamt=saveamt)
        elif category == 'Food & Drinks':
            db.execute("UPDATE users SET fand = fand + :saveamt WHERE id = :user_id", user_id=session["user_id"], saveamt=saveamt)
        elif category == 'Bills':
            db.execute("UPDATE users SET bills = bills + :saveamt WHERE id = :user_id", user_id=session["user_id"], saveamt=saveamt)
        elif category == 'Transport':
            db.execute("UPDATE users SET transport = transport + :saveamt WHERE id = :user_id", user_id=session["user_id"], saveamt=saveamt)
        elif category == 'Travel':
            db.execute("UPDATE users SET travel = travel + :saveamt WHERE id = :user_id", user_id=session["user_id"], saveamt=saveamt)
        elif category == 'Shop':
            db.execute("UPDATE users SET shop = shop + :saveamt WHERE id = :user_id", user_id=session["user_id"], saveamt=saveamt)


        db.execute("UPDATE users SET cash = cash + :saveamt WHERE id = :user_id", user_id=session["user_id"], saveamt=saveamt)

        rows = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])
        nic = rows[0]["cash"]

        db.execute("INSERT INTO history (user_id, users_cash, savename, saveamt, category) VALUES (:user_id, :nic, :savename, :saveamt, :category)", user_id=session["user_id"], savename=savename, saveamt=saveamt, category=category, nic=nic)

        flash("Saved!")

        return redirect("/")

    else:
        return render_template("save.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history = db.execute("SELECT * FROM history WHERE user_id = :user_id ORDER BY dateandtime DESC", user_id=session["user_id"])
    return render_template("history.html", history=history)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/signup", methods=["GET", "POST"])
def register():
    """Register user"""
    username = request.form.get("username")
    password = request.form.get("password")
    confirmation = request.form.get("confirmation")
    if request.method == "POST":
        if not username:
            return apology("You must provide a Username.", 400)

        elif not password:
            return apology("You must create a password.", 400)

        elif not password == confirmation:
            return apology("Ensure Passwords match.", 400)

        elif len(password) < 8:
            return apology("Password must be 8 characters or more", 400)

        hash = generate_password_hash(password)

        new_user = db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)", username=username, hash=hash)
        if not new_user:
            return apology("This Username is taken.", 400)
        session["user_id"] = new_user

        flash("Registered!")

        return redirect("/")

    else:
        return render_template("register.html")

@app.route("/withdraw", methods=["GET", "POST"])
@login_required
def withdraw():
    """Withdraw amount saved"""
    food = db.execute("SELECT fand as foodd FROM users WHERE id = :user_id", user_id=session["user_id"])
    cat = db.execute("SELECT bills as savee FROM users WHERE id = :user_id", user_id=session["user_id"])
    trave = db.execute("SELECT travel as travee FROM users WHERE id = :user_id", user_id=session["user_id"])
    others = db.execute("SELECT other as otherr FROM users WHERE id = :user_id", user_id=session["user_id"])
    trans = db.execute("SELECT transport as transs FROM users WHERE id = :user_id", user_id=session["user_id"])
    shops = db.execute("SELECT shop as shopp FROM users WHERE id = :user_id", user_id=session["user_id"])

    saveamt = request.form.get("withamt")
    category = request.form.get("category")
    withname = request.form.get("withname")

    rows = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])
    nic = rows[0]["cash"]
    if request.method == "POST":
        if not int(saveamt):
            return apology("Enter an amount boss", 400)
        elif not category:
            return apology("Pick a category", 400)

        if category == 'Other':
            tet = db.execute("SELECT other FROM users WHERE id = :user_id", user_id=session["user_id"])
            rip = tet[0]["other"]
            if int(rip) < int(saveamt):
                return apology("You do not have enough cash in this Category", 400)
            db.execute("UPDATE users SET other = other - :saveamt WHERE id = :user_id", user_id=session["user_id"], saveamt=saveamt)
            db.execute("UPDATE users SET cash = cash - :saveamt WHERE id = :user_id", user_id=session["user_id"], saveamt=saveamt)
        elif category == 'Food & Drinks':
            tet = db.execute("SELECT fand FROM users WHERE id = :user_id", user_id=session["user_id"])
            rip = tet[0]["fand"]
            if int(rip) < int(saveamt):
                return apology("You do not have enough cash in this Category", 400)
            db.execute("UPDATE users SET fand = fand - :saveamt WHERE id = :user_id", user_id=session["user_id"], saveamt=saveamt)
            db.execute("UPDATE users SET cash = cash - :saveamt WHERE id = :user_id", user_id=session["user_id"], saveamt=saveamt)
        elif category == 'Bills':
            tet = db.execute("SELECT bills FROM users WHERE id = :user_id", user_id=session["user_id"])
            rip = tet[0]["bills"]
            if int(rip) < int(saveamt):
                return apology("You do not have enough cash in this Category", 400)
            db.execute("UPDATE users SET bills = bills - :saveamt WHERE id = :user_id", user_id=session["user_id"], saveamt=saveamt)
            db.execute("UPDATE users SET cash = cash - :saveamt WHERE id = :user_id", user_id=session["user_id"], saveamt=saveamt)
        elif category == 'Transport':
            tet = db.execute("SELECT transport FROM users WHERE id = :user_id", user_id=session["user_id"])
            rip = tet[0]["transport"]
            if int(rip) < int(saveamt):
                return apology("You do not have enough cash in this Category", 400)
            db.execute("UPDATE users SET transport = transport - :saveamt WHERE id = :user_id", user_id=session["user_id"], saveamt=saveamt)
            db.execute("UPDATE users SET cash = cash - :saveamt WHERE id = :user_id", user_id=session["user_id"], saveamt=saveamt)
        elif category == 'Travel':
            tet = db.execute("SELECT travel FROM users WHERE id = :user_id", user_id=session["user_id"])
            rip = tet[0]["travel"]
            if int(rip) < int(saveamt):
                return apology("You do not have enough cash in this Category", 400)
            db.execute("UPDATE users SET travel = travel - :saveamt WHERE id = :user_id", user_id=session["user_id"], saveamt=saveamt)
            db.execute("UPDATE users SET cash = cash - :saveamt WHERE id = :user_id", user_id=session["user_id"], saveamt=saveamt)
        elif category == 'Shop':
            tet = db.execute("SELECT shop FROM users WHERE id = :user_id", user_id=session["user_id"])
            rip = tet[0]["shop"]
            if int(rip) < int(saveamt):
                return apology("You do not have enough cash in this Category", 400)
            db.execute("UPDATE users SET shop = shop - :saveamt WHERE id = :user_id", user_id=session["user_id"], saveamt=saveamt)
            db.execute("UPDATE users SET cash = cash - :saveamt WHERE id = :user_id", user_id=session["user_id"], saveamt=saveamt)
        db.execute("INSERT INTO history (user_id, users_cash, savename, saveamt, category) VALUES (:user_id, :nic, :withname, -:saveamt, :category)", user_id=session["user_id"], saveamt=saveamt, category=category, nic=nic, withname=withname)

        flash("Withdrawal Successful!")

        return redirect("/")

    else:
        return render_template("withdraw.html", rows=rows, cat=cat, food=food, trave=trave, others=others, trans=trans, shops=shops)

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)