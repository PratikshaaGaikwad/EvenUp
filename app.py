import os
import re
import uuid
import secrets
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from decimal import Decimal, InvalidOperation
from db import configure_database, get_db_connection

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "change-this-in-production")

app.config["MYSQL_HOST"] = os.getenv("MYSQL_HOST", "127.0.0.1")
app.config["MYSQL_PORT"] = int(os.getenv("MYSQL_PORT", "3306"))
app.config["MYSQL_USER"] = os.getenv("MYSQL_USER", "root")
app.config["MYSQL_PASSWORD"] = os.getenv("MYSQL_PASSWORD", "")
app.config["MYSQL_DATABASE"] = os.getenv("MYSQL_DATABASE", "evenup")
configure_database(app.config)

app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, "static", "uploads")
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")

oauth = None

if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    from authlib.integrations.flask_client import OAuth

    oauth = OAuth(app)

    oauth.register(
        name="google",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={
            "scope": "openid email profile",
            "prompt": "select_account"
        }
    )


def allowed_image(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS
    )


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))

        return f(*args, **kwargs)

    return decorated


def start_session(user):
    session["user_id"] = user["id"]
    session["user_name"] = user["name"]


@app.context_processor
def inject_current_user():
    if "user_id" not in session:
        return {"current_user": None}

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute(
        """
        SELECT id, name, email, handle, avatar_url
        FROM users
        WHERE id = %s
        """,
        (session["user_id"],)
    )

    current_user = cursor.fetchone()

    cursor.close()
    conn.close()

    return {"current_user": current_user}


@app.errorhandler(413)
def file_too_large(error):
    flash("Profile picture must be 5 MB or smaller.", "error")
    return redirect(url_for("profile"))


@app.route("/")
def home():
    return render_template("landing.html")


@app.route("/contact", methods=["POST"])
def contact():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    message = request.form.get("message", "").strip()

    if not name or not email or not message:
        flash("Please fill in every field before sending.", "error")
        return redirect(url_for("home") + "#contact")

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        flash("That doesn't look like a valid email address.", "error")
        return redirect(url_for("home") + "#contact")

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO contact_messages (name, email, message) VALUES (%s, %s, %s)",
        (name, email, message)
    )

    conn.commit()
    cursor.close()
    conn.close()

    flash("Thanks — we've got your message and will reply by email soon.", "success")
    return redirect(url_for("home") + "#contact")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        handle = request.form.get("handle", "").strip().lower().replace("@", "")
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not name or not handle or not email or not password:
            flash("Please complete every field.", "error")
            return redirect(url_for("register"))

        if not re.fullmatch(r"[a-z0-9_]{3,30}", handle):
            flash(
                "Your ID must use 3 to 30 lowercase letters, numbers, or underscores.",
                "error"
            )
            return redirect(url_for("register"))

        if len(password) < 6:
            flash("Choose a password with at least 6 characters.", "error")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for("register"))

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id FROM users WHERE email = %s OR handle = %s",
            (email, handle)
        )

        if cursor.fetchone():
            cursor.close()
            conn.close()

            flash("That email or EvenUp ID is already taken.", "error")
            return redirect(url_for("register"))

        cursor.execute(
            """
            INSERT INTO users (name, handle, email, password_hash)
            VALUES (%s, %s, %s, %s)
            """,
            (name, handle, email, generate_password_hash(password))
        )

        conn.commit()
        cursor.close()
        conn.close()

        flash("Account created. Your EvenUp ID is @" + handle, "success")
        return redirect(url_for("login"))

    return render_template(
        "register.html",
        google_enabled=oauth is not None
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute(
            "SELECT * FROM users WHERE email = %s",
            (email,)
        )

        user = cursor.fetchone()

        cursor.close()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            start_session(user)

            flash("Welcome back, " + user["name"] + "!", "success")

            if not user.get("handle"):
                return redirect(url_for("set_handle"))

            return redirect(url_for("dashboard"))

        flash("Invalid email or password.", "error")
        return redirect(url_for("login"))

    return render_template(
        "login.html",
        google_enabled=oauth is not None
    )


@app.route("/login/google")
def google_login():
    if oauth is None:
        flash("Google sign-in is not configured. Add GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET to .env.", "error")
        return redirect(url_for("login"))

    redirect_uri = GOOGLE_REDIRECT_URI or url_for(
        "google_callback",
        _external=True
    )

    return oauth.google.authorize_redirect(
        redirect_uri
    )


@app.route("/auth/google/callback")
def google_callback():
    if oauth is None:
        return redirect(url_for("login"))

    try:
        token = oauth.google.authorize_access_token()
        google_profile = token.get("userinfo") or oauth.google.userinfo()
    except Exception:
        app.logger.exception("Google OAuth callback failed")
        flash("Google sign-in could not be completed. Please try again.", "error")
        return redirect(url_for("login"))

    email = google_profile.get("email", "").strip().lower()
    name = google_profile.get("name") or "EvenUp member"
    picture = google_profile.get("picture")

    if not email or google_profile.get("email_verified") is not True:
        flash("Google did not return a verified email address.", "error")
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute(
        "SELECT * FROM users WHERE email = %s",
        (email,)
    )

    user = cursor.fetchone()

    if not user:
        cursor.close()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO users (name, email, password_hash, avatar_url)
            VALUES (%s, %s, %s, %s)
            """,
            (
                name,
                email,
                generate_password_hash(secrets.token_urlsafe(32)),
                picture
            )
        )

        conn.commit()
        user_id = cursor.lastrowid

        cursor.close()
        cursor = conn.cursor(dictionary=True)

        cursor.execute(
            "SELECT * FROM users WHERE id = %s",
            (user_id,)
        )

        user = cursor.fetchone()

    elif picture and not user.get("avatar_url"):
        cursor.close()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET avatar_url=%s WHERE id=%s",
            (picture, user["id"])
        )
        conn.commit()
        user["avatar_url"] = picture

    cursor.close()
    conn.close()

    start_session(user)

    if not user.get("handle"):
        return redirect(url_for("set_handle"))

    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    flash("You've been logged out.", "success")
    return redirect(url_for("home"))
def get_user_groups(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute(
        """
        SELECT
            g.id,
            g.name,
            g.created_at,
            COUNT(all_members.user_id) AS member_count
        FROM groups_tbl g
        INNER JOIN group_members my_membership
            ON my_membership.group_id = g.id
        LEFT JOIN group_members all_members
            ON all_members.group_id = g.id
        WHERE my_membership.user_id = %s
        GROUP BY g.id, g.name, g.created_at
        ORDER BY g.created_at DESC
        """,
        (user_id,)
    )

    groups = cursor.fetchall()

    cursor.close()
    conn.close()

    return groups


def get_user_summary(user_id):
    """Return the signed-in person's open balance across every group."""
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT COALESCE(SUM(amount), 0) AS paid FROM expenses WHERE paid_by = %s", (user_id,))
    paid = Decimal(str(cursor.fetchone()["paid"]))
    cursor.execute("SELECT COALESCE(SUM(share_amount), 0) AS shared FROM expense_shares WHERE user_id = %s", (user_id,))
    shared = Decimal(str(cursor.fetchone()["shared"]))
    cursor.execute("""SELECT COALESCE(SUM(CASE WHEN from_user_id=%s THEN amount ELSE 0 END),0) AS sent,
        COALESCE(SUM(CASE WHEN to_user_id=%s THEN amount ELSE 0 END),0) AS received FROM settlements""", (user_id, user_id))
    settlement = cursor.fetchone()
    balance = paid - shared - Decimal(str(settlement["received"])) + Decimal(str(settlement["sent"]))
    cursor.close(); conn.close()
    return {"owes": max(-balance, Decimal("0")), "receives": max(balance, Decimal("0"))}

@app.route("/dashboard")
@login_required
def dashboard():
    user_groups = get_user_groups(session["user_id"])
    summary = get_user_summary(session["user_id"])

    return render_template(
        "dashboard.html",
        groups=user_groups,
        summary=summary
    )


@app.route("/groups")
@login_required
def groups():
    user_groups = get_user_groups(session["user_id"])

    return render_template(
        "workspace.html",
        active="groups",
        title="Your shared spaces",
        eyebrow="Groups",
        groups=user_groups
    )

@app.route("/expenses")
@login_required
def expenses():
    search = request.args.get("q", "").strip()
    category = request.args.get("category", "").strip()
    group_id = request.args.get("group", type=int)
    from_date = request.args.get("from", "").strip()
    to_date = request.args.get("to", "").strip()

    conn = get_db_connection(); cursor = conn.cursor(dictionary=True)
    query = """SELECT e.*, g.name AS group_name, g.currency, u.name AS payer_name
        FROM expenses e
        JOIN groups_tbl g ON g.id=e.group_id
        JOIN users u ON u.id=e.paid_by
        JOIN group_members gm ON gm.group_id=g.id
        WHERE gm.user_id=%s"""
    params = [session["user_id"]]
    if search:
        query += " AND (e.description LIKE %s OR e.category LIKE %s OR u.name LIKE %s)"
        params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
    if category:
        query += " AND e.category=%s"; params.append(category)
    if group_id:
        query += " AND e.group_id=%s"; params.append(group_id)
    if from_date:
        query += " AND DATE(e.created_at) >= %s"; params.append(from_date)
    if to_date:
        query += " AND DATE(e.created_at) <= %s"; params.append(to_date)
    query += " ORDER BY e.created_at DESC"
    cursor.execute(query, tuple(params)); rows = cursor.fetchall()
    cursor.execute("""SELECT DISTINCT e.category FROM expenses e JOIN group_members gm ON gm.group_id=e.group_id
        WHERE gm.user_id=%s ORDER BY e.category""", (session["user_id"],))
    categories = [row["category"] for row in cursor.fetchall()]
    cursor.execute("""SELECT DISTINCT g.id, g.name FROM groups_tbl g JOIN group_members gm ON gm.group_id=g.id
        WHERE gm.user_id=%s ORDER BY g.name""", (session["user_id"],))
    groups = cursor.fetchall()
    cursor.close(); conn.close()
    filtered_total = sum(Decimal(str(row["amount"])) for row in rows)
    expense_export_rows = [
        [
            row["description"],
            row["category"],
            str(row["created_at"])[:10],
            row["group_name"],
            row["payer_name"],
            row["currency"],
            float(row["amount"]),
        ]
        for row in rows
    ]
    return render_template("expenses.html", expenses=rows, categories=categories, groups=groups,
                           filters={"q": search, "category": category, "group": group_id or "", "from": from_date, "to": to_date},
                           filtered_total=filtered_total, expense_export_rows=expense_export_rows)


@app.route("/insights")
@login_required
def insights():
    conn = get_db_connection(); cursor = conn.cursor(dictionary=True)
    cursor.execute("""SELECT e.category, SUM(e.amount) AS total FROM expenses e JOIN group_members gm ON gm.group_id=e.group_id
        WHERE gm.user_id=%s GROUP BY e.category ORDER BY total DESC""", (session["user_id"],))
    categories = cursor.fetchall()
    cursor.execute("""SELECT g.name, g.currency, COALESCE(SUM(e.amount), 0) AS total FROM groups_tbl g
        JOIN group_members gm ON gm.group_id=g.id LEFT JOIN expenses e ON e.group_id=g.id
        WHERE gm.user_id=%s GROUP BY g.id ORDER BY total DESC""", (session["user_id"],))
    groups_spend = cursor.fetchall(); cursor.close(); conn.close()
    total = sum(Decimal(str(item["total"])) for item in categories)
    conn = get_db_connection(); cursor = conn.cursor(dictionary=True)
    cursor.execute("""SELECT e.split_type, COUNT(*) AS expense_count, SUM(e.amount) AS total
        FROM expenses e JOIN group_members gm ON gm.group_id=e.group_id
        WHERE gm.user_id=%s GROUP BY e.split_type ORDER BY total DESC""", (session["user_id"],))
    split_methods = cursor.fetchall()
    cursor.execute("""SELECT DATE_FORMAT(e.created_at, '%%b') AS month_label,
        DATE_FORMAT(e.created_at, '%%Y-%%m') AS month_key, SUM(e.amount) AS total
        FROM expenses e JOIN group_members gm ON gm.group_id=e.group_id
        WHERE gm.user_id=%s AND e.created_at >= DATE_SUB(CURDATE(), INTERVAL 6 MONTH)
        GROUP BY month_key, month_label ORDER BY month_key""", (session["user_id"],))
    monthly = cursor.fetchall()
    cursor.execute("""SELECT DATE_FORMAT(e.created_at, '%%Y-%%m-%%d') AS day,
        SUM(e.amount) AS total FROM expenses e JOIN group_members gm ON gm.group_id=e.group_id
        WHERE gm.user_id=%s AND e.created_at >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
        GROUP BY day ORDER BY day""", (session["user_id"],))
    daily = cursor.fetchall(); cursor.close(); conn.close()
    return render_template("insights.html", categories=categories, groups_spend=groups_spend, total=total,
                           monthly=monthly, daily=daily, split_methods=split_methods)


@app.route("/set-handle", methods=["GET", "POST"])
@login_required
def set_handle():
    if request.method == "POST":
        handle = request.form.get("handle", "").strip().lower().replace("@", "")

        if not re.fullmatch(r"[a-z0-9_]{3,30}", handle):
            flash(
                "ID must use 3 to 30 lowercase letters, numbers, or underscores.",
                "error"
            )
            return redirect(url_for("set_handle"))

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id FROM users WHERE handle = %s AND id != %s",
            (handle, session["user_id"])
        )

        if cursor.fetchone():
            cursor.close()
            conn.close()

            flash("That ID is already taken. Try another one.", "error")
            return redirect(url_for("set_handle"))

        cursor.execute(
            "UPDATE users SET handle = %s WHERE id = %s",
            (handle, session["user_id"])
        )

        conn.commit()
        cursor.close()
        conn.close()

        flash("Your EvenUp ID is @" + handle, "success")
        return redirect(url_for("dashboard"))

    return render_template("set_handle.html")





@app.route("/api/user/<handle>")
@login_required
def find_user(handle):
    handle = handle.strip().lower().replace("@", "")

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute(
        """
        SELECT id, name, handle, avatar_url
        FROM users
        WHERE handle = %s
        """,
        (handle,)
    )

    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if not user:
        return {"found": False}, 404

    avatar = user["avatar_url"]

    if not avatar:
        avatar = (
            "https://api.dicebear.com/9.x/initials/svg?seed="
            + user["handle"]
            + "&backgroundColor=d9fb77"
        )

    return {
        "found": True,
        "name": user["name"],
        "handle": user["handle"],
        "avatar": avatar
    }


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute(
        """
        SELECT name, email, handle, gender, bio, avatar_url
        FROM users
        WHERE id = %s
        """,
        (session["user_id"],)
    )

    user = cursor.fetchone()

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        gender = request.form.get("gender", "").strip()
        bio = request.form.get("bio", "").strip()

        avatar_url = (
            request.form.get("avatar_url", "").strip()
            or user["avatar_url"]
        )

        uploaded_file = request.files.get("avatar_file")

        if uploaded_file and uploaded_file.filename:
            if not allowed_image(uploaded_file.filename):
                cursor.close()
                conn.close()

                flash(
                    "Use PNG, JPG, JPEG, GIF, or WEBP images only.",
                    "error"
                )
                return redirect(url_for("profile"))

            extension = uploaded_file.filename.rsplit(".", 1)[1].lower()
            filename = uuid.uuid4().hex + "." + extension

            uploaded_file.save(
                os.path.join(app.config["UPLOAD_FOLDER"], filename)
            )

            avatar_url = url_for(
                "static",
                filename="uploads/" + filename
            )

        if not name or not email:
            cursor.close()
            conn.close()

            flash("Name and email are required.", "error")
            return redirect(url_for("profile"))

        cursor.execute(
            """
            SELECT id FROM users
            WHERE email = %s AND id != %s
            """,
            (email, session["user_id"])
        )

        if cursor.fetchone():
            cursor.close()
            conn.close()

            flash(
                "That email address already belongs to another account.",
                "error"
            )
            return redirect(url_for("profile"))

        cursor.execute(
            """
            UPDATE users
            SET
                name = %s,
                email = %s,
                gender = %s,
                bio = %s,
                avatar_url = %s
            WHERE id = %s
            """,
            (
                name,
                email,
                gender,
                bio,
                avatar_url,
                session["user_id"]
            )
        )

        conn.commit()

        cursor.close()
        conn.close()

        session["user_name"] = name

        flash("Profile updated successfully.", "success")
        return redirect(url_for("dashboard"))

    cursor.close()
    conn.close()

    return render_template("profile.html", user=user)

def get_group_for_user(cursor, group_id, user_id):
    cursor.execute(
        """
        SELECT g.*
        FROM groups_tbl g
        INNER JOIN group_members gm ON gm.group_id = g.id
        WHERE g.id = %s AND gm.user_id = %s
        """,
        (group_id, user_id)
    )

    return cursor.fetchone()


def calculate_settlements(member_balances):
    creditors = []
    debtors = []

    for member in member_balances:
        balance = Decimal(str(member["balance"]))

        if balance > Decimal("0.01"):
            creditors.append({
                "name": member["name"],
                "handle": member["handle"],
                "amount": balance
            })

        elif balance < Decimal("-0.01"):
            debtors.append({
                "name": member["name"],
                "handle": member["handle"],
                "amount": abs(balance)
            })

    settlements = []
    creditor_index = 0
    debtor_index = 0

    while creditor_index < len(creditors) and debtor_index < len(debtors):
        creditor = creditors[creditor_index]
        debtor = debtors[debtor_index]

        amount = min(creditor["amount"], debtor["amount"])

        settlements.append({
            "from_name": debtor["name"],
            "from_handle": debtor["handle"],
            "to_name": creditor["name"],
            "to_handle": creditor["handle"],
            "amount": amount
        })

        creditor["amount"] -= amount
        debtor["amount"] -= amount

        if creditor["amount"] <= Decimal("0.01"):
            creditor_index += 1

        if debtor["amount"] <= Decimal("0.01"):
            debtor_index += 1

    return settlements


@app.route("/create-group", methods=["GET", "POST"])
@login_required
def create_group():
    if request.method == "POST":
        group_name = request.form.get("group_name", "").strip()
        group_type = request.form.get("group_type", "Other").strip()
        currency = request.form.get("currency", "EUR").strip()
        description = request.form.get("description", "").strip()

        if not group_name:
            flash("Enter a group name.", "error")
            return redirect(url_for("create_group"))

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO groups_tbl (
                name,
                group_type,
                currency,
                description,
                created_by
            )
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                group_name,
                group_type,
                currency,
                description,
                session["user_id"]
            )
        )

        conn.commit()

        group_id = cursor.lastrowid

        cursor.execute(
            """
            INSERT INTO group_members (group_id, user_id)
            VALUES (%s, %s)
            """,
            (group_id, session["user_id"])
        )

        conn.commit()
        cursor.close()
        conn.close()

        flash("Group created successfully.", "success")

        return redirect(
            url_for("group_detail", group_id=group_id)
        )

    return render_template("create_group.html")


@app.route("/groups/<int:group_id>")
@login_required
def group_detail(group_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    group = get_group_for_user(
        cursor,
        group_id,
        session["user_id"]
    )

    if not group:
        cursor.close()
        conn.close()

        flash("You do not have access to that group.", "error")
        return redirect(url_for("groups"))

    cursor.execute(
        """
        SELECT
            u.id,
            u.name,
            u.email,
            u.handle,
            u.avatar_url,
            CASE
                WHEN u.id = %s THEN 'OWNER'
                ELSE 'MEMBER'
            END AS role
        FROM users u
        INNER JOIN group_members gm ON gm.user_id = u.id
        WHERE gm.group_id = %s
        ORDER BY u.id = %s DESC, u.name ASC
        """,
        (
            group["created_by"],
            group_id,
            group["created_by"]
        )
    )

    members = cursor.fetchall()

    cursor.execute(
        """
        SELECT
            e.id,
            e.paid_by,
            e.description,
            e.amount,
            e.category,
            e.split_type,
            e.receipt_path,
            e.created_at,
            u.name AS payer_name,
            u.handle AS payer_handle
        FROM expenses e
        INNER JOIN users u ON u.id = e.paid_by
        WHERE e.group_id = %s
        ORDER BY e.created_at DESC
        LIMIT 8
        """,
        (group_id,)
    )

    expenses = cursor.fetchall()

    cursor.execute(
        """
        SELECT
            m.id,
            m.message,
            m.created_at,
            u.name,
            u.handle,
            u.avatar_url
        FROM group_messages m
        INNER JOIN users u ON u.id = m.user_id
        WHERE m.group_id = %s
        ORDER BY m.created_at ASC
        """,
        (group_id,)
    )

    messages = cursor.fetchall()

    cursor.execute(
        """
        SELECT
            u.id,
            u.name,
            u.handle,
            u.avatar_url,
            COALESCE(paid.total_paid, 0) AS total_paid,
            COALESCE(shared.total_share, 0) AS total_share
        FROM group_members gm
        INNER JOIN users u ON u.id = gm.user_id

        LEFT JOIN (
            SELECT
                paid_by,
                SUM(amount) AS total_paid
            FROM expenses
            WHERE group_id = %s
            GROUP BY paid_by
        ) paid ON paid.paid_by = u.id

        LEFT JOIN (
            SELECT
                es.user_id,
                SUM(es.share_amount) AS total_share
            FROM expense_shares es
            INNER JOIN expenses e ON e.id = es.expense_id
            WHERE e.group_id = %s
            GROUP BY es.user_id
        ) shared ON shared.user_id = u.id

        WHERE gm.group_id = %s
        ORDER BY u.name ASC
        """,
        (group_id, group_id, group_id)
    )

    balances = cursor.fetchall()

    for member in balances:
        member["total_paid"] = Decimal(str(member["total_paid"]))
        member["total_share"] = Decimal(str(member["total_share"]))
        member["balance"] = member["total_paid"] - member["total_share"]

    cursor.execute(
        """
        SELECT
            s.id,
            s.amount,
            s.created_at,
            sender.id AS from_user_id,
            sender.name AS from_name,
            sender.handle AS from_handle,
            receiver.id AS to_user_id,
            receiver.name AS to_name,
            receiver.handle AS to_handle
        FROM settlements s
        INNER JOIN users sender ON sender.id = s.from_user_id
        INNER JOIN users receiver ON receiver.id = s.to_user_id
        WHERE s.group_id = %s
        ORDER BY s.created_at DESC
        """,
        (group_id,)
    )

    settlement_history = cursor.fetchall()

    for payment in settlement_history:
        for member in balances:
            if member["id"] == payment["from_user_id"]:
                member["balance"] += Decimal(str(payment["amount"]))

            if member["id"] == payment["to_user_id"]:
                member["balance"] -= Decimal(str(payment["amount"]))

    settlements = calculate_settlements(balances)

    cursor.close()
    conn.close()

    return render_template(
        "group_detail.html",
        group=group,
        members=members,
        expenses=expenses,
        messages=messages,
        balances=balances,
        settlements=settlements,
        settlement_history=settlement_history
    )


def get_group_owner(cursor, group_id, user_id):
    cursor.execute(
        "SELECT * FROM groups_tbl WHERE id = %s AND created_by = %s",
        (group_id, user_id)
    )
    return cursor.fetchone()


@app.route("/groups/actions", methods=["POST"])
@login_required
def group_actions():
    group_id = request.form.get("group_id", type=int)
    action = request.form.get("action", "").strip()

    if not group_id:
        flash("Select a group first.", "error")
        return redirect(url_for("groups"))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    group = get_group_owner(cursor, group_id, session["user_id"])

    if not group:
        cursor.close()
        conn.close()
        flash("Only the group owner can manage this group.", "error")
        return redirect(url_for("groups"))

    if action == "edit":
        cursor.close()
        conn.close()
        return redirect(url_for("edit_group", group_id=group_id))

    if action == "delete":
        # Existing databases may not have ON DELETE CASCADE on every relationship,
        # so remove dependent records explicitly in foreign-key-safe order.
        cursor.execute("DELETE FROM settlements WHERE group_id = %s", (group_id,))
        cursor.execute(
            """DELETE es FROM expense_shares es
               INNER JOIN expenses e ON e.id = es.expense_id
               WHERE e.group_id = %s""",
            (group_id,)
        )
        cursor.execute("DELETE FROM group_messages WHERE group_id = %s", (group_id,))
        cursor.execute("DELETE FROM expenses WHERE group_id = %s", (group_id,))
        cursor.execute("DELETE FROM group_members WHERE group_id = %s", (group_id,))
        cursor.execute("DELETE FROM groups_tbl WHERE id = %s", (group_id,))
        conn.commit()
        cursor.close()
        conn.close()
        flash("Group deleted successfully.", "success")
        return redirect(url_for("groups"))

    cursor.close()
    conn.close()
    flash("Choose a valid group action.", "error")
    return redirect(url_for("groups"))


@app.route("/groups/<int:group_id>/edit", methods=["GET", "POST"])
@login_required
def edit_group(group_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    group = get_group_owner(cursor, group_id, session["user_id"])

    if not group:
        cursor.close()
        conn.close()
        flash("Only the group owner can edit this group.", "error")
        return redirect(url_for("groups"))

    if request.method == "POST":
        name = request.form.get("group_name", "").strip()
        group_type = request.form.get("group_type", "Other").strip()
        currency = request.form.get("currency", "INR").strip().upper()
        description = request.form.get("description", "").strip()

        if not name:
            cursor.close()
            conn.close()
            flash("Enter a group name.", "error")
            return redirect(url_for("edit_group", group_id=group_id))

        cursor.execute(
            """UPDATE groups_tbl
               SET name=%s, group_type=%s, currency=%s, description=%s
               WHERE id=%s AND created_by=%s""",
            (name, group_type, currency[:3], description, group_id, session["user_id"])
        )
        conn.commit()
        cursor.close()
        conn.close()
        flash("Group details updated.", "success")
        return redirect(url_for("group_detail", group_id=group_id))

    cursor.close()
    conn.close()
    return render_template("edit_group.html", group=group)


@app.route("/groups/<int:group_id>/remove-member/<int:user_id>", methods=["POST"])
@login_required
def remove_group_member(group_id, user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    group = get_group_owner(cursor, group_id, session["user_id"])

    if not group:
        cursor.close()
        conn.close()
        flash("Only the group owner can remove members.", "error")
        return redirect(url_for("group_detail", group_id=group_id))

    if user_id == group["created_by"]:
        cursor.close()
        conn.close()
        flash("The group owner cannot be removed.", "error")
        return redirect(url_for("group_detail", group_id=group_id))

    cursor.execute(
        "DELETE FROM group_members WHERE group_id=%s AND user_id=%s",
        (group_id, user_id)
    )
    conn.commit()
    cursor.close()
    conn.close()
    flash("Member removed from the group.", "success")
    return redirect(url_for("group_detail", group_id=group_id))


def can_manage_expense(cursor, group_id, expense_id, user_id):
    cursor.execute(
        """SELECT e.*, g.created_by FROM expenses e
           INNER JOIN groups_tbl g ON g.id=e.group_id
           INNER JOIN group_members gm ON gm.group_id=e.group_id
           WHERE e.id=%s AND e.group_id=%s AND gm.user_id=%s""",
        (expense_id, group_id, user_id)
    )
    expense = cursor.fetchone()
    return expense and (expense["created_by"] == user_id or expense["paid_by"] == user_id)


@app.route("/groups/<int:group_id>/expenses/<int:expense_id>/edit", methods=["POST"])
@login_required
def edit_expense(group_id, expense_id):
    description = request.form.get("description", "").strip()
    category = request.form.get("category", "Other").strip()
    amount_text = request.form.get("amount", "").strip()

    try:
        amount = Decimal(amount_text)
        if amount <= 0 or not description:
            raise InvalidOperation
    except (InvalidOperation, ValueError):
        flash("Enter a valid description and expense amount.", "error")
        return redirect(url_for("group_detail", group_id=group_id))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    expense = can_manage_expense(cursor, group_id, expense_id, session["user_id"])

    if not expense:
        cursor.close()
        conn.close()
        flash("You do not have permission to edit this expense.", "error")
        return redirect(url_for("group_detail", group_id=group_id))

    cursor.execute(
        "UPDATE expenses SET description=%s, amount=%s, category=%s WHERE id=%s AND group_id=%s",
        (description, amount, category, expense_id, group_id)
    )

    cursor.execute("SELECT user_id FROM expense_shares WHERE expense_id=%s ORDER BY user_id", (expense_id,))
    share_users = [row["user_id"] for row in cursor.fetchall()]
    if share_users:
        share = (amount / len(share_users)).quantize(Decimal("0.01"))
        remaining = amount
        for index, share_user_id in enumerate(share_users):
            current_share = remaining if index == len(share_users) - 1 else share
            remaining -= current_share
            cursor.execute(
                "UPDATE expense_shares SET share_amount=%s WHERE expense_id=%s AND user_id=%s",
                (current_share, expense_id, share_user_id)
            )

    conn.commit()
    cursor.close()
    conn.close()
    flash("Expense updated and balances recalculated.", "success")
    return redirect(url_for("group_detail", group_id=group_id))


@app.route("/groups/<int:group_id>/expenses/<int:expense_id>/delete", methods=["POST"])
@login_required
def delete_expense(group_id, expense_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    expense = can_manage_expense(cursor, group_id, expense_id, session["user_id"])

    if not expense:
        cursor.close()
        conn.close()
        flash("You do not have permission to delete this expense.", "error")
        return redirect(url_for("group_detail", group_id=group_id))

    cursor.execute("DELETE FROM expenses WHERE id=%s AND group_id=%s", (expense_id, group_id))
    conn.commit()
    cursor.close()
    conn.close()
    flash("Expense deleted.", "success")
    return redirect(url_for("group_detail", group_id=group_id))



@app.route("/groups/<int:group_id>/add-member", methods=["POST"])
@login_required
def add_group_member(group_id):
    handle = request.form.get("handle", "").strip().lower().replace("@", "")

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute(
        """
        SELECT id
        FROM groups_tbl
        WHERE id = %s AND created_by = %s
        """,
        (group_id, session["user_id"])
    )

    group = cursor.fetchone()

    if not group:
        cursor.close()
        conn.close()

        flash("Only the group owner can add members.", "error")
        return redirect(url_for("group_detail", group_id=group_id))

    cursor.execute(
        "SELECT id FROM users WHERE handle = %s",
        (handle,)
    )

    friend = cursor.fetchone()

    if not friend:
        cursor.close()
        conn.close()

        flash("No user was found with that EvenUp ID.", "error")
        return redirect(url_for("group_detail", group_id=group_id))

    cursor.execute(
        """
        SELECT user_id
        FROM group_members
        WHERE group_id = %s AND user_id = %s
        """,
        (group_id, friend["id"])
    )

    if cursor.fetchone():
        cursor.close()
        conn.close()

        flash("That user is already in this group.", "error")
        return redirect(url_for("group_detail", group_id=group_id))

    cursor.execute(
        """
        SELECT COUNT(*) AS total
        FROM group_members
        WHERE group_id = %s
        """,
        (group_id,)
    )

    member_count = cursor.fetchone()

    if member_count["total"] >= 20:
        cursor.close()
        conn.close()

        flash("A group can contain a maximum of 20 people.", "error")
        return redirect(url_for("group_detail", group_id=group_id))

    cursor.execute(
        """
        INSERT INTO group_members (group_id, user_id)
        VALUES (%s, %s)
        """,
        (group_id, friend["id"])
    )

    conn.commit()

    cursor.close()
    conn.close()

    flash("@" + handle + " was added to the group.", "success")
    return redirect(url_for("group_detail", group_id=group_id))


@app.route("/groups/<int:group_id>/add-expense", methods=["POST"])
@login_required
def add_expense(group_id):
    import json

    description = request.form.get("description", "").strip()
    category = request.form.get("category", "Other").strip() or "Other"
    paid_by = request.form.get("paid_by", type=int) or session["user_id"]
    split_type = request.form.get("split_type", "equal")
    if split_type not in {"equal", "selected", "custom"}:
        split_type = "equal"
    selected_members = request.form.getlist("split_members", type=int)
    items = []
    receipt_path = None

    if not description:
        flash("Enter an expense title.", "error")
        return redirect(url_for("group_detail", group_id=group_id))

    try:
        amount_field = "amount" if split_type == "custom" else "simple_amount"
        amount = Decimal((request.form.get(amount_field) or "0").strip() or "0")
        extra_amount = Decimal(request.form.get("extra_amount", "0").strip() or "0")
        if amount < 0 or extra_amount < 0:
            raise InvalidOperation
    except (InvalidOperation, ValueError):
        flash("Enter valid expense, tax, and tip amounts.", "error")
        return redirect(url_for("group_detail", group_id=group_id))

    if split_type == "custom":
        try:
            raw_items = json.loads(request.form.get("items_json", "[]"))
            for raw in raw_items:
                item_name = str(raw.get("name", "")).strip()
                item_amount = Decimal(str(raw.get("amount", "0")))
                assignees = [int(value) for value in raw.get("members", [])]
                if not item_name or item_amount <= 0 or not assignees:
                    raise InvalidOperation
                items.append({"name": item_name, "amount": item_amount, "members": assignees})
        except (ValueError, TypeError, InvalidOperation, json.JSONDecodeError):
            flash("Add at least one valid item and assign it to a member.", "error")
            return redirect(url_for("group_detail", group_id=group_id))

        subtotal = sum((item["amount"] for item in items), Decimal("0"))
        calculated_total = subtotal + extra_amount
        if calculated_total <= 0:
            flash("Custom expenses must contain at least one item.", "error")
            return redirect(url_for("group_detail", group_id=group_id))
        amount = calculated_total

    if amount <= 0:
        flash("Enter an expense amount greater than zero.", "error")
        return redirect(url_for("group_detail", group_id=group_id))

    uploaded_receipt = request.files.get("receipt_file")
    if uploaded_receipt and uploaded_receipt.filename:
        if not allowed_image(uploaded_receipt.filename):
            flash("Receipt must be a PNG, JPG, JPEG, GIF, or WEBP image.", "error")
            return redirect(url_for("group_detail", group_id=group_id))
        extension = uploaded_receipt.filename.rsplit(".", 1)[1].lower()
        filename = uuid.uuid4().hex + "." + extension
        uploaded_receipt.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
        receipt_path = url_for("static", filename="uploads/" + filename)

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    group = get_group_for_user(cursor, group_id, session["user_id"])

    if not group:
        cursor.close()
        conn.close()
        flash("You do not have access to that group.", "error")
        return redirect(url_for("groups"))

    cursor.execute("SELECT user_id FROM group_members WHERE group_id = %s", (group_id,))
    member_ids = {row["user_id"] for row in cursor.fetchall()}
    if paid_by not in member_ids:
        cursor.close()
        conn.close()
        flash("The payer must be a group member.", "error")
        return redirect(url_for("group_detail", group_id=group_id))

    if split_type == "custom":
        for item in items:
            item["members"] = list(dict.fromkeys(member_id for member_id in item["members"] if member_id in member_ids))
            if not item["members"]:
                cursor.close()
                conn.close()
                flash("Every item must be assigned to at least one group member.", "error")
                return redirect(url_for("group_detail", group_id=group_id))
        share_amounts = {}
        subtotal = sum((item["amount"] for item in items), Decimal("0"))
        for item in items:
            item_share = (item["amount"] / len(item["members"])).quantize(Decimal("0.01"))
            remaining_item = item["amount"]
            for index, member_id in enumerate(item["members"]):
                current_share = remaining_item if index == len(item["members"]) - 1 else item_share
                remaining_item -= current_share
                share_amounts[member_id] = share_amounts.get(member_id, Decimal("0")) + current_share
        if extra_amount and subtotal:
            allocated = Decimal("0")
            members_with_shares = list(share_amounts)
            for index, member_id in enumerate(members_with_shares):
                extra_share = extra_amount - allocated if index == len(members_with_shares) - 1 else (extra_amount * share_amounts[member_id] / subtotal).quantize(Decimal("0.01"))
                share_amounts[member_id] += extra_share
                allocated += extra_share
    else:
        share_members = [member_id for member_id in selected_members if member_id in member_ids] if split_type == "selected" else list(member_ids)
        if not share_members:
            cursor.close()
            conn.close()
            flash("Choose at least one person to split this expense with.", "error")
            return redirect(url_for("group_detail", group_id=group_id))
        share_amount = (amount / len(share_members)).quantize(Decimal("0.01"))
        share_amounts = {}
        remaining = amount
        for index, member_id in enumerate(share_members):
            current_share = remaining if index == len(share_members) - 1 else share_amount
            remaining -= current_share
            share_amounts[member_id] = current_share

    cursor.execute(
        """INSERT INTO expenses (group_id, paid_by, description, amount, category, split_type, receipt_path)
           VALUES (%s, %s, %s, %s, %s, %s, %s)""",
        (group_id, paid_by, description or "Itemized receipt", amount, category, split_type, receipt_path)
    )
    expense_id = cursor.lastrowid

    for member_id, share in share_amounts.items():
        cursor.execute(
            "INSERT INTO expense_shares (expense_id, user_id, share_amount) VALUES (%s, %s, %s)",
            (expense_id, member_id, share)
        )

    for item in items:
        cursor.execute(
            "INSERT INTO expense_items (expense_id, item_name, amount) VALUES (%s, %s, %s)",
            (expense_id, item["name"], item["amount"])
        )
        item_id = cursor.lastrowid
        item_share = (item["amount"] / len(item["members"])).quantize(Decimal("0.01"))
        remaining_item = item["amount"]
        for index, member_id in enumerate(item["members"]):
            current_share = remaining_item if index == len(item["members"]) - 1 else item_share
            remaining_item -= current_share
            cursor.execute(
                "INSERT INTO expense_item_shares (item_id, user_id, amount) VALUES (%s, %s, %s)",
                (item_id, member_id, current_share)
            )

    conn.commit()
    cursor.close()
    conn.close()
    flash("Expense added and split successfully.", "success")
    return redirect(url_for("group_detail", group_id=group_id))


@app.route("/groups/<int:group_id>/messages", methods=["POST"])
@login_required
def add_message(group_id):
    message = request.form.get("message", "").strip()

    if not message:
        return redirect(url_for("group_detail", group_id=group_id))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    group = get_group_for_user(
        cursor,
        group_id,
        session["user_id"]
    )

    if not group:
        cursor.close()
        conn.close()

        flash("You do not have access to that group.", "error")
        return redirect(url_for("groups"))

    cursor.execute(
        """
        INSERT INTO group_messages (
            group_id,
            user_id,
            message
        )
        VALUES (%s, %s, %s)
        """,
        (
            group_id,
            session["user_id"],
            message[:500]
        )
    )

    conn.commit()

    cursor.close()
    conn.close()

    return redirect(url_for("group_detail", group_id=group_id))

@app.route("/groups/<int:group_id>/settle", methods=["POST"])
@login_required
def settle_payment(group_id):
    to_user_id = request.form.get("to_user_id", type=int)
    amount_text = request.form.get("amount", "").strip()

    try:
        amount = Decimal(amount_text)

        if amount <= 0:
            raise InvalidOperation

    except (InvalidOperation, ValueError):
        flash("Enter a valid settlement amount.", "error")
        return redirect(url_for("group_detail", group_id=group_id))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    group = get_group_for_user(
        cursor,
        group_id,
        session["user_id"]
    )

    if not group:
        cursor.close()
        conn.close()

        flash("You do not have access to that group.", "error")
        return redirect(url_for("groups"))

    cursor.execute(
        """
        SELECT user_id
        FROM group_members
        WHERE group_id = %s AND user_id = %s
        """,
        (group_id, to_user_id)
    )

    receiver = cursor.fetchone()

    if not receiver:
        cursor.close()
        conn.close()

        flash("That person is not a member of this group.", "error")
        return redirect(url_for("group_detail", group_id=group_id))

    if to_user_id == session["user_id"]:
        cursor.close()
        conn.close()

        flash("You cannot settle a payment with yourself.", "error")
        return redirect(url_for("group_detail", group_id=group_id))

    cursor.execute(
        """
        INSERT INTO settlements (
            group_id,
            from_user_id,
            to_user_id,
            amount
        )
        VALUES (%s, %s, %s, %s)
        """,
        (
            group_id,
            session["user_id"],
            to_user_id,
            amount
        )
    )

    conn.commit()

    cursor.close()
    conn.close()

    flash("Settlement recorded successfully.", "success")

    return redirect(url_for("group_detail", group_id=group_id))


if __name__ == "__main__":
    app.run(debug=True)
