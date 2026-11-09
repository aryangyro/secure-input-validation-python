"""Secure Input Processing Module
Validates input, stops SQL injection and XSS, and uses secure randomness.
Demo users are fake (alice, bob, carol) with placeholder passwords.
Run:  python3 secure_input.py            (demo)
       python3 secure_input.py --interactive
"""
import html
import os
import random
import re
import secrets
import sqlite3

BASE_DIR = os.path.abspath("safe_files")

# ---------------------------------------------------------------- 4.1 (A)
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


def valid_email(email):
    """True only for username@domain.com style addresses."""
    if not isinstance(email, str) or "<" in email or ">" in email:
        return False                      # embedded script / tag: reject
    if not EMAIL_RE.match(email):
        return False
    domain = email.rsplit("@", 1)[1]
    if domain.startswith((".", "-")) or ".." in domain or domain.endswith("."):
        return False                      # invalid domain
    return True


# ---------------------------------------------------------------- 4.1 (B)
NAME_RE = re.compile(r"^[A-Za-z0-9_.]+$")


def valid_filename(name):
    """Only letters, digits, _ and . ; no traversal, no hidden files."""
    if not name or name.startswith("."):
        return False                      # hidden file like .env
    if ".." in name or "/" in name or "\\" in name:
        return False                      # path traversal
    return bool(NAME_RE.match(name))


# ---------------------------------------------------------------- 4.1 (C)
def valid_path(user_path):
    """Normalize the path and keep it inside the safe base directory."""
    full = os.path.normpath(os.path.join(BASE_DIR, user_path))
    if os.path.commonpath([BASE_DIR, full]) != BASE_DIR:
        return False                      # escapes the safe folder
    return True


def show_validation():
    print("=" * 60)
    print("4.1 (A) Email validation")
    print("=" * 60)
    for e in ["alice@hospital.com", "bob@clinic.org",
              "bad<script>@x.com", "no-at-sign", "carol@.com",
              "dave@hospital"]:
        print(f"  {e:28} -> {'VALID' if valid_email(e) else 'REJECTED'}")
    print("=" * 60)
    print("4.1 (B) Filename validation")
    print("=" * 60)
    for f in ["report.pdf", "patient_01.txt", "../etc/passwd",
              ".env", "my file.txt", "data.csv"]:
        print(f"  {f:28} -> {'VALID' if valid_filename(f) else 'REJECTED'}")
    print("=" * 60)
    print("4.1 (C) File path validation  (base: safe_files/)")
    print("=" * 60)
    for p in ["report.pdf", "notes/data.txt", "../secret.txt",
              "../../etc/passwd", "a/b/../../safe.txt"]:
        print(f"  {p:28} -> {'ALLOWED' if valid_path(p) else 'BLOCKED'}")


# ---------------------------------------------------------------- 4.2
def make_db():
    """Small SQLite database with three demo users."""
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE users (username TEXT, role TEXT)")
    db.executemany("INSERT INTO users VALUES (?, ?)",
                   [("alice", "doctor"), ("bob", "nurse"), ("carol", "admin")])
    return db


def vulnerable_lookup(db, user_input):
    """UNSAFE: user input glued straight into the SQL string."""
    query = "SELECT * FROM users WHERE username = '" + user_input + "'"
    return db.execute(query).fetchall()


def secure_lookup(db, user_input):
    """SAFE: parameterized query, input is data, never code."""
    query = "SELECT * FROM users WHERE username = ?"
    return db.execute(query, (user_input,)).fetchall()


def show_sql_injection():
    print("=" * 60)
    print("4.2 SQL Injection Prevention")
    print("=" * 60)
    db = make_db()
    attack = "' OR '1'='1"
    print(f"Attacker input: {attack}")
    print("Vulnerable query:")
    print("  SELECT * FROM users WHERE username = '" + attack + "'")
    rows = vulnerable_lookup(db, attack)
    print(f"  -> returned {len(rows)} rows (ALL users!): {rows}")
    print("Secure query:")
    print("  SELECT * FROM users WHERE username = ?")
    rows = secure_lookup(db, attack)
    print(f"  -> returned {len(rows)} rows: {rows}  (attack blocked)")
    print("Normal lookup 'alice' (secure):",
          secure_lookup(db, "alice"))


# ---------------------------------------------------------------- 4.3
def sanitize_comment(comment):
    """Output encoding: turn < > & into harmless text."""
    return html.escape(comment)


def show_xss():
    print("=" * 60)
    print("4.3 XSS Prevention")
    print("=" * 60)
    comment = "<script>alert('Hacked')</script> Nice portal!"
    print(f"User comment (raw):     {comment}")
    print(f"After html.escape():    {sanitize_comment(comment)}")
    print("The browser now shows the text instead of running it.")


# ---------------------------------------------------------------- 4.4
def unsafe_format(user_input):
    """UNSAFE: user input used as the format string itself."""
    try:
        return user_input % ("SECRET", 12345)
    except Exception as e:
        return f"CRASH / leak attempt: {type(e).__name__}: {e}"


def safe_format(user_input):
    """SAFE: fixed format string, input is only data (%s)."""
    return "%s" % user_input


def show_buffer_overflow():
    print("=" * 60)
    print("4.4 Formatting & Buffer Overflow Awareness")
    print("=" * 60)
    evil = "Balance: %s, code: %d"
    print(f"User input: {evil!r}")
    print(f"  Unsafe  printf(user_input): {unsafe_format(evil)}")
    print(f"  Safe    printf(\"%s\", input): {safe_format(evil)}")
    print("In C, printf(user_input) lets %s/%x read stack memory and")
    print("long input can overflow a fixed buffer and hijack control flow.")


# ---------------------------------------------------------------- 4.5
def show_randomness():
    print("=" * 60)
    print("4.5 Secure Random Number Generation")
    print("=" * 60)
    random.seed(42)                       # insecure: fixed seed = predictable
    print("Insecure random.randint(1,100), seed 42:",
          [random.randint(1, 100) for _ in range(5)])
    random.seed(42)
    print("Same seed again, same numbers:      ",
          [random.randint(1, 100) for _ in range(5)])
    print("Secure secrets.randbelow(100):      ",
          [secrets.randbelow(100) for _ in range(5)])
    print("Secure secrets.randbelow(100):      ",
          [secrets.randbelow(100) for _ in range(5)])
    print("Session token:  ", secrets.token_urlsafe(24))
    print("Reset token:    ", secrets.token_urlsafe(24))
    print()
    print("Distribution of 1000 secrets.randbelow(100) values:")
    values = [secrets.randbelow(100) for _ in range(1000)]
    buckets = [0] * 10
    for v in values:
        buckets[v // 10] += 1
    for i, count in enumerate(buckets):
        bar = "#" * (count // 4)
        print(f"  {i*10:2}-{i*10+9:2}: {count:3} {bar}")
    print(f"  min={min(values)}, max={max(values)}, "
          f"expected ~100 per bucket -> roughly uniform")


# ---------------------------------------------------------------- demo
def demo():
    os.makedirs(BASE_DIR, exist_ok=True)
    show_validation()
    print()
    show_sql_injection()
    print()
    show_xss()
    print()
    show_buffer_overflow()
    print()
    show_randomness()
    print()
    print("Demo done.")


def interactive():
    os.makedirs(BASE_DIR, exist_ok=True)
    print("Secure Input Module - interactive mode")
    print("Commands: email | file | path | sql | xss | token | quit")
    db = make_db()
    while True:
        cmd = input("> ").strip().lower()
        if cmd in ("quit", "q", "exit"):
            print("Bye.")
            break
        elif cmd == "email":
            print("VALID" if valid_email(input("Email: ")) else "REJECTED")
        elif cmd == "file":
            print("VALID" if valid_filename(input("Filename: ")) else "REJECTED")
        elif cmd == "path":
            print("ALLOWED" if valid_path(input("Path: ")) else "BLOCKED")
        elif cmd == "sql":
            print("Secure lookup:", secure_lookup(db, input("Username: ")))
        elif cmd == "xss":
            print("Safe output:", sanitize_comment(input("Comment: ")))
        elif cmd == "token":
            print("Session token:", secrets.token_urlsafe(24))
        else:
            print("Unknown command. Try: email, file, path, sql, xss, token, quit")


if __name__ == "__main__":
    import sys
    if "--interactive" in sys.argv:
        interactive()
    else:
        demo()
