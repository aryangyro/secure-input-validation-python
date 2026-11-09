"""Tests for secure_input.py - run: python3 test_input.py"""
import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from secure_input import (make_db, sanitize_comment, secure_lookup,
                          valid_email, valid_filename, valid_path,
                          vulnerable_lookup)

passed = failed = 0


def check(name, got, want):
    global passed, failed
    if got == want:
        passed += 1
        print(f"PASS: {name}")
    else:
        failed += 1
        print(f"FAIL: {name} - got {got!r}, want {want!r}")


# 4.1 (A) email
check("email valid", valid_email("alice@hospital.com"), True)
check("email valid .org", valid_email("bob@clinic.org"), True)
check("email rejects script", valid_email("bad<script>@x.com"), False)
check("email rejects no @", valid_email("no-at-sign"), False)
check("email rejects bad domain", valid_email("carol@.com"), False)
check("email rejects no TLD", valid_email("dave@hospital"), False)

# 4.1 (B) filename
check("filename valid", valid_filename("report.pdf"), True)
check("filename valid _", valid_filename("patient_01.txt"), True)
check("filename rejects traversal", valid_filename("../etc/passwd"), False)
check("filename rejects hidden", valid_filename(".env"), False)
check("filename rejects space", valid_filename("my file.txt"), False)

# 4.1 (C) path
check("path allows safe file", valid_path("report.pdf"), True)
check("path allows subdir", valid_path("notes/data.txt"), True)
check("path blocks ../", valid_path("../secret.txt"), False)
check("path blocks ../../", valid_path("../../etc/passwd"), False)
check("path allows normalized safe", valid_path("a/b/../../safe.txt"), True)

# 4.2 SQL injection
db = make_db()
check("vuln normal lookup", vulnerable_lookup(db, "alice"),
      [("alice", "doctor")])
check("vuln injection returns all 3",
      len(vulnerable_lookup(db, "' OR '1'='1")), 3)
check("secure normal lookup", secure_lookup(db, "alice"),
      [("alice", "doctor")])
check("secure blocks injection", secure_lookup(db, "' OR '1'='1"), [])

# 4.3 XSS
check("xss escaped", sanitize_comment("<script>alert('Hacked')</script>"),
      "&lt;script&gt;alert(&#x27;Hacked&#x27;)&lt;/script&gt;")
check("xss plain text unchanged", sanitize_comment("hello"), "hello")
check("xss no raw script left",
      "<script>" in sanitize_comment("<script>alert('Hacked')</script>"),
      False)

# 4.4 format string
from secure_input import safe_format, unsafe_format
check("safe format keeps %s literal",
      safe_format("Balance: %s, code: %d"), "Balance: %s, code: %d")
check("unsafe format leaks args",
      unsafe_format("Balance: %s, code: %d"), "Balance: SECRET, code: 12345")

# 4.5 randomness
t1, t2 = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
check("tokens unique", t1 != t2, True)
check("token length >= 32", len(t1) >= 32, True)
vals = [secrets.randbelow(100) for _ in range(1000)]
buckets = [sum(1 for v in vals if i * 10 <= v < i * 10 + 10)
           for i in range(10)]
check("1000 values in range", min(vals) >= 0 and max(vals) <= 99, True)
check("distribution roughly uniform (each bucket 60-140)",
      all(60 <= b <= 140 for b in buckets), True)

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
