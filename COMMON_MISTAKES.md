# Common Mistakes in Input Validation

Mistakes I kept running into while building `secure_input.py`, and what
each one actually costs in a real system. Every example below is a real
bug pattern, not a made-up one.

## 1. Validating on the client and trusting it on the server

JavaScript checks in the browser are nice for the user, but anyone can
turn them off or send a request straight to your API with `curl`. The
server must check everything again. Client checks are a convenience,
server checks are the security.

## 2. Blocklisting instead of allowlisting

Trying to list every bad character (`<`, `>`, `'`, `;`, ...) always misses
one. It is much safer to say what is *allowed* — letters, digits and a
few safe symbols — and reject everything else. The code in this repo
validates usernames and emails this way.

## 3. Using string formatting to build SQL queries

```python
# Dangerous — the input becomes part of the query
query = f"SELECT * FROM users WHERE name = '{name}'"

# Safe — the input stays data, never code
cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
```

One quote character in the input is enough to break the first version.
Parameterized queries are the fix, and there is no shortcut around them.

## 4. Escaping output in some places and not others

Escaping a comment when it is shown on a page but not when it is shown
in an admin dashboard leaves the same hole open in a different place.
Escape at the point where data is *used*, every time, in every view.

## 5. Checking the file name but not the file path

`report.pdf` looks safe, but `../../etc/passwd` is also just a string.
Always check the full resolved path and make sure it stays inside the
folder you meant. This repo rejects paths that try to escape the base
directory.

## 6. Treating "looks random" as "is random"

`random.randint()` is fine for a game. It is not fine for a password
reset token or a session id, because its output can be predicted. Use
`secrets.token_hex()` for anything security-related. The difference is
one import, and it matters.

## 7. Showing the attacker which check failed

An error message like "username is correct but the password is wrong"
tells an attacker the username exists. Keep login errors generic:
"Invalid username or password." The same goes for validation errors —
do not leak which rule an input tripped over if that helps an attacker.

## How to use this file

Pick one mistake, find it in your own code (or in this repo's demo
functions), and fix it. Then write a test that proves it stays fixed.
