# Secure Input Validation in Python

A small, complete input processing module that shows how a web system
protects itself from the most common input attacks: bad data getting in,
SQL injection, cross-site scripting (XSS), format-string tricks, and
predictable random tokens.

It is built around a healthcare example — a web portal where doctors,
nurses and administrators look up patient records — but the ideas apply
to any system that takes input from users. Most real-world breaches start
with input that was not checked properly. This project shows, in working
code, what "checked properly" actually looks like.

If you are new to this, start at the top and read down. Every idea is
explained in plain English before the code that uses it.

## What this project does

- **Input validation:** checks emails, filenames and file paths before
  the system trusts them, and rejects anything suspicious.
- **SQL injection prevention:** shows a vulnerable query being attacked,
  then shows a parameterized query stopping the same attack cold.
- **XSS prevention:** takes a comment containing a `<script>` tag and
  neutralises it with `html.escape`, so the browser shows the text
  instead of running it.
- **Buffer overflow awareness:** demonstrates unsafe
  `printf(user_input)` versus safe `printf("%s", user_input)`, and
  explains why buffer overflows happen and why Python is safer but not
  immune.
- **Secure randomness:** compares `random` (predictable) with `secrets`
  (cryptographically secure), generates session and password-reset
  tokens, and analyses the distribution of 1,000 random values.
- **Entropy analysis:** explains what entropy is, why predictable
  randomness is dangerous, and how token prediction and session
  hijacking work.

## The files

| File | What it is |
| --- | --- |
| `secure_input.py` | The whole project, 236 lines. Validation, SQL injection demo, XSS, format-string demo, secure randomness, demo and interactive mode. |
| `test_input.py` | 29 automated tests for the project. Run it with `python3 test_input.py`. |
| `README.md` | This file. |
| `WORKLOG.md` | What was built on Nov 8, 2026, test results, and challenges. |
| `safe_files/` | Created when you run the program. The safe base directory for file paths. Ignored by git. |

## Quick start

You need Python 3. No libraries are required — everything uses the
standard library (`re`, `sqlite3`, `secrets`, `html`).

Run the demo — it walks through the whole flow by itself:

```bash
python3 secure_input.py
```

Or run it interactively, choosing what to test yourself:

```bash
python3 secure_input.py --interactive
```

Run the tests:

```bash
python3 test_input.py
```

### Demo users

The SQLite database in the demo has three fake users, with placeholder
roles — never use data like this for real:

| User | Role |
| --- | --- |
| alice | doctor |
| bob | nurse |
| carol | admin |

## Part 1: Input validation — never trust what a user types

The first rule of secure software is simple: **never trust user input**.
Every string that comes from outside the program — a form field, a file
name, a URL — is a potential attack. Validation means checking that input
against a strict rule *before* the program uses it, and rejecting anything
that does not fit.

There are two ways to validate: allow-listing and deny-listing. An
allow-list says "only these things are allowed" and rejects everything
else. A deny-list says "these specific bad things are banned" and allows
everything else. Allow-lists are safer, because attackers are creative —
there is always a bad input you forgot to ban. This project uses
allow-lists wherever it can.

### (A) Email validation

A valid email looks like `username@domain.com`. The validator uses a
regular expression (regex) to check the shape, then adds extra checks the
regex alone cannot do:

```python
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

def valid_email(email):
    if not isinstance(email, str) or "<" in email or ">" in email:
        return False                      # embedded script / tag: reject
    if not EMAIL_RE.match(email):
        return False
    domain = email.rsplit("@", 1)[1]
    if domain.startswith((".", "-")) or ".." in domain or domain.endswith("."):
        return False                      # invalid domain
    return True
```

What gets rejected, and why:

| Input | Result | Why |
| --- | --- | --- |
| `alice@hospital.com` | VALID | Normal address |
| `bob@clinic.org` | VALID | Normal address |
| `bad<script>@x.com` | REJECTED | Contains `<` and `>` — an embedded script |
| `no-at-sign` | REJECTED | No `@`, fails the regex |
| `carol@.com` | REJECTED | Domain starts with a dot — invalid domain |
| `dave@hospital` | REJECTED | No top-level domain (`.com`, `.org`) |

The `<` and `>` check matters because an email field is often displayed
back to users later. If an attacker can store `<script>...` in an email
address and the system later prints it into a web page, you have an XSS
vulnerability — which is exactly what Part 3 deals with.

### (B) Filename validation

Filenames are dangerous because they can contain path characters. The
rule here is strict: only letters, digits, `_` and `.` are allowed.

```python
NAME_RE = re.compile(r"^[A-Za-z0-9_.]+$")

def valid_filename(name):
    if not name or name.startswith("."):
        return False                      # hidden file like .env
    if ".." in name or "/" in name or "\\" in name:
        return False                      # path traversal
    return bool(NAME_RE.match(name))
```

| Input | Result | Why |
| --- | --- | --- |
| `report.pdf` | VALID | Letters and a dot |
| `patient_01.txt` | VALID | Letters, digits, underscore, dot |
| `../etc/passwd` | REJECTED | `..` and `/` — path traversal |
| `.env` | REJECTED | Hidden file — often holds secrets |
| `my file.txt` | REJECTED | Space is not in the allow-list |
| `data.csv` | VALID | Letters and a dot |

Hidden files deserve a special mention. Files starting with `.`, like
`.env`, are hidden on Linux and macOS, and `.env` files very often contain
database passwords and API keys. An attacker who can ask the system for a
file called `.env` — or upload one — can steal those secrets. So hidden
files are rejected outright.

### (C) File path validation

A filename is one thing; a whole path is another. Even a valid-looking
filename can be dangerous inside a path: `../../etc/passwd` climbs out of
the intended folder. The fix is to **normalise** the path and check it
stays inside a safe base directory:

```python
BASE_DIR = os.path.abspath("safe_files")

def valid_path(user_path):
    full = os.path.normpath(os.path.join(BASE_DIR, user_path))
    if os.path.commonpath([BASE_DIR, full]) != BASE_DIR:
        return False                      # escapes the safe folder
    return True
```

`os.path.normpath` collapses `.` and `..` segments, so
`a/b/../../safe.txt` becomes `safe_files/safe.txt` — which is inside the
safe folder, so it is correctly ALLOWED. That is path normalisation
working as intended, not a bug, and it is covered by a test. But
`../secret.txt` normalises to a path *outside* `safe_files/`, so it is
BLOCKED.

| Input | Result | Why |
| --- | --- | --- |
| `report.pdf` | ALLOWED | Inside the safe folder |
| `notes/data.txt` | ALLOWED | Subdirectory, still inside |
| `../secret.txt` | BLOCKED | Escapes the safe folder |
| `../../etc/passwd` | BLOCKED | Escapes the safe folder |
| `a/b/../../safe.txt` | ALLOWED | Normalises back inside |

This is called a **directory traversal** (or path traversal) attack, and
it is one of the oldest tricks in the book. The defence is always the
same: never trust a path from the user, resolve it fully, and check the
result is where you expect it to be.

## Part 2: SQL injection — when data becomes code

SQL injection is the classic input attack. It happens when user input is
glued straight into a database query as text, so the database cannot tell
where the programmer's SQL ends and the attacker's input begins.

### The vulnerable query

```python
def vulnerable_lookup(db, user_input):
    query = "SELECT * FROM users WHERE username = '" + user_input + "'"
    return db.execute(query).fetchall()
```

A normal lookup for `alice` produces:

```sql
SELECT * FROM users WHERE username = 'alice'
```

That works fine. But an attacker types `' OR '1'='1` as their username,
and the query becomes:

```sql
SELECT * FROM users WHERE username = '' OR '1'='1'
```

`'1'='1'` is always true, so the `WHERE` condition matches *every* row.
The demo shows this: the vulnerable query returns all 3 users — alice,
bob and carol — from one crafted input. In a real system, the same trick
can dump a whole users table, or worse: `' OR '1'='1'; DROP TABLE users; --`
can delete data.

### The secure query

```python
def secure_lookup(db, user_input):
    query = "SELECT * FROM users WHERE username = ?"
    return db.execute(query, (user_input,)).fetchall()
```

The `?` is a **parameter placeholder**. The input is sent to the database
*separately* from the SQL, as data — never as code. The database already
knows the shape of the query before it sees the input, so no input can
change what the query does. The same attack input `' OR '1'='1` now
returns **0 rows**: the database simply looks for a user literally named
`' OR '1'='1`, finds nobody, and moves on.

| Input | Vulnerable query | Secure query |
| --- | --- | --- |
| `alice` | 1 row: alice | 1 row: alice |
| `' OR '1'='1` | 3 rows: ALL users | 0 rows: attack blocked |

The lesson is not "sanitise the quotes out of the input" — attackers
always find a way around that. The lesson is **never build SQL by
concatenating strings**. Use parameterized queries (also called prepared
statements) every time, in every language. It is the single most
effective defence against SQL injection, and it costs nothing.

## Part 3: Cross-site scripting (XSS) — when text becomes code

XSS is SQL injection's cousin, but for web pages instead of databases.
It happens when user input is printed into a web page without escaping,
so the browser cannot tell where the page's HTML ends and the attacker's
input begins.

The demo takes a comment:

```
<script>alert('Hacked')</script> Nice portal!
```

If that is printed into a page as-is, the browser runs the script. A
real attacker would not show an alert — they would steal session cookies,
redirect the user, or rewrite the page. The fix is **output encoding**
with `html.escape`:

```python
def sanitize_comment(comment):
    return html.escape(comment)
```

`html.escape` turns `<`, `>`, `&`, `"` and `'` into harmless text
entities:

```
&lt;script&gt;alert(&#x27;Hacked&#x27;)&lt;/script&gt; Nice portal!
```

The browser now *shows* the text `<script>alert('Hacked')</script>`
instead of running it. The user's words are still there — nothing was
deleted — they just cannot act as code any more.

Two points worth remembering:

- **Escape on output, not on input.** Store what the user typed, and
  escape it when you display it. That way the same data can be shown
  safely in a web page, an email, or a report, each with the escaping
  that context needs.
- **Input sanitisation is a second layer, not a replacement.** Removing
  `<script>` from input helps, but attackers have dozens of ways to
  spell the same attack (`<ScRiPt>`, encoded characters, event handlers
  like `onerror=`). Output encoding is the defence that actually holds.

## Part 4: Buffer overflows and format strings — why Python is safer (but not immune)

### The unsafe and safe versions

In C, `printf` takes a format string, and the format string controls
what the function does with the rest of its arguments. If user input is
used *as* the format string, the attacker controls that behaviour:

```c
printf(user_input);        /* UNSAFE */
printf("%s", user_input);  /* SAFE   */
```

The project demonstrates this in Python, where `%` formatting works the
same way:

```python
def unsafe_format(user_input):
    return user_input % ("SECRET", 12345)

def safe_format(user_input):
    return "%s" % user_input
```

With the input `Balance: %s, code: %d`:

| Version | Output |
| --- | --- |
| Unsafe `printf(user_input)` | `Balance: SECRET, code: 12345` — the attacker's `%s` and `%d` pulled values out of the program |
| Safe `printf("%s", input)` | `Balance: %s, code: %d` — the input is printed literally, as data |

In real C, this is far worse than leaking two values. `%s` and `%x` can
read memory off the stack, and `%n` can *write* to memory. Combined with
a long input that overflows a fixed-size buffer, an attacker can overwrite
the return address on the stack and hijack the program's control flow —
that is a **buffer overflow**, and it has been behind some of the most
serious vulnerabilities in computing history.

### Why buffer overflows happen

A buffer overflow happens when a program writes more data into a fixed
block of memory (a buffer) than the block can hold, and the extra data
spills into neighbouring memory. In C, strings and arrays have no
built-in length checking: `strcpy`, `gets` and `sprintf` will happily
keep writing past the end. What sits next to the buffer — other
variables, saved registers, the return address — gets overwritten, and
the attacker chooses what it gets overwritten *with*.

### Why Python is safer — but not immune

Python is safer for three reasons. First, its strings and lists are
dynamic: they grow as needed, and indexing past the end raises an
exception instead of writing into random memory. Second, Python checks
bounds everywhere — there is no `strcpy` with no length limit. Third,
Python code runs on a virtual machine with its own memory management, so
an ordinary Python bug cannot overwrite a return address the way a C bug
can.

But "safer" is not "immune". Python programs still call C libraries
underneath (through `ctypes`, C extensions, or libraries like Pillow and
NumPy), and a bug in one of those can overflow just like a C program.
Python is also vulnerable to the *logic* version of the same mistake:
passing untrusted input where a format string or a template is expected
— for example, `user_input % values`, or an f-string built from user
data, or a logging call like `logger.info(user_input)`. The principle is
the same in every language: **user input is data, never a format string,
never code, never a template.**

## Part 5: Secure randomness — `random` vs `secrets`

Not all randomness is equal. Python has two random modules, and choosing
the wrong one is a real security bug.

### The insecure way

```python
import random
random.seed(42)
random.randint(1, 100)   # -> [82, 15, 4, 95, 36]
random.seed(42)
random.randint(1, 100)   # -> [82, 15, 4, 95, 36]  same again!
```

`random` is a **pseudo-random number generator (PRNG)** based on the
Mersenne Twister algorithm. Given the same seed, it produces the same
sequence every time — that is the whole point of a seed, and it is very
useful for testing and simulations. But it is also predictable: if an
attacker learns the seed (or a few outputs, from which the internal state
can be reconstructed), they can predict every future value. `random` is
fine for games and shuffling a playlist. It must never be used for
security.

### The secure way

```python
import secrets
secrets.randbelow(100)   # -> [44, 21, 81, 61, 2]
secrets.randbelow(100)   # -> [25, 40, 57, 64, 59]  different every run
```

`secrets` draws from the operating system's cryptographic random source
(`/dev/urandom` on Linux, `CryptGenRandom` on Windows). It cannot be
seeded, it cannot be reproduced, and its output cannot be predicted from
earlier outputs. That is what security tokens need.

### Session and password-reset tokens

The demo generates both kinds of token with `secrets.token_urlsafe(24)`:

```
Session token:   kQ_9ObGupt4qWRyTSADMgwh2tppRx2eM
Reset token:     5ThHWXs7t2NOUQdzCSqCk3A8JOdG8Z-V
```

Each token is 24 random bytes, encoded in URL-safe base64 — 32 characters
of unpredictable text. A token like this is used in two places:

- **Session tokens** identify a logged-in user. The server stores the
  token and checks it on every request. If an attacker can guess or
  predict a session token, they can impersonate that user.
- **Password-reset tokens** are sent in a "forgot your password" email.
  Anyone with the token can set a new password for the account. If an
  attacker can predict the next reset token, they can take over any
  account.

Both only work if the token is genuinely unpredictable — which is why
`secrets`, not `random`, is the right tool. The tests check that two
tokens are never equal and are at least 32 characters long.

### Measuring randomness: 1,000 values

The demo generates 1,000 values with `secrets.randbelow(100)` and counts
how many fall in each bucket of 10:

```
Distribution of 1000 secrets.randbelow(100) values:
   0- 9: 104 ##########################
  10-19: 104 ##########################
  20-29: 114 ############################
  30-39:  93 #######################
  40-49:  95 #######################
  50-59:  95 #######################
  60-69: 116 #############################
  70-79:  97 ########################
  80-89:  98 ########################
  90-99:  84 #####################
  min=0, max=99, expected ~100 per bucket -> roughly uniform
```

With 1,000 values spread over 10 buckets, you expect about 100 in each.
The real counts (84–116) are close to that — the small differences are
normal statistical noise. If the numbers were heavily skewed (say 400 in
one bucket and 10 in another), that would mean the generator is biased
and some values are far more likely than others — which makes tokens
easier to guess. The tests check every bucket lands between 60 and 140.

## Part 6: Entropy — how much surprise is in your randomness?

### What is entropy?

**Entropy** is a measure of unpredictability, usually counted in bits.
A coin flip has 1 bit of entropy: two equally likely outcomes. A
6-digit PIN has about 20 bits (1,000,000 possibilities, roughly
2^20). A 128-bit token has 128 bits of entropy — so many possibilities
that guessing it is, for practical purposes, impossible.

Entropy is not the same as length. A 32-character password of all `a`s
has almost no entropy, even though it is long. What matters is how many
*different* values are possible, and how evenly likely they are. A token
generated by `secrets.token_urlsafe(24)` has 24 random bytes behind it —
192 bits of entropy. A token generated by `random` with a seed an attacker
can guess has, effectively, almost no entropy at all, however long it
looks.

### Why predictable randomness is dangerous

If randomness is predictable, every security mechanism built on it falls
apart. The attacker does not need to break the encryption or guess the
password — they just need to predict the next "random" value.

### Weak seed-based randomness vs cryptographic randomness

| | Weak / seed-based (`random`) | Cryptographic (`secrets`) |
| --- | --- | --- |
| Source | Algorithm + seed (Mersenne Twister) | Operating system entropy pool |
| Reproducible? | Yes — same seed, same sequence | No — cannot be seeded or replayed |
| Predictable from past output? | Yes — state can be reconstructed from ~624 outputs | No |
| Good for | Games, simulations, testing | Tokens, keys, passwords, anything security-related |
| Cost | Fast | Slightly slower, but fast enough for tokens |

### Attack scenarios

- **Token prediction.** A password-reset system generates tokens with
  `random` and a seed based on the current time. An attacker requests a
  reset for their own account, sees the token, works out the seed from
  the time, and predicts the token that will be issued for the victim's
  account a second later. They use it to reset the victim's password and
  take over the account. This is not theoretical — it has happened in
  real products.
- **Session hijacking.** Session IDs are generated from a predictable
  sequence. An attacker logs in, gets session ID 1000, and simply tries
  1001, 1002, 1003… until they land on another user's active session.
  They are now logged in as that user, with no password needed. Modern
  systems prevent this by using long, cryptographically random session
  IDs — but only if the randomness is genuinely random.

The defence in both cases is the same: use a cryptographic random source
(`secrets` in Python, `/dev/urandom`, `crypto.getRandomValues` in the
browser), use enough bits (at least 128 for a token), and never seed it
yourself.

## How to run the demo, step by step

Running `python3 secure_input.py` does this, in order:

1. **Email validation** — six addresses are checked; two are valid, four
   are rejected for different reasons.
2. **Filename validation** — six filenames are checked; valid ones pass,
   `../etc/passwd` and `.env` are rejected.
3. **File path validation** — five paths are checked against the safe
   base directory; traversal attempts are blocked.
4. **SQL injection** — the attack `' OR '1'='1` returns all 3 users on
   the vulnerable query and 0 rows on the secure query.
5. **XSS** — a comment with `<script>alert('Hacked')</script>` is escaped
   with `html.escape`.
6. **Buffer overflow** — user input containing `%s` and `%d` leaks values
   through the unsafe format call and is printed literally by the safe
   one.
7. **Secure randomness** — seeded `random` repeats itself, `secrets`
   does not; session and reset tokens are generated; 1,000 values are
   analysed for a uniform distribution.

Interactive mode is a conversation instead: it asks for a command, then
prompts for the input to test.

```
Secure Input Module - interactive mode
Commands: email | file | path | sql | xss | token | quit
> email
Email: alice@hospital.com
VALID
> sql
Username: ' OR '1'='1
Secure lookup: []
> quit
Bye.
```

## Tests

`test_input.py` runs 29 checks and prints `PASS` or `FAIL` for each,
then a total. It covers:

- Email: valid addresses pass; scripts, missing `@`, bad domains and
  missing TLDs are rejected.
- Filenames: valid names pass; traversal, hidden files and spaces are
  rejected.
- Paths: safe paths allowed; `../` and `../../` blocked; a path that
  normalises back inside the safe folder is allowed.
- SQL injection: the vulnerable query returns all 3 users for the attack
  input; the secure query returns 0 rows; normal lookups work on both.
- XSS: the script tag is escaped, plain text is unchanged, no raw
  `<script>` survives.
- Format strings: the safe version keeps `%s` literal; the unsafe
  version leaks the arguments.
- Randomness: two tokens are unique and at least 32 characters; 1,000
  values are in range and roughly uniform (each bucket 60–140).

Result on Nov 8, 2026: **29 passed, 0 failed.**

```bash
python3 test_input.py
```

## Glossary

| Term | Meaning |
| --- | --- |
| Input validation | Checking user input against strict rules before trusting it. |
| Allow-list | Only the listed things are permitted; everything else is rejected. |
| Deny-list | Only the listed bad things are banned; everything else is allowed. |
| Directory traversal | Using `..` in a path to escape the intended folder. |
| SQL injection | Tricking a database by smuggling SQL code inside user input. |
| Parameterized query | A query with `?` placeholders; input is sent as data, never as code. |
| XSS (cross-site scripting) | Smuggling a script into a web page through user input. |
| Output encoding | Converting `<`, `>`, `&` etc. into harmless text before display. |
| Buffer overflow | Writing past the end of a fixed block of memory, corrupting what is next to it. |
| Format-string attack | Using `%s`, `%x`, `%n` in input to read or write memory through `printf`. |
| PRNG | Pseudo-random number generator — deterministic, reproducible from a seed. |
| Entropy | A measure of unpredictability, counted in bits. |
| Token prediction | Guessing the next security token because the generator is predictable. |
| Session hijacking | Taking over someone else's logged-in session. |
| Cryptographic randomness | Randomness from the operating system's entropy pool; unpredictable and unreproducible. |

## Limitations

- The SQLite database is in-memory and resets every run — it is a demo,
  not a real database.
- The XSS demo shows escaping in a terminal, not in a real browser; the
  principle is identical, but a real web app also needs a Content
  Security Policy and framework-level escaping.
- The buffer overflow demo simulates the C problem in Python; Python
  itself cannot overflow a buffer this way, so the demo shows the
  format-string part of the problem, not an actual memory corruption.
- The distribution check (buckets of 60–140) is a rough sanity check,
  not a proper statistical test like chi-squared.
- `random` is used in the demo *on purpose*, to show it is predictable.
  Never copy that part into real security code — use `secrets`.
- The path validator only checks the normalised path string; it does not
  follow symlinks, so a symlink inside the safe folder pointing outside
  would not be caught. A production version would resolve symlinks too
  (for example with `os.path.realpath`).
