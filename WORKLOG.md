# Work Log

## Nov 8, 2026 — Secure input validation module

**What was built:** a single Python script, `secure_input.py` (236 lines),
that works as a Secure Input Processing Module for a healthcare web
portal. It covers six parts:

- **Input validation engine** — email (regex plus domain checks, rejects
  embedded scripts), filename (only letters, digits, `_` and `.`; rejects
  `../` traversal and hidden files like `.env`), and file path (normalised
  and confined to a `safe_files/` base directory).
- **SQL injection** — a small in-memory SQLite database with three demo
  users (alice/doctor, bob/nurse, carol/admin). The vulnerable
  string-concatenated query returns all 3 users for the attack input
  `' OR '1'='1`; the secure parameterized query returns 0 rows for the
  same input.
- **XSS prevention** — a comment containing
  `<script>alert('Hacked')</script>` is neutralised with `html.escape`,
  so the browser shows the text instead of running it.
- **Buffer overflow awareness** — unsafe `printf(user_input)` lets `%s`
  and `%d` in the input leak values; safe `printf("%s", user_input)`
  prints the input literally. Plus a written explanation of why buffer
  overflows happen and why Python is safer but not immune.
- **Secure randomness** — `random` with seed 42 gives the same five
  numbers twice (predictable); `secrets.randbelow(100)` differs every
  run. Session and password-reset tokens via `secrets.token_urlsafe(24)`,
  and 1,000 values analysed for distribution (about 84–116 per bucket
  of 10, roughly uniform).
- **Entropy analysis** — a written answer: what entropy is, why
  predictable randomness is dangerous, weak seed-based vs cryptographic
  randomness, and token prediction and session hijacking scenarios.

The script runs in two modes: a non-interactive demo that walks through
everything, and an `--interactive` menu (email / file / path / sql / xss
/ token / quit).

**Test results:** `test_input.py` — **29 passed, 0 failed**, covering
email, filename, path, both SQL queries, XSS escaping, format-string
safety, token uniqueness, and the 1,000-value distribution. Demo run
exits 0, and an interactive scripted session exits 0.

**Challenges:**

- The title's "(4%)" was split across three runs in the original document
  (`(`, `4`, `%)`), so a plain text replace missed it, and a first attempt
  stripped the spaces between the title runs. Fixed by removing the runs
  instead of editing the text.
- Screenshot generation: splitting the validation output into email /
  filename / path blocks needed a regex split on the section headers,
  since the sections are not separated by blank lines.
- `a/b/../../safe.txt` normalises back inside the safe folder, so it is
  correctly ALLOWED — that is path normalisation working as intended,
  not a bug, and it is covered by a test.
- The script came in at 236 lines, slightly under the 250–300 target, but
  all six parts are covered and nothing was padded to hit the range.
