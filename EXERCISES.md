# Exercises: Secure Input Validation

These exercises use the code in `secure_input.py`. Do them in a copy of
the repo, or in a scratch directory, so a mistake costs nothing. Run
the demo first (`python3 secure_input.py`) so you know what the safe
versions look like, then try to break things.

## 1. Beat your own validator

The validator in this project rejects suspicious emails, filenames and
paths. Try to get a bad input past it. Start with the obvious ones —
`../../etc/passwd` as a filename, `test@` as an email — and then get
creative: weird unicode characters, very long strings, null bytes,
mixed-case tricks.

Write down every input that got through that should not have, and
every good input that got wrongly rejected. Fix at least one of each,
and run `python3 test_input.py` to make sure you did not break the
existing tests.

**What to notice:** validation is a list of edge cases, and attackers
live in the edge cases. A validator that handles the ten inputs you
thought of is not the same as one that handles the input someone else
thinks of.

## 2. Write the attack before the fix

Pick the SQL injection demo in `secure_input.py` and, before looking at
the safe version, write your own attack string. Your goal: log in as
the admin user without knowing the password. Try `' OR '1'='1` first,
then try to make the query return all users instead of one.

Then look at the parameterized version and explain, in one paragraph,
why the same string is harmless there. The important question is not
"does it work" but "where does the input stop being code and start
being data?"

**What to notice:** the fix is not "block the quote character". The fix
is never letting the input become part of the query in the first place.
Blocklists chase the attacker's creativity; parameterized queries remove
the opportunity.

## 3. Steal a session token — on paper

The project shows `random` tokens next to `secrets` tokens. Do the
maths: if a session token is generated with Python's `random` module
and seeded with the current time in seconds, how many guesses would an
attacker need to find a token issued in the last hour? (Hint: it is
about 3,600, not millions.)

Now do the same for a 32-byte token from `secrets.token_hex(32)`. Write
both numbers down. That gap is the entire argument for using the right
random source, and it is worth being able to explain it without
hand-waving.

**What to notice:** "random" is not one thing. `random` is fine for
shuffling a playlist and dangerous for anything an attacker wants to
predict. The module you pick is a security decision, not a style
choice.

## 4. Find the XSS the escape missed

`html.escape` neutralises a `<script>` tag in a comment. But XSS has
more than one home. Find a place in a web page where escaped text is
still dangerous — for example, inside an HTML attribute like
`<a href="USER INPUT HERE">`, or inside a `<script>` block where the
input becomes JavaScript, not HTML.

Write a short example of an input that is safe as page text but
dangerous in one of those contexts, and explain what the correct fix
is for that context (hint: it is not the same function).

**What to notice:** escaping is context-dependent. A fix that works in
one part of the page can be useless, or even harmful, in another.
"Escape the output" is only good advice if you also ask "escape it for
where?"

## 5. Measure the entropy yourself

The entropy section explains why predictable randomness is dangerous.
Make it concrete: generate 1,000 tokens with `random` and 1,000 with
`secrets`, and count how many duplicates appear in each set. Then try
tokens of different lengths — 4 characters, 8, 16 — and watch how the
duplicate count changes.

Write down the shortest token length where you would feel comfortable
using the token as a password-reset link, and explain your reasoning
in two sentences.

**What to notice:** entropy is not a feeling. It is a number, and you
can measure it. Security decisions get much easier once you stop
arguing from vibes and start counting.

## 6. Review a real form like an attacker

Pick a form you actually use — a login page, a search box, a comment
form on a site you visit. For each field, write down: what does the
site accept, what does it reject, and what happens when you send
something strange (a very long string, a quote character, a `<script>`
tag)?

You are not trying to break the site — just observe what it does with
bad input, the way you would review your own code. Note one thing it
does well and one thing you would change if it were your project.

**What to notice:** input validation is everywhere once you start
looking for it, and most of it is invisible until it fails. Doing this
exercise on real sites trains the instinct faster than any textbook,
because you start to notice the difference between a site that thought
about its inputs and one that did not.
