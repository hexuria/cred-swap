# cred-swap

Ask a hosted model about your real production incident without sending it your
real production data.

`cred-swap` rewrites text before it leaves your machine. Every secret and every
piece of personal data is replaced by a stand-in of the same shape, so the model
still sees a sixteen-digit card number and a routable-looking host and answers
the question you actually asked. Every stand-in is stable, so the fourth mention
of a colleague is still the same person as the first. And every stand-in is
reversible, so the answer comes back with your real values in it.

```console
$ cat incident.txt
The charge from dana.reyes@northwind-logistics.com failed. Card
4242 4242 4242 4242 was declined. Deploy box 198.51.100.44 still has
  aws_secret_access_key = wJalrXU...EXAMPLEKEY
  DATABASE_URL=postgresql://appuser:s3cr3t@db.prod.internal:5432/orders

$ cred-swap scrub incident.txt
The charge from sloane.gilchrist@vandelay.test failed. Card
4431 6965 2038 6935 was declined. Deploy box 203.0.113.144 still has
  aws_secret_access_key = lFX0dQelKiC3zdmWOk6huklzmUhYhjFgTZWpExei
  DATABASE_URL=postgresql://fable:0LrMblzEd2eEz@db.globex.invalid:5432/oldbridge
    1 × email-address
    1 × credit-card
    1 × ip-v4
    1 × aws-secret-access-key
    1 × database-url
5 values replaced.
```

Pipe the model's answer back through `cred-swap restore` and the real addresses,
cards and keys are back where they belong.

## What it is

This is a Rust take on the idea behind
[opencloak](https://github.com/arikchakma/opencloak), a Chrome extension that
masks personal details in a chat box before you press Enter. The idea is the
same. Almost everything else is different.

- **It runs where your text is**, not only in a browser tab. A command in a
  pipe, a library in your own program, or a proxy in front of a model API.
- **It knows about credentials**, not only about people. API keys, cloud
  credentials, connection strings and private keys are the values that turn a
  careless paste into an incident, so they are the ones it is best at.
- **It restores.** The extension shows you real values in your browser; the
  answer it received still talked about the fakes. Here the round trip is real:
  the code the model hands back compiles against your actual config.
- **Detection is deterministic.** No model, no GPU, no download. A rule table
  with structural checks behind it: Luhn for cards, mod-97 for IBANs, the ABA
  checksum for routing numbers, entropy for unlabelled secrets. It is very good
  at things with a defined shape and weaker at free-form names. See
  [Limits](#limits).

## Install

```console
cargo install --path crates/cred-swap-cli
```

Or build from the workspace:

```console
cargo build --release      # target/release/cred-swap
```

## Use it

### In a pipe

```console
$ cred-swap scrub notes.md | pbcopy              # safe to paste anywhere
$ pbpaste | cred-swap restore                    # the answer, with real values
```

`scrub` writes the rewritten text to standard output and its summary to
standard error, so it drops into a pipeline without contaminating it.

### As a gate in CI or a pre-commit hook

```console
$ cred-swap detect --strict staged.diff
WHERE  KIND                   VALUE
3:12   aws-access-key-id      AKIA…LE (20 chars)
9:1    private-key-block      -----BEGIN RSA PRIVATE KEY----- …(27 lines)

2 values found, 2 of them credentials.
```

`--strict` exits 1 when anything is found. Credentials are abbreviated in the
report by default, so the check does not put the secret into your CI log. Pass
`--show-values` when you are looking at your own terminal.

### In front of a model API

Point any client's base URL at the proxy and change nothing else:

```console
$ cred-swap proxy --upstream https://api.anthropic.com
cred-swap: proxying http://127.0.0.1:8787 -> https://api.anthropic.com
```

```console
$ export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
```

Request bodies are scrubbed on the way out and responses restored on the way
back, including streamed ones — a stand-in that arrives one character per
server-sent event is still put back correctly. Your own API key travels in your
own headers and is never touched; it has to reach the provider for the call to
work at all.

### As a library

```rust
use cred_swap_core::{Cloak, Policy, Style, Surrogates};

let mut cloak = Cloak::new(
    Policy::default(),
    Surrogates::from_secret(b"a secret only this machine knows", Style::Realistic),
)?;

let scrubbed = cloak.scrub("Email dana@acme.com, card 4242 4242 4242 4242.");
assert_eq!(scrubbed.replacements.len(), 2);

let answer = format!("I would email {} first.", scrubbed.replacements[0].fake);
assert_eq!(cloak.restore(&answer), "I would email dana@acme.com first.");
```

## How it works

**Detection** is a table of rules, each a pattern plus an optional structural
check. Rules that would otherwise fire on every second line of a snippet are
keyword-gated: `password = …` matches, a bare word does not. When two rules
claim the same span, the more specific one wins, so a key is reported as an
Anthropic key rather than as a generic secret.

**Substitution** is deterministic. A stand-in is derived from an HMAC of the
session seed and the real value, so the same input always produces the same
output without any lookup — and nobody holding only the stand-ins can work
backwards to the originals. Shapes are preserved where they carry meaning: a
generated card number passes Luhn, a generated IBAN passes mod-97, a generated
routing number passes the ABA checksum.

Everything generated is inert by construction:

| Kind | Where stand-ins come from |
|---|---|
| Email, hostname, URL | `.example`, `.invalid`, `.test` — reserved, cannot be registered |
| IPv4 | `203.0.113.0/24`, the RFC 5737 documentation range |
| IPv6 | `2001:db8::/32`, the RFC 3849 documentation prefix |
| Phone | `555-0100`–`555-0199`, the block reserved for fiction |
| US SSN | The `900` block, which is never issued |
| MAC | A locally-administered address, which no manufacturer holds |
| Stripe key | Always test mode, so a leak fails loudly instead of moving money |

**The vault** records each pairing so the substitution is consistent and
reversible. It lives in one file per session, written owner-only, and it is the
most sensitive thing the tool touches: it holds every original next to its
stand-in. Nothing in the codebase logs it, and the `Debug` output of every type
that can reach it prints counts rather than contents.

## Configure

```console
$ cred-swap init
```

That writes a commented starter file. The parts worth knowing:

```toml
policy = "standard"   # standard | secrets | aggressive | none
style  = "realistic"  # realistic | tagged

allow = ["support@example.com"]   # never replace these

[[term]]                          # always replace these, whatever their shape
literal = "Project Halcyon"
kind = "custom:codename"

[[pattern]]                       # your own rules
label = "employee-id"
regex = '\bEMP-\d{6}\b'
group = 0
```

Use `--policy secrets` when the text is source code: it masks credentials and
leaves names, addresses and cards alone, so the snippet still reads. Use
`--style tagged` when you would rather see `[[EMAIL_ADDRESS_1]]` than a
plausible substitute.

Run `cred-swap kinds` to see all 41 rules and which are on.

## Sessions

Stand-ins are consistent inside a session and independent between sessions.

```console
$ cred-swap --session incident-4821 scrub notes.md
$ cred-swap --session incident-4821 vault list
$ cred-swap --session incident-4821 vault reroll dana@corp.com   # a different stand-in
$ cred-swap --session incident-4821 vault clear --new-seed       # forget everything
```

Vault files live under `~/.local/share/cred-swap` (or the platform equivalent).
Set `CRED_SWAP_HOME` to put them somewhere else, such as an encrypted volume.

Use `--no-save` for one-way redaction — scrubbing a log before attaching it to a
ticket — when you want no record that could reverse it.

## Limits

Read this part.

- **Pattern matching misses free-form personal data.** A name in the middle of a
  sentence, with no honorific and no `name:` label, will not be found. Structured
  values — keys, cards, addresses, connection strings — are the strong case.
- **A stand-in tells the model a value was withheld** only in `tagged` style. In
  `realistic` style the model reasons about the substitute as if it were real,
  which is the point, and also means its answer may assert things about a value
  that does not exist.
- **The proxy sees bodies, not headers.** That is deliberate, and it means a
  secret placed in a header goes upstream untouched.
- **Restoration in a stream costs a little latency.** The proxy holds back a few
  bytes so it can recognise a stand-in that has not finished arriving.
- **This reduces exposure. It does not guarantee it.** Read the report when the
  stakes call for it. `cred-swap detect` exists for exactly that.

## Layout

| Crate | What it is |
|---|---|
| `cred-swap-core` | Detection, substitution, the vault. No I/O beyond the vault file. |
| `cred-swap-proxy` | The HTTP proxy, including streaming restoration. |
| `cred-swap-cli` | The `cred-swap` binary. |

```console
cargo test --workspace     # 153 tests
cargo clippy --workspace --all-targets
```

## License

MIT. See [LICENSE](LICENSE).
