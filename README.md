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
  DATABASE_URL=postgresql://appuser:s3cr3t@db.prod.internal/orders

$ cred-swap scrub incident.txt
The charge from sloane.gilchrist@vandelay.test failed. Card
4431 6965 2038 6935 was declined. Deploy box 203.0.113.144 still has
  aws_secret_access_key = lFX0dQelKiC3…ZWpExei
  DATABASE_URL=postgresql://fable:0LrMblzEd2eEz@db.globex.invalid/oldbridge
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

### In a browser extension

The core compiles to WebAssembly, so a content script can mask a prompt in the
composer before it is sent and put the real values back in the reply. It is the
same rule table, not a reimplementation of it.

```console
wasm-pack build crates/cred-swap-wasm --target web --out-dir pkg --release
```

```js
import init, { Cloak } from "./pkg/cred_swap_wasm.js";
await init();

// The seed lives in the vault. Persist it or every stand-in already sent
// becomes unrestorable.
const saved = await browser.storage.local.get("vault");
const cloak = saved.vault ? Cloak.fromVault(saved.vault) : Cloak.create();

// Show the user what would be replaced, before anything is sent.
for (const f of cloak.detect(composer.value)) {
  chips.append(chip(f.kind, f.secret ? mask(f.value) : f.value));
}

const { text, replacements } = cloak.scrub(composer.value);
composer.value = text;
await browser.storage.local.set({ vault: cloak.export() });

// And put the real values back in the reply.
reply.textContent = cloak.restore(reply.textContent);
```

`cloak.scrubExcept(text, keptOffsets)` honours chips the user unticked, except
for credentials, which it replaces regardless. `cloak.restoreStreaming(buffer)`
is for a reply that arrives a few characters at a time: it returns the text
that is safe to show and how much of the buffer it consumed, so a stand-in
split across chunks is still reassembled.

There is a working page at `crates/cred-swap-wasm/demo/index.html`. Serve the
crate directory over HTTP and open it:

```console
python3 -m http.server -d crates/cred-swap-wasm 8000
# then open http://localhost:8000/demo/
```

The browser build has no operating system to ask for entropy, so it takes its
seed from `crypto.getRandomValues` and drops the `getrandom` dependency
entirely. Store the exported vault in the extension's `storage.local`, which
other sites cannot read, never in a page's own `localStorage`, which they can.

### In an agent harness or a server

`cred-swap-core` is a plain Rust library with no I/O beyond its own state file,
so a server can embed it directly rather than proxying through one.

```toml
[dependencies]
cred-swap-core = { git = "https://github.com/hexuria/cred-swap" }
```

A server handling many conversations at once wants `SessionStore`, which keeps
one vault per conversation, shares it safely across threads, and persists it:

```rust
use cred_swap_core::session::SessionStore;
use cred_swap_core::{Policy, Style};

let store = SessionStore::builder()
    .directory("/var/lib/my-server/cred-swap")
    .policy(Policy::default())
    .style(Style::Realistic)
    .secret(b"a stable per-deployment secret")
    .build()?;

let session = store.session("run:8f21c4")?;   // cheap, cloneable, Send + Sync
```

Each session's generator is derived from the store secret and the session id,
so two conversations give the same real value two different stand-ins. Without
that, a stand-in seen in one tenant's transcript would identify that value in
every other tenant's.

**An agent harness needs four hooks, not two.** A chat client scrubs what goes
out and restores what comes back. An agent also acts on what the model says, so
the model's own words have to be translated back before they are executed:

| Hook | Call | Why |
|---|---|---|
| Outbound request | `session.scrub_json(&mut body)` | Walks every string in the body, whatever the provider's schema. |
| Tool call arguments | `session.restore_json(&mut call)` | **Before the tool runs.** The model was shown a stand-in host, so it asks you to connect to the stand-in. |
| Tool result | `session.scrub(&output)` | A file read or command output is where secrets actually enter a transcript. |
| Final answer | `session.restore(&reply)` | So the human reads real values. |

The second one is the hook people forget, and it is the one that breaks the
agent rather than leaking: without it the coworker dutifully tries, and fails,
against a host that does not exist.

For a streamed reply use `session.restore_streaming(&buffer)`, which returns
the text that is safe to emit and how much of the buffer it consumed. Keep the
remainder and prepend it to the next chunk, so a stand-in split across two
chunks still comes back whole.

A runnable version of all four hooks:

```console
cargo run -p cred-swap-core --example agent_harness
```

If you would rather not touch the harness at all, `cred-swap proxy` gives you
the same thing at the HTTP boundary for a one-line base URL change, at the cost
of not being able to reach tool calls before they execute.

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
| US ITIN | Area `9xx` with group `93`, which is neither an SSN nor an issued ITIN |
| UK NINO | The `ZZ` prefix, which heads HMRC's own never-issued list |
| Canadian SIN | A leading `8`, which is never assigned |
| Indian Aadhaar | A leading `1`, which is never issued |
| MAC | A locally-administered address, which no manufacturer holds |
| Stripe key | Always test mode, so a leak fails loudly instead of moving money |

Not every scheme has a block set aside, and the ones that do not are said so
rather than implied otherwise. A Philippine TIN, an Australian ABN, a Brazilian
CPF, a Singapore NRIC, an Indian PAN and an EU VAT number all come back
well-formed, and each could in principle coincide with a number somebody holds.
Where the scheme has a checksum the stand-in satisfies it, so masked text still
validates the way the original did.

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

Run `cred-swap kinds` to see all 44 rules and which are on.

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
| `cred-swap-wasm` | Browser bindings, and the demo page. |

```console
./scripts/check.sh      # everything CI runs, in the order CI runs it
```

Run that before pushing and CI holds no surprises. It exists because the
interesting failures were all ones a plain `cargo test` could not see: a lint
only the newest stable knows about, a browser build that compiles the core with
a feature turned off, a scan that walks tracked files and so cannot see one you
have not staged yet.

CI runs those on Linux, macOS and Windows, checks the minimum supported Rust
version, builds the browser package, audits dependencies for advisories, and
runs `cred-swap` over this repository's own source. That last job has a
baseline in [`.cred-swap.toml`](.cred-swap.toml): it waives the specific
synthetic strings the rule tests depend on, by value and with a reason, and
leaves every rule armed.

Contributions that add a rule should add a case to both sides of it: something
the rule must catch, and something nearby it must not. The second is the one
that matters. A rule that fires on ordinary source code gets the whole tool
switched off.

## License

MIT. See [LICENSE](LICENSE).
