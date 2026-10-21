# Sherlock — Digital Forensics Assistant

An AI-orchestrated OSINT platform with a detective at the centre of it. Talk to Sherlock
like a colleague and he answers; tell him to investigate a subject and he opens a case,
builds a prerequisite-ordered pipeline, runs the available OSINT tools, and stitches every
finding into one forensic report.

> "The game is afoot!" — and the trail is already digital.

## Run it

```bash
cd sherlock
./run.sh
```

Then open <http://localhost:5000>.

`run.sh` picks a Python interpreter that actually has Flask (preferring `.venv`),
so it does not matter which `python3` your shell resolves to.

If you prefer the explicit form:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python app.py
```

## Why you may have seen `ModuleNotFoundError: No module named 'flask'`

macOS often exposes two interpreters:

| Interpreter | Version | Flask? |
|---|---|---|
| `/usr/bin/python3` (system) | 3.9.6 | yes |
| `/usr/local/bin/python3` (Homebrew) | 3.14.5 | no |

If `python3` resolves to the Homebrew one, importing Flask fails. `run.sh` sidesteps this
entirely by using the project venv. You can also force the system interpreter:
`/usr/bin/python3 app.py`.

## What it does

- **A detective, not a search box** — the console is a conversation. Sherlock is prompted
  with a Sherlock Holmes persona (dry, observant, slightly cryptic, builds on what you
  said) and routes each message itself: talk and he talks back, say *investigate* and he
  opens a case. The routing is decided by the model and then checked against the
  sentence itself, so an explicit order is never talked past.
- **Live answers** — a local model can take minutes. The browser starts a background job
  and watches it: status lines, the stages of a case ticking over, and the words arriving
  as they are written.
- **Dynamic pipelines** — stages are topologically sorted so prerequisites always run first
  (e.g. username analysis → platform search → correlation → enrichment → synthesis).
- **Four target types** — `username`, `email`, `name`, `comprehensive`.
- **Tool orchestration** — integrates Sherlock, Maigret, Social Analyzer, Blackbird, GHunt,
  Holehe, h8mail, theHarvester, Amass, Subfinder, Photon, dnstwist, PhoneInfoga,
  TruffleHog, SpiderFoot, and ExifTool when they are installed. Install them into the
  same `.venv` that runs Sherlock (`./.venv/bin/pip install maigret ghunt …`) — the
  console scripts and modules are looked up there, not in the system Python, and
  packages that ship no `__main__` (holehe, ghunt) are started through the script
  their installer creates.
- **Built-in passive engine** — GitHub API, Gravatar, DNS resolution, and crt.sh
  certificate transparency work with no extra installs or API keys, so every stage still
  returns real evidence on a clean machine.
- **Stitched report** — confirmed identifiers, per-source evidence, coverage gaps, and
  next-step recommendations, rendered in the Results tab.
- **Bring your own tools** — download and configure OSINT repositories straight from
  GitHub, then wire them into any pipeline stage (see below).

## Model configuration

Settings uses a three-step flow, in order:

1. **Provider** — OpenAI, Anthropic, Google Gemini, OpenRouter, Ollama (local),
   or any OpenAI-compatible endpoint.
2. **Credentials** — paste the key and press *Verify key & load models*. Sherlock calls
   the provider's `/models` endpoint with that key, so a bad key fails here instead of
   silently later. Keys are written to `models/config.json` (chmod `0600`) and are never
   returned by the API.
3. **Model** — the dropdown is populated from the models the key can actually access.
   Saving activates it (shown in the top bar and side rail).

Ollama needs no key: point it at `http://127.0.0.1:11434` and verify.

**Endpoint-only mode.** Choose *OpenAI-compatible endpoint* and paste just a server URL — no key
required. Trailing paths are trimmed automatically (`/v1`, `/v1/models`, `/v1/chat/completions`
all work), and a bare host is retried once under `/v1`. The URL may also be pasted into the key
box; Sherlock moves it to the base URL field for you.

With a model configured, each investigation gets a short prose **model briefing** at the top of
the report, generated from the collected evidence. If the call fails or no model is set, the
rule-based stitcher still produces the full report.

## GitHub repositories (bring your own tools)

The **Repos** tab lets you add your own OSINT tooling from GitHub, without touching
the filesystem by hand.

1. **Token** — paste a personal access token. It is validated against `GET /user`
   before it is stored, written to `models/github.json` (chmod `0600`), and never
   returned by the API. A classic token needs the `repo` scope for private
   repositories; a fine-grained token needs read access to repository contents.
   Public search works without a token (10 requests/minute).
2. **Search** — *All of GitHub* searches the public API; *My repositories* lists the
   repositories the token can reach (owner, collaborator, organization member).
3. **Download & configure** — Sherlock downloads the repository into `repos/`, detects
   what kind of project it is, runs the matching build step, works out the runnable
   entry point and the command line it expects, and registers it as a tool.

What "configure" does for you:

| Project type | Build step | Entry point |
|---|---|---|
| Python with `pyproject.toml` / `setup.py` | `pip install -e .` | the installed console script |
| Python script with `requirements.txt` | `pip install -r requirements.txt` | the script itself |
| Go | `go build` | the compiled binary |
| Node | `npm install` | `node_modules/.bin/<name>` when the package declares a `bin`, otherwise the main script (`node index.js`) |
| Rust | `cargo build --release` | the release binary |
| Shell | `chmod +x` | `bash <script>.sh` |

The entry point is only accepted if the file really exists after the build. A
repository whose toolchain is missing — Go without Go installed, for example — is
marked **failed** with the reason ("go is not installed on this machine") instead of
being handed an entry point that would fail at investigation time.

The console script is read out of the project's own metadata — `[project.scripts]`
in `pyproject.toml`, `entry_points={'console_scripts': [...]}` in `setup.py` — and
resolved to the script `pip install -e .` just created. If the project has no
packaging, Sherlock falls back to the main script or `python -m <package>` and
runs it straight from the checkout.

The argument pattern is detected from the tool's own `argparse` options
(`-u`, `--username`, `-e`, `-d`, …) and can be edited in the UI — it always contains
`{target}`, which is replaced with the investigation target.

Downloaded repositories then appear in the **Pipeline** tab next to the built-in
integrations, and any tool can be assigned to any stage. The assignment is persisted
and the stage runs the tool you chose. A download that could not be configured is
labelled *(downloaded · failed)* in the stage dropdown so it is never mistaken for a
working tool.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/github` | Token state, rate limit, installed repositories |
| `POST` | `/api/github/token` | `{ token }` — validated, then stored |
| `GET` | `/api/github/search?q=&scope=public\|mine` | Repository search |
| `POST` | `/api/github/install` | `{ full_name, ref }` — download and configure |
| `POST` | `/api/github/args` | `{ key, args }` — change the argument pattern |
| `POST` | `/api/github/remove` | `{ key }` — delete the checkout and unassign it |
| `GET` | `/api/tools` | Built-in plus downloaded tools |
| `GET`/`POST` | `/api/pipeline-tools` | Read or change the tool assigned to a stage |

## API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | Web UI |
| `GET` | `/api/providers` | Supported providers |
| `POST` | `/api/providers/verify` | `{ provider, apiKey, baseUrl }` → models the key can use |
| `GET` | `/api/config` | Active provider/model (never the key) |
| `POST` | `/api/config` | `{ provider, model, baseUrl, apiKey }` |
| `POST` | `/api/investigate` | `{ "target": str, "type": "username\|email\|name\|comprehensive" }` |
| `POST` | `/api/chat` | `{ message, history, mode, type }` → the agent answers, or opens a case and returns the run |
| `POST` | `/api/chat/start` | Same payload, but returns `{ job }` straight away |
| `GET` | `/api/chat/job/<id>` | `{ status, events[], result, error }` — status lines and streamed text |
| `GET` | `/api/pipeline-status` | Ordered stage list |

### Talking to Sherlock

`POST /api/chat` is the blocking form of the conversation:

```bash
curl -s -X POST http://localhost:5000/api/chat \
  -H 'Content-Type: application/json' \
  -d '{"message":"Investigate the username torvalds","history":[],"mode":"auto"}'
```

- `mode: "auto"` — the model decides whether this is conversation or a case.
- `mode: "investigate"` — open a case whatever is said; `type` fixes the subject type.
- `history` — the spoken words so far, as `[{role, content}]`.

The reply comes back in `reply`. When a case was opened, `mode` is `investigate` and the
whole run comes back in `run` (pipeline stages plus the stitched report).

For long jobs, `POST /api/chat/start` returns a job id immediately; poll
`GET /api/chat/job/<id>` for `events`, where `type: "status"` lines report the case
progress and `type: "delta"` lines carry the answer as it is written.

### The console

The window is styled after a case file: a pixel typeface (Silkscreen) for the
labels, a mono typeface for the evidence, brass and ink on a dark desk, and hard
edges rather than soft shadows. The composer has two modes — **Chat** and
**Investigate** — and the chat log remembers what you said and what Sherlock
answered, so a case can be opened in the middle of a conversation.

## Port

Defaults to `5000`. Override with `PORT=8080 ./run.sh`.

## Scope

Use only for lawful, authorized investigations. Publicly reachable data is still sensitive;
treat correlations as leads, not proof.
