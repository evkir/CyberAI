# How CyberAI Refuses

An offensive tool that proceeds when it should stop is worse than one that
stops when it should proceed: the first sends packets nobody authorised, the
second wastes a minute. This page says where the refusals are, what each one
says out loud, and why two readers of the same environment variable answer
differently on purpose.

Nothing here is a list kept by hand. `tests/architecture/test_every_refusal_is_on_the_page.py`
walks the package with AST, collects every class that inherits from an
exception, and fails if one of them is missing below -- or if a name below
no longer exists in the tree.

## What a refusal costs the reader

A refusal is only useful if somebody learns of it. The tree holds four
shapes, and they differ by who is standing at the screen:

**Raised and left to travel.** The caller decides what the message becomes.
This is the shape for a stop that must not be swallowed: an unauthorised
egress, a budget already spent.

**Raised, caught, and turned into one line.** A command-line reader gets a
sentence instead of a traceback. `click.ClickException` is the wrapper, and
the original is chained with `from exc` so the cause survives in a debug run.

**Raised, caught, and turned into a value.** The run continues with a
substitute. Only one refusal does this, and only when the caller supplied
the substitute in advance.

**Not raised at all.** The reader narrows to a default instead. This is not
a refusal to act -- it is a refusal to invent a choice nobody made, and it
is the subject of the second half of this page.

## Every refusal in the tree

| exception | raised in | what the reader sees |
| --- | --- | --- |
| `EgressViolation` | `core/egress_guard.py` | air-gapped mode was asked for and the endpoint is not local; the message names provider, base URL and the two ways to fix it |
| `BudgetExceeded` | `core/cost_tracker.py` | the spend cap set by `CYBERAI_MAX_COST_USD` was reached; the call is not made |
| `ToolInputBlocked` | `core/safety.py` | a tool argument failed validation before the tool ran |
| `SealedEnvError` | `core/sandbox/proc.py` | a subprocess was asked to start with an environment the sandbox will not seal |
| `AgentIterationLimitError` | `core/base_agent.py` | an agent loop hit its iteration ceiling rather than running unbounded |
| `InjectionBlocked` | `core/security/guard.py` | under the `deny` policy, a prompt-injection verdict stops the call before any provider is contacted |
| `CorpusError` | `core/security/eval_corpus.py` | the evaluation corpus could not be read; surfaces as one CLI line |
| `RecordMismatch` | `core/security/llm_classifier.py` | a replay recording does not match the corpus it is replayed against; surfaces as one CLI line |
| `AgentTimeoutError` | `core/timeout.py` | nothing, when a fallback was supplied; otherwise it travels |
| `RateLimitError` | `utils/backoff.py` | nothing: the class is declared and no code raises it |

The last row is the reason this table is generated from the tree rather than
written once. A refusal nobody raises is indistinguishable, from the outside,
from a refusal that never fires -- and the difference matters to anyone
reading the backoff helper expecting it to signal.

`InjectionBlocked` is caught once on its way out, in `core/llm_client.py`,
and re-raised. The catch exists to write the verdict to the audit trail
before the exception propagates: a blocked call is the one most worth having
in the record, so the refusal is documented first and delivered second.

## Refusing to invent a choice

Six readers translate environment variables into configuration. None of them
raises, and that is deliberate: `from_env` has no raise in it at all, nine
call sites reach it, and one of those is inside an MCP tool where an
exception is not a message anybody reads. Garbage in a variable must not
abort a scan at startup.

What they do instead is narrow. A value outside the declared set is read as
nobody having chosen, so the default stands.

| reader | reads | a value it does not recognise |
| --- | --- | --- |
| `_env_bool` | feature flags that default to off | off, which is the default anyway |
| `_env_guard_bool` | flags whose default protects the run | the default, which stays on |
| `_env_int` | whole numbers with a default | the default |
| `_env_optional_int` | whole numbers with no default | unset, which the caller can tell from a real choice |
| `_env_float` | decimals with a default | the default |
| `_env_provider` | the LLM provider name | the default provider |

**Two boolean readers, because the words for "no" are not the words for
"nobody chose".** `_env_bool` asks whether a value is one of the words for
yes, so everything else reads as no. For the flags that default to off that
is the same answer as the default and costs nothing. For a flag that
defaults to on it is the difference between a guard and no guard: measured
on 2026-09-19, `CYBERAI_STRICT_SCOPE=` -- the empty string a shell leaves
behind for an unset variable in a `.env` file -- turned the scope refusal
off, and so did `CYBERAI_STRICT_SCOPE=nope`. `_env_guard_bool` holds the
named list in both directions and leaves the default standing otherwise.

**The environment narrows, the flag refuses.** `CYBERAI_LLM_PROVIDER=gemini`
leaves the default provider in force and the run proceeds; `--provider
gemini` is refused by the parser, which lists the names that exist. The
asymmetry is not an oversight. A stale variable is read by nobody in
particular, possibly long after whoever set it moved on, and aborting a scan
there helps no one. A flag is typed by a person who is at the terminal right
now and will read the reply. `cyberai status` prints the provider actually
in force, which is where an unrecognised variable gets said out loud.

## What this page does not cover

Refusals that belong to a library rather than to this package -- a `click`
parser error, a `requests` timeout, an nmap exit code -- are not listed.
They are real and they reach the user, but a page that tried to enumerate
them would describe somebody else's tree and go stale on their schedule.
