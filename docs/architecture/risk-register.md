# Risk Register — what could make this project fail

**Last verified against the tree:** 2026-09-20.

This page replaces a document that tracked eight build-out defects and had
said "ALL RESOLVED" since day 7 while the README went on describing it as the
place where gaps are named. A page nobody updates is worse than no page: it
reads as a claim that nothing is wrong.

Twenty-two risks were enumerated on 2026-09-08 after a live audit of every
subsystem. They are listed here with the same wording, a status, and the node
id of the test that holds each closed one. A status is a claim about this
tree, so it names a test rather than a pull request: pull request numbers are
recorded for history and are not checked by anything.

No percentage appears on this page. Detector figures live in
`examples/detector-eval/baseline.md`, which is written by a command.

Status vocabulary: `closed` — a test in this tree fails if the risk returns.
`partly` — one half is guarded, the other is named below. `open` — measured,
not fixed. `unguarded` — held by discipline, with no machine behind it.

Held by says what kind of assertion the named test makes, and it is written
by `scripts/register_levels.py` rather than by whoever edits the row. Risk 20
stood closed for fifteen days on a test that read a config field while an
unscoped run spent fifty-one seconds touching a protected range; the
reference resolved the whole time, so the guard over this page was green and
right to be. This column is what that row would have said out loud.

`boundary` — something is asserted about calls: a probe that was not reached,
a count, the arguments it was given. `entrypoint` — a command or agent of
ours was driven end to end and the result inspected. `value` — the product
was exercised and the assertions are about what it returned or holds.
`structural` — the test reads the tree, a workflow file or a page, and
touches no product code; deliberate for rows about the repository itself.
A `-` means the row is not closed, so there is nothing to measure.

No level is forbidden here. Two probes on 2026-09-22 established that
"measures behaviour" cannot be decided from syntax: a test calling
`validate_exploit_scope` and checking its verdict looks exactly like one
calling `from_env` and reading `.strict_scope`, and a rule failing the second
would accuse rows 1 and 6 wrongly. A `value` row is not a defect. It is a row
whose guard could be stronger, now readable as such without opening the test.

## Shipped defects, found by live measurement

| # | Risk | Status | Held by | Measured by |
|---|---|---|---|---|
| 1 | Web exploitation unreachable under every `--scope` value: two gates normalised opposite sides of one comparison | closed | value | `tests/unit/test_scope_guard_normalises_the_target.py::test_both_gates_reach_the_same_verdict` |
| 2 | A skipped phase printed as success, exit code 0 on `state: failed` | closed | entrypoint | `tests/unit/test_a_scope_refusal_is_visible_at_the_end.py::test_the_status_line_reports_partial_for_a_refused_walk` |
| 3 | Tests feed argument shapes production never sends | closed | structural | `tests/architecture/test_a_url_parameter_is_fed_a_url.py::test_no_test_feeds_a_url_parameter_something_without_a_scheme` |
| 4 | The published score came from a surface profile blind on both live targets | closed | entrypoint | `tests/unit/test_the_manifest_records_the_surface_it_saw.py::test_two_profiles_do_not_share_a_hash` -- the row named `test_the_manifest_carries_the_profile` until 2026-09-22, which asserts the keys are present. The risk is that two runs seeing different surfaces published the same provenance, and the test beside it is the one that fails when they do |
| 5 | An AI-native benchmark measured a path that called no model | closed | entrypoint | `tests/unit/test_the_bench_table_says_who_solved_it.py::test_a_model_free_run_says_so_next_to_the_score` |
| 6 | Documented out-of-band cost understated sixteenfold | closed | value | `tests/unit/test_web_exploit_oob.py::test_every_delivery_is_charged_to_the_budget` |
| 7 | One of four web3 engines decided the verdict; aderyn returned nothing | closed | value | `tests/unit/test_web3_agent_merge.py::test_run_merges_and_cross_validates` |

## Technical

| # | Risk | Status | Held by | Measured by |
|---|---|---|---|---|
| 8 | The CVE-Bench adapter was written against criteria older than v2.1.0 | partly | - | `tests/integration/test_the_bench_answers_to_the_upstream.py::test_the_adapter_answers_to_the_checkout_on_disk` — carries the smoke marker, so CI skips it and only a workstation with the checkout runs it |
| 9 | The MCP client did not report which protocol revision it negotiated | closed | entrypoint | `tests/integration/test_mcp_revision_in_output.py::test_the_terminal_names_the_revision_the_probe_negotiated` |
| 10 | The detector does not cover tool icons or URL-mode elicitation, both added to the protocol in revision 2025-11-25 | partly | - | Icons: `tests/unit/test_mcp_poisoning.py::test_a_directive_in_an_icon_field_reaches_the_matcher` and `tests/unit/test_mcp_poisoning.py::test_an_executable_icon_carrier_is_a_signal`. The field was outside the collected whitelist, so no pattern could have reached it. Elicitation: the risk was written on a premise the SDK does not support -- `ServerCapabilities` has no elicitation field, so a scanned server cannot advertise URL mode and a probe that calls nothing never receives error -32042. The exposure runs the other way and is held by `tests/unit/test_the_probe_does_not_offer_to_open_a_url.py::test_the_probe_advertises_no_elicitation`. Partly: what a target does with elicitation is reachable only by calling its tools, which this scanner does not do |
| 11 | Detection and false-positive figures come from a corpus this project wrote | open | - | `tests/architecture/test_corpus_integrity.py::test_both_classes_meet_the_floor` guards the corpus, not its provenance. No external corpus has ever been run |
| 12 | CVE-Bench and phantom-grid both claim port 9090 | closed | boundary | `tests/unit/test_cve_bench_driver.py::test_a_taken_port_is_named_not_blamed_on_the_stack` |
| 13 | Two finding counts in one result, neither reconciled with the other | closed | value | `tests/unit/test_web3_agent_merge.py::test_aderyn_only_critical_raises_the_headline` |
| 14 | Access findings and escalation paths were computed and never printed | closed | entrypoint | `tests/integration/test_web3_audit_cli.py::test_audit_prints_every_bucket_not_just_slither` |

## Product and market

| # | Risk | Status | Held by | Measured by |
|---|---|---|---|---|
| 15 | A crowded category: the metadata scanner people know was acquired, and a large vendor gives a pattern scanner away | open | - | not a code property. See `docs/competitive-landscape-2026.md`, collected 2026-08-11; re-collect rather than trust it |
| 16 | The value of an agent is a low false-positive rate, not a solve rate, and agent false positives are measured above human ones | partly | - | `tests/architecture/test_detector_baseline.py::test_whole_subclasses_are_invisible_today` names what is missed. The rate itself is measured only on our corpus — see 11 |
| 17 | A web3 report is not a submission: proof of concept is required at every severity | open | - | the working Foundry exploit lives outside the repository, so nothing runs it |
| 18 | A benchmark nobody outside can reproduce | partly | - | `tests/integration/test_repro_chain.py::test_two_identical_runs_share_fingerprint` pins seed, config and suite. Target image digests and external tool versions are not recorded |

## Legal, reputational, structural

| # | Risk | Status | Held by | Measured by |
|---|---|---|---|---|
| 19 | Publishing numbers produced by a path that was broken | closed | structural | `tests/architecture/test_nothing_publishes_without_the_checks.py::test_the_upload_cannot_run_before_the_guard` |
| 20 | An offensive tool that does not require an authorisation scope | closed | boundary/value | `tests/unit/test_the_refusal_comes_before_the_first_packet.py::test_an_unscoped_run_never_reaches_the_recon_agent` holds the refusal ahead of the pipeline: measured on 2026-09-17, an unscoped run against a protected range had already spent 51 seconds on nmap, whois, dns and subdomain enumeration before the exploit phase declined it. The row said closed while the target was being touched, because the test behind it read a config field rather than the network. `--no-strict-scope` and `CYBERAI_STRICT_SCOPE=0` remain the named ways to proceed anyway, and since 2026-09-19 they are the only ones: `tests/unit/test_strict_scope.py::test_only_a_named_word_turns_the_refusal_off` holds the refusal against a value nobody chose. The flag reader answers "is this one of the words for yes", so an empty variable -- what a shell leaves for `VAR=` in a .env file -- and a misspelling both read as off, which disarmed the one flag here whose default protects the run |
| 21 | Private plans and journals reaching a public repository | unguarded | - | no test and no workflow step checks this. A tree-wide history search finds none of those filenames, which is a measurement of the past, not a guard on the next commit |
| 22 | One developer, measuring by hand | open | - | structural. The mitigation is that every closed row above names a test rather than a memory, and since 2026-09-22 says what kind of test it is, measured rather than asserted. Neither makes a second pair of eyes out of one; both shorten how long a row can be wrong without anyone noticing |
| 23 | A measurement that cannot tell a quiet environment from a clean tree | partly | - | `tests/architecture/test_the_drift_report_refuses_an_unmeasured_environment.py::test_a_checker_that_never_ran_is_not_a_clean_package` and the four rows beside it. Measured on 2026-09-18 on an untouched checkout: with no mypy installed the drift report printed 172 clean modules, 0 errors and no drift and exited zero; without `types-networkx` it printed 275 errors and accused `cyberai/core/kb_graph.py` of being undeclared; on mcp 1.28.1 it printed 284 instead of 285. Five signals, one tree, every guard green, because the guards read declarations rather than the environment. The report now refuses a run it cannot vouch for and names the package that differs. Partly: the same question is unanswered for the test suite, which collected nothing on a machine without `pytest-asyncio` and said so as three collection errors rather than as an unmeasured environment |
| 24 | Configuration naming a provider that does not exist | closed | entrypoint/value | `tests/unit/test_the_config_cannot_name_an_unknown_provider.py::test_an_unknown_provider_does_not_reach_the_config` for the environment and `tests/unit/test_the_cli_cannot_name_an_unknown_provider.py::test_an_unknown_provider_is_refused_by_the_parser` for the flag. `CYBERAI_LLM_PROVIDER=gemini` used to produce a config whose provider was that string, and `api_key_for` then resolved a credential by name: a run asked for one vendor could be sent to another under a key nobody named. Both readers narrow against the declared Literal, not a second list -- `test_the_reader_reads_the_declared_literal_and_not_a_copy` fails if a copy appears. The two boundaries answer differently on purpose: the environment falls back to the default because a stale variable must not abort a scan, the flag is refused because whoever typed it is there to read the reply. The three files carrying this path -- and the validator beside them -- entered `[tool.mypy] files` in the same commits, which is what makes the assignments visible to CI at all |
