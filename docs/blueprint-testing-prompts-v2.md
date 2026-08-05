# Blueprint-Driven Testing — Prompt Library

A set of reusable prompts for turning docs + blueprints into an actual, objective testing
practice across cc-platform, Nexus, CoreConductor, and similar projects. Swap in the
bracketed placeholders (`[PROJECT_NAME]`, `[PATH]`, etc.) for each project you run these
against.

Run Prompt 0 first; it triages which of the others actually apply to that project. Not every
prompt fits every project — #10 (non-determinism/fault injection) in particular only applies
if the project is an orchestration/agent-coordination system; confirm that before running it
rather than assuming.

---

## 0. Kickoff / Triage

```
I want to build a real testing practice for [PROJECT_NAME], located at [REPO_PATH].
The blueprint/design doc is at [BLUEPRINT_PATH] (or: describe it if there's no single file).

Before writing anything, audit the current state:
1. What automated tests exist today (unit, integration, e2e)? Where do they live, what do
   they run with, and roughly what do they cover?
2. Does the blueprint contain requirements that have NO corresponding test anywhere in the
   codebase? List the gaps.
3. Is there any CI config? Does it run on every host type this project targets, or just one?
4. Are there parts of this project that are AI-generated or AI-assisted (vs. hand-written)?
   Flag them — they need eval-style testing, not just unit tests.
5. Does this project talk to other projects (e.g. cc-platform, Nexus, CoreConductor) over an
   API, message queue, shared file format, or CLI? List each integration point.
6. Does this project run multi-step workflows, pipelines, or state machines (a request or
   job that moves through several stages)? List them — these need the workflow-completion
   check in Prompt 2, not just ordinary unit tests.
7. Is this project (or any part of it) an orchestration/agent-coordination system where
   behavior can be non-deterministic or where components can fail/restart independently? If
   so, flag it for Prompt 10.

Give me a short scorecard: conformance (% of blueprint requirements with a linked test),
regression coverage (rough %), integration points tested vs. untested, workflows tested to
full completion vs. only partially, and whether evals exist for the AI-generated parts. Then
recommend which prompts to run next, in priority order.
```

---

## 1. Turn the Blueprint into an Acceptance Spec (kills drift, gives you pass/fail)

```
Read the blueprint for [PROJECT_NAME] at [BLUEPRINT_PATH] and the current codebase at
[REPO_PATH]. Convert every requirement in the blueprint into an atomic, checkable
acceptance criterion using given/when/then form.

Rules:
- One criterion = one observable, testable behavior. Split compound requirements apart.
- For any requirement describing a multi-step process, write a criterion for the workflow
  REACHING its terminal state and producing its real end effect — not just for the first
  step succeeding. (Full workflow coverage is handled in depth by Prompt 2; this just makes
  sure the spec itself doesn't stop at step one.)
- Write output as [Gherkin .feature files | a YAML file with id/description/given/when/then]
  — pick whichever this project's stack can consume as an actual test input.
- Each criterion gets a stable ID (e.g. AUTH-001) so it can be linked to a test later.
- For every criterion, note whether a test already exists in the codebase that covers it. If
  yes, name the test file/function. If no, mark it UNCOVERED.
- Call out any blueprint language that's too vague to convert into a criterion as-is (e.g.
  "should be fast," "should handle errors gracefully") and propose a concrete, measurable
  version for me to confirm before you finalize it.

Finish with a conformance summary: total criteria, % covered, and the top 10 UNCOVERED
criteria ranked by how critical they look (auth, data integrity, and public API surface rank
highest).
```

Follow-up, once you've reviewed the spec:

```
For the top [N] UNCOVERED criteria from the acceptance spec, write the actual test code in
[TEST_FRAMEWORK]. Link each test back to its criterion ID in a comment or annotation so the
mapping stays traceable as the code changes.
```

---

## 2. Workflow / Multi-Step Completion Coverage

The most common gap in a testing suite that otherwise looks healthy: tests exercise the
first step or two of a workflow (the part that's easy to trigger and mock) and stop, leaving
the rest of the flow — including error paths, retries, and the actual terminal state — never
actually run.

```
For [PROJECT_NAME] at [REPO_PATH], identify every multi-step workflow, pipeline, or state
machine in the system — any request or job that moves through more than one stage,
including orchestrations that call out to multiple sub-agents/services, and async jobs with
several phases.

For each workflow:
1. Enumerate every step/state/transition it can pass through, including error paths,
   retries, timeouts, and resume-from-checkpoint paths — not just the happy path.
2. Check existing tests: do they assert only that the workflow STARTED (kicked off without
   error) or that step 1-2 succeeded, and stop there? Flag any test that mocks or stubs out
   the middle or final steps instead of exercising them for real.
3. For each step, report whether it's covered by a test that (a) enters that step and (b)
   verifies the correct transition/exit out of it. Produce a step/transition coverage
   table, not just an overall pass/fail — a workflow can look "tested" while only its first
   20% is ever actually exercised.
4. Write or strengthen tests so every workflow has at least one test that runs it to a real
   terminal state and confirms the actual side effects of completion (data written,
   downstream systems notified, resources released, callbacks fired) — not just "no
   exception was thrown along the way."
5. Add tests for resuming a workflow that was interrupted partway through, and for the
   workflow re-entering an error/retry branch mid-flow, if the system supports either —
   these paths are usually the least tested and most likely to be broken in practice.
6. Where a full run is expensive or slow to test (needs real external systems, takes a long
   time), propose a cheaper way to still exercise it end-to-end — fakes, time-warping,
   checkpoint replay, or a scaled-down version of the same path — rather than leaving it
   permanently untested past step 2.

Output a coverage table per workflow: total steps, steps entered by tests, steps whose exit
transition is verified, and whether a full-completion test exists. Rank workflows by how far
short they fall of full-path coverage, and treat that ranking as the priority order for
follow-up test-writing.
```

---

## 3. Regression Safety Net

```
For [PROJECT_NAME] at [REPO_PATH]:

1. Scan git history / issue tracker (if accessible) for the last [10-20] bug fixes. For each
   one, tell me whether a regression test was added alongside the fix. List the ones that
   weren't.
2. For any fix that shipped without a regression test, write one now that reproduces the
   original bug (it should fail against the pre-fix code and pass against current code).
3. Propose a standing rule I can enforce going forward: no bugfix PR merges without a
   regression test. Draft it as a short CONTRIBUTING.md or PR-template snippet.

Where the codebase has logic that's naturally table-driven or has many input variants
(parsers, validators, config loaders, API handlers), prefer property-based or snapshot tests
over hand-enumerated cases — flag where those would pay off most.
```

---

## 4. Contract Tests at Integration Seams (kills cross-project gaps)

```
[PROJECT_NAME] integrates with [OTHER_PROJECT(S), e.g. Nexus, CoreConductor] via
[API calls | message queue | shared files | CLI invocation — describe if known, otherwise
ask me to confirm].

For each integration point:
1. Define the contract explicitly: request/response schema, message format, required
   fields, error conditions, timing/ordering assumptions — whatever actually crosses the
   boundary.
2. Write it down in a shared, versioned format (JSON Schema, OpenAPI, protobuf, or a plain
   markdown contract doc if nothing more formal fits) so both sides can test against the
   same source of truth.
3. Write consumer-side tests that validate [PROJECT_NAME]'s requests/messages conform to the
   contract, and provider-side tests that validate its responses conform to it — without
   requiring the other full system to be running (use fakes/mocks built FROM the contract,
   not hand-guessed).
4. Propose 3-5 true end-to-end smoke tests that exercise the real wired-up path
   ([PROJECT_NAME] + [OTHER_PROJECT]) for the highest-risk flows only — not full coverage,
   just enough to catch "the contract was right but the wiring wasn't."

Flag any integration point where the contract is currently implicit (only inferable from
reading both codebases) — those are the highest-risk gaps.
```

---

## 5. Evals for AI-Generated Components

```
[PROJECT_NAME] has AI-generated or AI-assisted components at [PATH(S)]. Standard unit tests
don't catch quality drift here, so set up an eval harness:

1. Build a fixed set of representative input scenarios (aim for [10-30] to start), covering
   typical cases, edge cases, and at least a few adversarial/malformed inputs.
2. For each scenario, define what a graded "good" output looks like — a rubric or scoring
   function, not just pass/fail. Keep the grading criteria explicit and written down, not
   just "looks right."
3. Write a runnable script that executes all scenarios against the current build and outputs
   a score (per-scenario and aggregate).
4. Store scores with a timestamp/commit hash so I can track quality over time and catch
   silent regressions in AI-generated output across builds.

Tell me if any scenario's "good" definition is genuinely ambiguous — I'd rather resolve that
now than bake in a bad rubric.
```

---

## 6. Suite Trust Check: Mutation Testing

Coverage percentage tells you what ran, not what would actually catch a bug. This checks the
difference.

```
For [PROJECT_NAME] at [REPO_PATH], run mutation testing on the existing test suite using
[TOOL — e.g. mutmut/cosmic-ray for Python, Stryker for JS/TS, PIT for Java, cargo-mutants for
Rust — pick what fits the stack].

1. Report the mutation score (% of introduced bugs the suite actually caught) alongside the
   existing line/branch coverage %, so I can see the gap between "ran" and "would catch a
   real bug."
2. List the specific surviving mutants (bugs the suite missed) in the highest-risk files
   (auth, data integrity, public API, payment/billing if applicable) and propose the
   specific assertion each corresponding test is missing.
3. Don't chase 100% mutation score — flag anywhere the number is being used as a vanity
   metric rather than a signal, and tell me if effort would be better spent elsewhere (e.g.
   Prompt 2's workflow coverage) instead of killing the last few mutants in low-risk code.
```

---

## 7. Flaky Test Management

Running the same suite across [a variety of Linux hosts] will surface flakiness that a
single-host setup hides. Untracked flakiness quietly trains everyone to distrust red builds.

```
For [PROJECT_NAME] at [REPO_PATH]:

1. Identify tests that have failed intermittently (check CI history if available, or run the
   suite [N] times in a row locally/in CI to surface non-deterministic failures).
2. For each flaky test, diagnose the likely cause (race condition, shared state between
   tests, time/order dependency, external network call, uncontrolled randomness) rather than
   just flagging it as flaky.
3. Fix what's fixable now. For anything that needs more investigation, add it to a
   quarantine list (skipped in the main gating run, still executed and reported separately)
   so it doesn't block merges but also doesn't get silently forgotten.
4. Propose a policy: how long a test can stay quarantined before it's fixed or deleted, and
   who owns tracking that list.
```

---

## 8. Performance & Load Regression Benchmarks

```
For [PROJECT_NAME] at [REPO_PATH], identify the operations where latency, throughput, or
resource usage actually matters (the ones a user or dependent system would notice if they
got slower) — [e.g. specific API endpoints, orchestration steps, or batch jobs].

1. Write benchmarks for those operations using [TOOL — e.g. pytest-benchmark, k6, JMH, hyperfine].
2. Establish a current baseline and store it alongside the code (not just in a dashboard that
   disappears).
3. Add a check that flags a regression if a benchmark degrades more than [X]% versus the
   stored baseline, and wire it into the harness from [the portable harness prompt] so it
   runs the same way on every host.
4. Call out any operation that's performance-sensitive per the blueprint but currently has no
   benchmark at all.
```

---

## 9. Security & Dependency Scanning

```
For [PROJECT_NAME] at [REPO_PATH]:

1. Run a dependency/software-composition scan ([e.g. `pip-audit`, `npm audit`, `cargo audit`,
   `trivy`, `grype` — pick what fits] ) and report known vulnerabilities by severity.
2. Run a static analysis / SAST pass appropriate to the language ([e.g. `bandit`, `semgrep`,
   `gosec`]) focused on the highest-risk areas: anything handling auth, secrets,
   deserialization, or cross-project input from [OTHER_PROJECTS].
3. Check for hardcoded secrets or credentials in the repo history, not just the current tree.
4. Propose which of these checks should gate CI (block merge) versus just report, and how
   often the full scan should re-run given dependencies drift even without code changes.
```

---

## 10. Non-Determinism & Fault Injection (orchestration/agent-coordination systems only)

Only run this if Prompt 0 flagged the project as coordinating multiple agents/services,
making decisions that aren't strictly deterministic, or needing to tolerate component
failure. Confirm that's actually this project's shape before using it.

```
[PROJECT_NAME] coordinates [agents/services/nodes — describe] and may not always produce
byte-identical output for the same input. Build tests appropriate to that:

1. Capture real interaction traces (or representative synthetic ones) as replayable
   fixtures, and test against "did this converge on an acceptable outcome" rather than
   "did this produce an identical output" where exact determinism isn't the real
   requirement — but be explicit about which parts of the system SHOULD be deterministic
   and hold those to exact-match tests instead.
2. Design fault-injection tests for the failure modes that matter here: killing a
   node/agent mid-task, dropping or delaying a message, a downstream dependency timing out
   or returning malformed data. For each, state what the blueprint claims should happen
   (retry, failover, degrade gracefully, surface an error) and test that it actually does.
3. Combine this with Prompt 2's workflow-completion coverage: a fault injected mid-workflow
   should still be checked against whether the workflow reaches a defined terminal state
   (success, or a well-defined failure state) rather than hanging or silently dropping work.
4. Flag any failure mode the blueprint doesn't actually specify behavior for — that's a
   blueprint gap, not just a test gap, and belongs back in Prompt 1.
```

---

## 11. Portable Test Harness (one command, same result on every host)

```
[PROJECT_NAME] needs to run identically across [LIST HOSTS / describe variety, e.g. "several
local Linux boxes with different distros/versions"]. Set up a single-entrypoint test harness:

1. Create one command (Makefile target or script) that runs the full test suite — unit,
   regression, workflow-completion, contract, eval, performance, and security checks from
   earlier — with no manual setup steps beyond running it.
2. Containerize the test environment (Docker or Podman) so dependency/OS drift between hosts
   can't cause false passes/fails. Pin versions.
3. Add a preflight check that verifies host prerequisites (Docker installed, required ports
   free, disk space, etc.) and fails fast with a clear message instead of a confusing test
   failure.
4. Output a single structured summary at the end: pass/fail counts per category (unit,
   regression, workflow completion, contract, eval, performance, security) plus the
   conformance % from the acceptance spec and the mutation score, so I get one scorecard
   regardless of which host ran it.

Test it by describing what would happen on a host with [an older Docker version | no GPU |
whatever varies most across your hosts] and flag any assumption that would break there.
```

---

## 12. Closing the Loop: Incidents → Acceptance Criteria

```
For [PROJECT_NAME], review [the last N production incidents / bug reports / postmortems —
point me at where these live if I have access].

For each one:
1. Determine whether the blueprint or acceptance spec actually specified the correct
   behavior for the situation that caused the incident. If it did and the test coverage was
   just missing, add the missing test. If the blueprint itself was silent or wrong about it,
   flag it as a blueprint gap rather than only a test gap.
2. Draft the new or corrected acceptance criterion (same ID convention as Prompt 1) so the
   spec reflects what SHOULD have been true, and link it to a new regression/workflow test
   that would have caught this before it shipped.
3. Summarize any pattern across incidents (e.g. "most incidents come from untested
   mid-workflow failure paths") so I know where to invest beyond just patching each one.
```

---

## 13. Blueprint Versioning / Spec-First Discipline

```
For [PROJECT_NAME]:

1. Check whether the blueprint at [BLUEPRINT_PATH] is version-controlled alongside the code
   (same repo, or at least linked commit history). If not, propose how to get it there.
2. Compare the current blueprint against the current acceptance spec and codebase behavior —
   flag anywhere they've diverged (blueprint says X, code does Y, with no record of an
   intentional decision to change it).
3. Propose a lightweight process: blueprint changes and behavior changes land together (same
   PR or explicitly linked PRs), so the spec and the implementation can't silently drift
   apart the way a standalone doc does.
```

---

## 14. Ongoing Discipline (run periodically, not just once)

```
For [PROJECT_NAME]: compare the current codebase against the acceptance spec at
[SPEC_PATH] and regenerate the full conformance scorecard:
- blueprint criteria covered / total
- workflow-completion coverage per workflow (steps entered vs. steps with verified exit,
  full-completion test present or not)
- regression test count and flaky-test quarantine list size
- contract test status per integration point
- latest eval scores and trend
- mutation score and coverage %
- performance benchmark status (any regressions past threshold)
- open security/dependency findings
- any blueprint/spec divergence found

Call out anything that regressed since the last run, any new blueprint content not yet
converted into criteria, and any eval or performance score that dropped more than [X]% since
the last run. Keep this to a short status report, not a rewrite of the spec — flag drift,
don't fix it silently.
```

---

### How to use this file
Run Prompt 0 against one project first (pick the most painful one). Its output tells you
which numbered prompts actually apply — you likely won't need all fourteen for every
project, and #10 in particular only applies to orchestration/agent-coordination systems.
Prompts 1-5 build the core practice; 6-10 harden it; 11 makes it portable; 12-13 keep it from
decaying over time; 14 is the recurring check. Re-run Prompt 14 on a cadence (e.g. weekly, or
on every release) to keep drift visible instead of silent.
