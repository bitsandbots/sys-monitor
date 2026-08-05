# Testing Strategy — [PROJECT_NAME]

> Copy this file into the repo root as `TESTING_STRATEGY.md` and fill in the bracketed
> sections. Use the prompt library (`blueprint-testing-prompts.md`) to generate the actual
> content — this doc is the standard; the prompts are how you produce what it points to.
> Not every section applies to every project — see the note on Section 10.
> Last reviewed: [DATE] by [OWNER]

## 1. Definition of Done

A change to this project is considered properly tested when:
- [ ] It's covered by an acceptance criterion linked to the blueprint (Section 2), OR is
      infrastructure/tooling with no blueprint-level behavior to cover.
- [ ] For any multi-step workflow it touches, the workflow still reaches a verified terminal
      state end-to-end (Section 3) — not just its first step or two.
- [ ] Any bug fix ships with a regression test that fails without the fix (Section 4).
- [ ] Any change at an integration seam (Section 5) passes the contract tests on both sides.
- [ ] AI-generated/AI-assisted components (Section 6) don't drop the eval score below
      [THRESHOLD].
- [ ] Mutation score (Section 7) on touched files doesn't drop below [THRESHOLD] — coverage
      % alone is not sufficient evidence.
- [ ] No new flaky tests introduced (Section 7); existing quarantine list isn't growing.
- [ ] No performance regression past [X]% on benchmarked operations (Section 8).
- [ ] No new high/critical security or dependency findings (Section 9).
- [ ] The full suite passes via the single harness command (Section 11) — not just locally,
      in the containerized run.

## 2. Blueprint & Acceptance Spec

- Blueprint source: [PATH OR LINK]
- Acceptance spec (generated via Prompt 1): [PATH, e.g. `/tests/acceptance/spec.yaml`]
- Current conformance: [X / Y criteria covered] — last measured [DATE]
- Criteria ID convention: [e.g. `AUTH-001`, `DATA-014`]

Any blueprint requirement without a linked acceptance criterion is a gap, not an oversight —
track it here rather than letting it stay implicit:

| Requirement | Criterion ID | Status | Notes |
|---|---|---|---|
| [ ] | | UNCOVERED / COVERED | |

## 3. Workflow / Multi-Step Completion Coverage

The most common false sense of security: a workflow "has tests" but they only exercise the
first step or two. Track actual path coverage per workflow, not just presence/absence of a
test.

| Workflow | Total steps/states | Steps entered by tests | Exit transitions verified | Resume/retry paths tested | Full-completion test exists |
|---|---|---|---|---|---|
| [e.g. job submission → processing → notify] | | | | | Y/N |

- Workflows still needing full-path coverage (ranked by how far short they fall): [list]
- Workflows too expensive to run fully in tests, and the cheaper stand-in used instead
  (fakes / time-warping / checkpoint replay): [list]

## 4. Regression Suite

- Test framework: [e.g. pytest, jest, go test]
- Location: [PATH]
- Rule: no bugfix PR merges without a regression test reproducing the original bug (enforced
  via [PR template / CI check / code review checklist — pick one]).
- Property-based / snapshot testing used for: [list components where input space is large —
  parsers, validators, config loaders, etc., or "none yet"]

## 5. Integration Contracts

List every project/system this one talks to, and where the contract for each is defined.
Implicit contracts (only inferable by reading both codebases) are the highest-risk rows —
flag and prioritize them.

| Talks to | Mechanism | Contract defined at | Consumer tests | Provider tests | Status |
|---|---|---|---|---|---|
| [Nexus / CoreConductor / etc.] | [API / queue / file / CLI] | [PATH or "implicit — TODO"] | [PATH] | [PATH] | |

End-to-end smoke tests (real wired-up path, highest-risk flows only):
- [ ] [Flow 1 — path to test]
- [ ] [Flow 2 — path to test]

## 6. Evals (AI-generated / AI-assisted components)

- Components covered: [PATH(S)]
- Scenario set: [PATH, count]
- Rubric/scoring: [PATH or brief description]
- Score history: [PATH to log, or tool used to track over time]
- Alert threshold: flag if aggregate score drops more than [X]% between runs

## 7. Suite Trust: Mutation Testing & Flaky Test Management

- Mutation testing tool: [e.g. mutmut, Stryker, PIT, cargo-mutants]
- Current mutation score: [X%] (vs. line/branch coverage of [Y%] — the gap between these two
  numbers is the real signal, not either one alone)
- Known surviving mutants in high-risk files: [list or link]
- Flaky test quarantine list: [PATH or link], current size: [N]
- Quarantine policy: [how long a test can stay quarantined before fix-or-delete, and owner]

Caution: neither coverage % nor mutation score is a target to maximize for its own sake —
they're gap-finders. Don't spend effort chasing the last few points in low-risk code at the
expense of Section 3's workflow coverage.

## 8. Performance & Load Benchmarks

- Benchmarked operations: [list — the ones where latency/throughput actually matters]
- Tool: [e.g. pytest-benchmark, k6, JMH, hyperfine]
- Baseline stored at: [PATH]
- Regression threshold: flag if any benchmark degrades more than [X]% vs. baseline
- Operations that are performance-sensitive per the blueprint but not yet benchmarked:
  [list]

## 9. Security & Dependency Scanning

- Dependency/SCA scan: [tool], run [cadence]
- SAST scan: [tool], focused on: [auth / secrets / deserialization / cross-project input]
- Secret-scanning covers full git history: [Y/N]
- Gating vs. reporting: [which checks block merge vs. just report]
- Current open findings: [PATH or link, count by severity]

## 10. Non-Determinism & Fault Injection

> Only fill in this section if this project coordinates multiple agents/services, makes
> non-deterministic decisions, or must tolerate component failure. Delete the section if it
> doesn't apply rather than leaving it blank — an empty section reads as an unassessed gap.

- Components/paths that are intentionally non-deterministic: [list] — tested via replay
  fixtures against "acceptable outcome," not exact match.
- Components that SHOULD be deterministic: [list] — held to exact-match tests.
- Fault-injection scenarios covered (node/agent killed mid-task, message dropped/delayed,
  downstream timeout or malformed response): [list, with expected behavior per blueprint and
  test status]
- Failure modes the blueprint doesn't yet specify behavior for (blueprint gap, feed back into
  Section 2): [list]

## 11. Test Harness

- Single entrypoint: `[e.g. make test]`
- Containerized: [Yes/No — tool, e.g. Docker, pinned versions at PATH]
- Host prerequisites checked by preflight: [list, or PATH to preflight script]
- Hosts this must run identically on: [list or describe variety]
- Output: single scorecard — pass/fail per category (unit, regression, workflow completion,
  contract, eval, performance, security) + conformance % + mutation score

## 12. CI Wiring

- Triggers on: [push / PR / schedule]
- Gates merge on: [which categories from Section 11 must pass]
- Runs on: [which host/OS matrix]

## 13. Closing the Loop: Incidents → Acceptance Criteria

- Incident/postmortem source: [PATH or link]
- Process: every production incident produces either a new/corrected acceptance criterion
  (Section 2) plus a linked regression or workflow test, or an explicit note that the
  blueprint already covered it and only test coverage was missing.
- Recent incidents reviewed and closed the loop on: [list or link]
- Patterns noticed across incidents (e.g. "most come from untested mid-workflow failure
  paths"): [notes]

## 14. Blueprint Versioning / Spec-First Discipline

- Blueprint is version-controlled: [Y/N, location]
- Process: blueprint changes and behavior changes land together (same PR or explicitly
  linked PRs) — [describe or link to the actual rule/enforcement]
- Last checked for blueprint/implementation divergence: [DATE], findings: [notes]

## 15. Review Cadence

- Full conformance re-check (Prompt 14 from the prompt library): [weekly / every release / on
  demand]
- Owner: [who reviews drift when it's flagged]

## Appendix: Prompts

This doc is filled in and kept current using the shared prompt library. Quick reference —
run the numbered prompt against the section it maps to:

| Section | Prompt |
|---|---|
| 2 — Acceptance Spec | Prompt 1 |
| 3 — Workflow Completion Coverage | Prompt 2 |
| 4 — Regression Suite | Prompt 3 |
| 5 — Integration Contracts | Prompt 4 |
| 6 — Evals | Prompt 5 |
| 7 — Mutation Testing | Prompt 6 |
| 7 — Flaky Test Management | Prompt 7 |
| 8 — Performance & Load Benchmarks | Prompt 8 |
| 9 — Security & Dependency Scanning | Prompt 9 |
| 10 — Non-Determinism & Fault Injection | Prompt 10 |
| 11 — Test Harness | Prompt 11 |
| 13 — Closing the Loop | Prompt 12 |
| 14 — Blueprint Versioning | Prompt 13 |
| Whole-doc drift check | Prompt 14 |

Full prompt text: see `blueprint-testing-prompts.md`.
