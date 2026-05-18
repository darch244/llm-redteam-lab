# Ethics & Authorized Use

Advanced LLM security testing trades on edge cases — the same techniques that
find real vulnerabilities can, misused, harm real users. Read this before
running anything.

## Authorization is non-negotiable

- **Written scope.** Have the system owner's written authorization covering the
  specific targets, time window, and permitted techniques you will use.
- **Scope creep is a vulnerability.** The lab ships 110 probes plus scenarios;
  running the `full` suite against an API you are allowed to test is fine.
  Repurposing it against an endpoint that is out of scope is not.
- **Bug bounty ≠ blanket authorization.** Platform program scopes (HackerOne,
  Bugcrowd, Intigriti, vendor VDPs) define exactly what is testable. Read the
  in-scope section before every engagement; respect rate limits and testing
  windows.

## Operational discipline

- **Prefer the mock target** when learning the tooling — zero external impact.
- **Use the least harmful technique set** that answers the question you need
  answered. If a heuristic/offline result answers it, don't hit the production
  model.
- **Reduce collateral:** minimal probe counts, paced requests, `--offline`
  where possible, and never target user-generated content channels casually.
- **Handle findings carefully:** The reports you generate embed real prompts,
  responses and repro steps and are designed to be redacted and *shared with
  the target's defenders*. They are not intended to help third parties
  re-attack the victim.

## Our specific trade-offs

- **Probe libraries are attacker-oriented by design.** They exist so defenders
  can reproduce the same class of failures and harden against them. If you
  ship a probe, ship the *defence* in the rationale (what good hardening looks
  like).
- **Indirect-injection / RAG fixtures** live under `examples/` so the poisoning
  mechanics are transparent and self-contained — you can demod everything
  against the mock target.
- **The `mock` target cannot be "owned".** Prefer `mock` for education, CI,
  and environment validation; reserve real provider targets for engagements
  where you have authorization and the impact is justified.

## If you're new

1. Run `rtl scan --target mock --suite suites/quick.yaml`.
2. Read the generated `report.html` — understand what `succeeded` /
   `refused` / `ambiguous` mean operationally.
3. Run the same suite against a local Ollama model (your own machine, your own
   model) before touching any hosted system.

This project and its contributors are not liable for misuse. When in doubt,
don't.