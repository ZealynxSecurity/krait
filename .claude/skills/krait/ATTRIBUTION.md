# Detection Sources

Krait's detection layer combines original research with curated knowledge from the open-source security community. All integrated content is from MIT-licensed repositories.

| Source | What We Integrated | License | Link |
|--------|-------------------|---------|------|
| **pashov/skills** | ~100 attack vectors across 8 modules + 58 extended heuristics | MIT | [github.com/pashov/skills](https://github.com/pashov/skills) |
| **PlamenTSV/plamen** | Devil's Advocate verification methodology, cross-cutting analysis perspectives | MIT | [github.com/PlamenTSV/plamen](https://github.com/PlamenTSV/plamen) |
| **forefy/.context** | Protocol-type context enrichment across 7 primers (10,600+ findings distilled) | MIT | [github.com/forefy/.context](https://github.com/forefy/.context) |

## What's Original to Krait

- Full audit pipeline architecture (recon → detect → state analysis → verify → report)
- 8 kill gates with zero-FP track record across 45 contests
- Deterministic file risk scoring formula
- Module trigger system (tier 0/1/2 with evidence-based activation)
- Shadow audit benchmarking methodology and self-improvement loop
- 43 original heuristics derived from missed findings in blind contest testing
- Consensus scoring across multi-lens, multi-mindset analysis

Built by [Zealynx Security](https://zealynx.io).
