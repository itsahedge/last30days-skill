---
title: claude.ai distribution + discoverability push
type: feat
status: active
date: 2026-04-14
---

# claude.ai distribution + discoverability push

## Overview

The 200-file upload bug is fixed and `last30days.skill` works on claude.ai. But "it can be uploaded" is not the same as "people use it." Claude.ai has no native skill marketplace, so discovery happens through a 3-layer stack: Anthropic's curated plugin marketplace, third-party aggregators, and social/newsletter amplification. The question Matt asked - "is the GitHub release the right decision" - has a clear answer: yes, but it is table stakes, not the strategy. This plan cuts the release and then pulls the real distribution levers.

## Problem Frame

Today, the only way a claude.ai user can get `last30days` is to clone the repo and run `scripts/build-skill.sh`. That filters out 99% of potential users. Even once a release exists with a direct download link, the hard problem is discovery - claude.ai users do not browse GitHub for skills. They find skills via Anthropic's "Discover" tab in Claude Code, third-party aggregator sites (skillsmp.com, mcpmarket.com, claudeskills.info), awesome-lists on GitHub, newsletters (The Neuron), and social posts (X, r/ClaudeAI).

Success looks like: a claude.ai user who never visits the repo can find, download, and upload the skill in under 60 seconds, and keep using it because the trigger description fires on the right prompts.

## Requirements Trace

- R1. A one-click install path exists for claude.ai users: click a link from README/marketplace/aggregator, get `last30days.skill`, drop into Upload dialog
- R2. The skill is submitted to Anthropic's official plugin marketplace at `platform.claude.com/plugins/submit`
- R3. The skill is listed in at least 4 high-traffic awesome-lists / aggregators
- R4. The SKILL.md YAML `description` and `argument-hint` fields are tuned so Claude's skill-selector actually invokes `last30days` on research-intent prompts (trigger quality is the single biggest install-to-reuse lever)
- R5. First-run experience works with zero API keys for the default sources (Reddit, Hacker News, Polymarket, GitHub) - already true, verify does not regress
- R6. At least one high-visibility amplification moment ships within 14 days: demo GIF + launch tweet + The Neuron pitch
- R7. Basic metrics are in place to learn what works: release-download counts, aggregator referrer traffic, GitHub star velocity before/after

## Scope Boundaries

Non-goals for this plan:
- Not building a custom skill-hosting site or our own marketplace
- Not changing the runtime pipeline or adding features - this is pure distribution
- Not spamming aggregators with low-effort PRs - one quality submission per venue
- Not gaming install counts or stars
- Not displacing the existing Claude Code plugin / OpenClaw / Gemini distribution - those stay as-is, cross-linked
- Not depending on Anthropic marketplace acceptance before other levers ship - marketplace review is slow and gate-able

## Context and Research

### The claude.ai skill ecosystem in April 2026

- **No native claude.ai skill marketplace.** Upload is the only end-user path inside the web UI.
- **Anthropic's Plugin/Skills Marketplace** (submissions at `platform.claude.com/plugins/submit`) is the closest thing to a "featured" channel and ships through Claude Code's "Discover" tab. Quality/security review gates acceptance. Research-category skills are under-represented vs. dev-tool skills.
- **Third-party aggregators** drive most organic discovery outside Anthropic's channels:
  - `skillsmp.com`, `mcpmarket.com`, `claudeskills.info`, `skillsdirectory.com`, `agensi.io`
  - These aggregators scrape awesome-lists, so one well-placed PR cascades
- **Awesome-lists** where skills discovery congregates:
  - `ComposioHQ/awesome-claude-skills`
  - `travisvn/awesome-claude-skills`
  - `karanb192/awesome-claude-skills`
  - `VoltAgent/awesome-agent-skills`
  - `sickn33/antigravity-awesome-skills` (1,400+ skills indexed)
- **Newsletter amplification:** The Neuron runs a daily "AI Skill of the Day" digest - the single biggest external traffic source per successful skill creators. Their "practical workflow" angle fits a research skill cleanly.
- **Install-count reference points** from public aggregator data:
  - `self-improving-agent`: 357k installs
  - `frontend-design`: 277k installs
  - `skill-vetter`: 190k installs
  - `github`: 148k installs
  - `proactive-agent`: 135k installs
  - Long tail: ~500 installs

The gap between 500-install and 357k-install skills is mostly: (a) trigger description quality, (b) zero-config first run, (c) one amplification moment that caught.

### Current distribution surface for last30days

- Claude Code plugin via marketplace and GitHub URL: live
- OpenClaw via ClawHub (`clawhub install last30days-official`): live
- Gemini extension: live
- Manual `git clone`: documented in README
- claude.ai `.skill` upload: just shipped, undocumented for end users (no link)

The cross-linking graph is incomplete. Traffic that already exists (Claude Code install page, OpenClaw listing, Gemini extensions page) is not being routed to the new claude.ai path.

### Reference: trigger description quality

The root `SKILL.md` `description` field is how Claude decides whether to invoke the skill. Current text (as of 3.0.1, 167 chars):

> "Multi-query social research across Reddit, X, YouTube, TikTok, Instagram, Hacker News, Polymarket, and the web. Intelligent query planning with Gemini/OpenAI fallback."

Analysis: solid source list, weak on action verbs and example queries. Successful skills include imperative verbs ("research", "find", "summarize", "compare") and 1-2 example triggers the user might type. At 167/200 chars, there is room.

## Key Technical Decisions

- **Cut v3.0.1 GitHub release with `last30days.skill` attached as an asset** (table stakes). Rationale: every downstream lever (README link, marketplace submission, aggregator PR, tweet) needs a stable public download URL.
- **Automate `.skill` build in CI on tag push** so future releases never forget to attach the artifact. Rationale: manual builds break over time; this is a one-time 10-line GitHub Actions workflow.
- **Prioritize marketplace submission in parallel with aggregator PRs**, not in sequence. Rationale: marketplace review is slow and opaque; do not block aggregator work on it. If rejected, we still have the aggregator presence.
- **Tune the SKILL.md description to optimize trigger selection**, not marketing copy. Rationale: this is the single biggest re-use lever per the ecosystem research. Marketing copy goes in README/release notes, not frontmatter.
- **One quality pass per aggregator, not a spray.** Rationale: awesome-list maintainers reject duplicate / low-effort PRs; reputation matters.
- **Ship the launch tweet with a real demo GIF**, not a screenshot. Rationale: Boris Cherny's Claude Code viral tweet template (one query, one result, "oh wow" moment) consistently outperforms text-only launches.
- **Pitch The Neuron once, with a production-quality 60-second demo**, not a cold email. Rationale: single shot at the biggest amplifier; treat it like a press release, not a tweet.
- **Track release-download count + GitHub referrer traffic as proxies for adoption** until we have better signal. Rationale: claude.ai upload counts are not exposed to creators.
- **Cross-link existing distribution pages back to claude.ai** as part of the release. Rationale: converting existing users to multi-surface users is cheaper than acquiring new ones.

## Open Questions

### Resolved during planning

- Is the GitHub release the right first step? Yes. Every other lever depends on a stable download URL. But it is a prerequisite, not the strategy.
- Does claude.ai have a native skill directory? No (confirmed April 2026).
- Should we wait for Anthropic marketplace acceptance before shipping other levers? No - parallelize.
- Do we need to rebuild the runtime to improve claude.ai adoption? No - the runtime is strong; the gap is distribution.

### Deferred to implementation

- Exact Neuron pitch copy - draft during Unit 8, refine based on what their recent editions have favored
- Whether to tag `@steipete`, `@AnthropicAI`, `@alexalbert__` in the launch tweet - confirm current handles and review each's posting culture before tagging
- Which specific demo query to record for the launch GIF - pick during Unit 7 based on what's newsworthy that week
- Whether to request a "skills-research" badge on skillsdirectory.com/agensi.io - check their current badge programs during Unit 5

## High-Level Technical Design

> *This illustrates the intended distribution graph and is directional guidance for review, not implementation specification.*

```
[GitHub Release v3.0.1]
    |
    +-- last30days.skill (asset, public URL)
    |
    +------> README "Upload to claude.ai" section (Unit 3)
    |
    +------> Claude Code plugin README link (Unit 4)
    +------> OpenClaw listing link (Unit 4)
    +------> Gemini extension link (Unit 4)
    |
    +------> Anthropic marketplace submission (Unit 6)
    |
    +------> Aggregator PRs (Unit 5):
    |          * ComposioHQ/awesome-claude-skills
    |          * travisvn/awesome-claude-skills
    |          * karanb192/awesome-claude-skills
    |          * VoltAgent/awesome-agent-skills
    |          * sickn33/antigravity-awesome-skills
    |          * skillsmp.com submit form
    |
    +------> Amplification (Units 7-9):
               * Demo GIF + launch tweet
               * The Neuron "Skill of the Day" pitch
               * News-cycle recurring tweet (weekly)

All paths end at: claude.ai Upload Skill dialog
Trigger quality (Unit 2) determines whether installs become sustained usage
```

## Implementation Units

- [ ] **Unit 1: Cut v3.0.1 GitHub release with `.skill` asset + auto-build CI**

**Goal:** Produce a stable public download URL for `last30days.skill` so every downstream lever has something to link to, and guarantee future releases include the artifact automatically.

**Requirements:** R1

**Dependencies:** None (plan 2026-04-14-001 already shipped the build script)

**Files:**
- Create: `.github/workflows/release.yml`
- Modify: none at release time (release is a git-tag + GitHub release action)

**Approach:**
- Tag `v3.0.1` on `main`, push
- Create GitHub release with the CHANGELOG v3.0.1 entry as body, attach `dist/last30days.skill`
- Add CI workflow that triggers on `push: tags: 'v*'`, runs `bash scripts/build-skill.sh`, uploads the artifact to the release. The `action-gh-release` pattern is standard.
- Release URL shape: `https://github.com/mvanhorn/last30days-skill/releases/download/v3.0.1/last30days.skill` (deterministic, shareable)

**Patterns to follow:**
- Any existing `.github/workflows/` patterns in the repo
- `actions/checkout@v4` + `softprops/action-gh-release@v2` is the conventional combo

**Test scenarios:**
- Happy path: pushing `v3.0.1` tag produces a release with `last30days.skill` attached and publicly downloadable without auth
- Edge case: re-tagging `v3.0.1` does not duplicate or corrupt the asset
- Error path: build failure in the workflow fails the release cleanly (no empty release created)

**Verification:**
- `curl -fsSL -o /tmp/dl.skill https://github.com/mvanhorn/last30days-skill/releases/download/v3.0.1/last30days.skill` succeeds anonymously
- Downloaded file matches `dist/last30days.skill` byte-for-byte
- A second tag (e.g., `v3.0.2-test`) in a branch triggers the workflow end-to-end

- [ ] **Unit 2: Tune SKILL.md description and argument-hint for trigger quality**

**Goal:** Increase the probability that Claude's skill-selector invokes `last30days` on research-intent prompts. Trigger quality is the single biggest install-to-reuse lever per ecosystem research.

**Requirements:** R4, R5

**Dependencies:** None

**Files:**
- Modify: `SKILL.md` (frontmatter `description` and `argument-hint` only)
- Modify: `skills/last30days/SKILL.md` (if parity needed)

**Approach:**
- Rewrite `description` to lead with an imperative action verb and include 1-2 concrete example queries, staying =200 chars
- Rewrite `argument-hint` to show 2-3 canonical invocations that mirror real user phrasing, not marketing phrasing
- Keep the source list intact - that's the value prop - but move it later in the sentence
- Reference frames that worked for high-install skills: `frontend-design`, `self-improving-agent`, `github`

**Technical design:** *(directional guidance, not implementation spec)*

Candidate shape (verify char count in implementation):

```yaml
description: "Research what people actually say about any topic in the last 30 days. Pulls real posts and engagement from Reddit, X, YouTube, TikTok, Hacker News, Polymarket, GitHub, and the web."
argument-hint: 'last30days AI video tools | last30days nvidia earnings reaction | last30days best noise cancelling headphones'
```

**Test scenarios:**
- Happy path: in a fresh claude.ai chat, prompts like "what are people saying about X this week" surface `last30days` in the skill-selector candidate set
- Edge case: generic "research X" prompts do not over-select `last30days` when the user clearly wants a general answer (avoids false-positive selection)
- Integration: test in all three environments - claude.ai web, Claude Code, OpenClaw - to confirm selection behavior is consistent

**Verification:**
- Description =200 chars, checked by the same regex Unit 6 of plan 001 used
- At least 3 real-user prompt phrasings trigger skill selection in manual testing
- No regression on zero-config first-run (no new API keys required)

- [ ] **Unit 3: Rewrite the README claude.ai section with one-click install**

**Goal:** Replace the current "run this bash script" instructions with a one-click download link pointing at the GitHub release asset.

**Requirements:** R1

**Dependencies:** Unit 1 (release must exist first)

**Files:**
- Modify: `README.md` (the "Upload as a Claude Skill" section added in plan 001)

**Approach:**
- Replace the `bash scripts/build-skill.sh` instruction with a direct download link to the release asset
- Keep the build-from-source instruction as a fallback for developers, demoted below the direct link
- Add a short 3-step install guide with specific UI path: "Settings > Capabilities > Skills > + button, drop the .skill file"
- Include a screenshot or GIF showing the upload flow if space allows (can be added in Unit 7)

**Test scenarios:**
- Test expectation: none - pure documentation change

**Verification:**
- A user following the README instructions end-to-end can go from "never heard of this" to working skill in under 60 seconds
- Instructions specify the exact claude.ai UI path current as of the release date

- [ ] **Unit 4: Cross-link existing distribution surfaces back to claude.ai**

**Goal:** Convert existing Claude Code plugin / OpenClaw / Gemini traffic into claude.ai installs. Cheaper than net-new acquisition.

**Requirements:** R1

**Dependencies:** Unit 1, Unit 3

**Files:**
- Modify: `README.md` (install matrix - add claude.ai row prominently)
- Modify: `variants/open/SKILL.md` in the private repo if that governs OpenClaw listing copy
- Modify: `gemini-extension.json` if `description` or install hints exist there
- External: update the ClawHub listing page for `last30days-official` to mention claude.ai availability

**Approach:**
- Every listing page a user currently lands on should have a one-line "Also available as a claude.ai Skill: [download]" link
- Use a consistent short-URL pattern so it's instantly recognizable across surfaces
- Do not require users to re-read each install guide - the cross-link is opportunistic, not blocking

**Test scenarios:**
- Test expectation: none - documentation/external-listing updates

**Verification:**
- Each of the 4 distribution surfaces (Claude Code plugin marketplace, OpenClaw ClawHub listing, Gemini extensions page, GitHub README) contains a visible claude.ai cross-link within 1 scroll of the page top

- [ ] **Unit 5: Submit PRs to high-traffic Claude skill awesome-lists**

**Goal:** Get listed in the 5 highest-traffic aggregators so third-party skill-discovery sites (skillsmp.com, mcpmarket.com, claudeskills.info) pick up the entry.

**Requirements:** R3

**Dependencies:** Unit 1, Unit 2 (description should be tuned before first impression in these lists)

**Files (external repos):**
- `ComposioHQ/awesome-claude-skills` - PR adding last30days to the relevant category
- `travisvn/awesome-claude-skills`
- `karanb192/awesome-claude-skills`
- `VoltAgent/awesome-agent-skills`
- `sickn33/antigravity-awesome-skills`

**Approach:**
- One PR per list, in parallel
- Each PR: one-line entry matching the list's existing format; link to release asset (not repo root)
- If the list has a "research" or "data-gathering" category, use it; otherwise append to the most adjacent section
- Draft copy once, reuse across PRs - but match each list's voice and entry format
- Do not self-star or brigade - let the listing earn traction organically

**Test scenarios:**
- Test expectation: none - external PRs, not code

**Verification:**
- All 5 PRs opened on the same day (batch effort, reduces overhead)
- Entries include: skill name, one-sentence description matching tuned SKILL.md copy, release URL, source repo URL
- Track merge status over 14 days; abandon PRs that go stale after reasonable nudging

- [ ] **Unit 6: Submit to Anthropic's official Plugin/Skills Marketplace**

**Goal:** Get featured in Claude Code's "Discover" tab, the closest thing to a native claude.ai skill directory.

**Requirements:** R2

**Dependencies:** Unit 1, Unit 2

**Files:**
- No repo changes; this is an external submission at `platform.claude.com/plugins/submit`

**Approach:**
- Submit via Anthropic's form with: skill name, description (matches tuned SKILL.md), GitHub repo URL, release asset URL, demo video link (from Unit 7 if available)
- Expect quality/security review; Anthropic will likely ask for the ClawGuard-scanner-style audit items already surfaced in issue #231 - have responses ready
- Do not wait for acceptance before shipping other levers

**Test scenarios:**
- Test expectation: none - external submission

**Verification:**
- Submission confirmation received
- Track review status weekly; iterate on feedback if any

- [ ] **Unit 7: Record a 15-60 second demo GIF or screen recording**

**Goal:** Produce the visual asset that every amplification channel needs - launch tweet, Neuron pitch, README hero, release notes.

**Requirements:** R6

**Dependencies:** Unit 2 (want the tuned description on-screen), Unit 3 (want the updated install flow)

**Files:**
- Create: `assets/claudeai-demo.gif` (or `.mp4` if GIF is too large)
- Modify: `README.md` to embed the GIF

**Approach:**
- Two possible framings:
  1. "Upload + use" flow: 15 seconds showing Upload dialog -> skill appears -> sample query -> result
  2. "One query" flow: 15-30 seconds of a real research query running end-to-end with actual output
- Pick framing 2 for outside-audience amplification (tweet, Neuron); framing 1 for the README
- Record at 1x speed (speeding up feels fake); edit to =60 seconds
- Export as optimized GIF or H.264 MP4 =5MB

**Test scenarios:**
- Test expectation: none - media asset

**Verification:**
- Asset loads cleanly in GitHub README
- Asset uploads cleanly to X (under their video length/size caps)
- Matt watches it fresh and the "oh wow" moment is unambiguous in the first 5 seconds

- [ ] **Unit 8: Pitch The Neuron "AI Skill of the Day"**

**Goal:** One high-leverage newsletter placement that historically drives the biggest external install spike for Claude skills.

**Requirements:** R6

**Dependencies:** Unit 1, Unit 7

**Approach:**
- Identify The Neuron editor contact (newsletter footer, X DMs, their `skilloftheday@` alias if published)
- Pitch with: 3-sentence hook, demo video link, release URL, 3 example queries that show breadth
- Angle: "researcher skill that queries 12+ social sources in one shot" - novelty vs. their typical dev-tool coverage
- Offer exclusive timing if they want (publish first, then we tweet)
- Do not follow up more than twice

**Test scenarios:**
- Test expectation: none - external pitch

**Verification:**
- Pitch sent with all assets linked
- Track whether the issue ships within 14 days; if not, reuse the materials for other newsletters

- [ ] **Unit 9: Launch tweet + recurring news-cycle posts**

**Goal:** Seed social discovery and establish a weekly cadence so the skill stays top-of-mind.

**Requirements:** R6

**Dependencies:** Unit 1, Unit 7

**Approach:**
- Launch tweet: demo GIF + 1-sentence description + install link. Post to X, cross-post to r/ClaudeAI and r/singularity same day.
- Do not tag handles reflexively - research each target account's culture first
- Weekly recurring pattern: pick a news moment (earnings, launch, election, cultural event), run `last30days` on it, screenshot the output, post. Low-effort, repeatable, compounds.
- Track: likes, impressions, link-click referrer traffic to the release page

**Test scenarios:**
- Test expectation: none - social posts

**Verification:**
- Launch tweet live with demo GIF
- At least one follow-up news-cycle post within 7 days
- Referrer traffic spike visible in GitHub traffic dashboard

- [ ] **Unit 10: Adoption telemetry and feedback loop**

**Goal:** Learn which levers work so we double down on wins and cut losses. Current blind spot: no visibility into claude.ai install counts.

**Requirements:** R7

**Dependencies:** Unit 1

**Approach:**
- Baseline metrics (capture on Unit 1 ship day):
  - GitHub stars
  - Clones/day
  - Traffic referrers
  - Release-asset download count (GitHub exposes this on the Release page)
- Weekly review during the first 6 weeks of:
  - Release download deltas
  - Star velocity
  - Referrer sources (identifies which aggregator/newsletter/tweet drove traffic)
  - New GitHub issues that mention claude.ai specifically
- No dedicated analytics infrastructure - use what GitHub provides + manual referrer spot-checks
- Publish a "what worked / what didn't" retro after 6 weeks in `docs/solutions/` so the next launch compounds

**Test scenarios:**
- Test expectation: none - observability

**Verification:**
- Baseline metrics captured in a `docs/solutions/YYYY-MM-DD-*.md` note
- Weekly log of download/star/referrer deltas maintained
- Retro written at week 6 with concrete learnings for the next release

## System-Wide Impact

- **Interaction graph:** Touches GitHub (release, CI), external aggregators (PRs), Anthropic marketplace (submission), X/Reddit/newsletter (social), ClawHub/Gemini listings (cross-links). No runtime code changes.
- **State lifecycle risks:** Minimal. The main risk is inconsistent cross-linking (some surfaces mention claude.ai, others don't) - Unit 4 treats this as a coordinated sweep, not per-surface creep.
- **API surface parity:** None - no API changes.
- **Integration coverage:** The critical integration is trigger-selection behavior (Unit 2). Manual verification across web / Claude Code / OpenClaw is the gate.
- **Unchanged invariants:** Runtime pipeline, existing install paths (Claude Code plugin / OpenClaw / Gemini) all stay working. Zero-config first-run for default sources remains intact.

## Risks and Dependencies

| Risk | Mitigation |
|------|------------|
| Anthropic marketplace rejects the submission on security/quality grounds | Run `scripts/build-skill.sh` output through ClawGuard or equivalent scanner pre-submission; address #231 findings if real |
| Awesome-list maintainers reject or ignore PRs | Submit to 5 lists in parallel; any 2 acceptances are enough; do not brigade |
| The Neuron pitch is ignored | Treat as upside, not critical path; reuse materials for other newsletters (Ben's Bites, TLDR, Superhuman AI) |
| Tuned description causes false-positive skill selection on unrelated prompts | Manual prompt-testing in Unit 2; be willing to walk back if Claude over-invokes the skill |
| A new Anthropic marketplace or directory launches mid-plan and changes the landscape | The research-tracking cadence in Unit 10 catches this within a week; plan can adapt |
| Launch tweet flops / no organic pickup | Weekly news-cycle cadence (Unit 9) is the compounding play, not the launch moment |
| Cross-repo cross-links in Unit 4 go stale when listings move | Use canonical GitHub Release URL (deterministic) as the link target everywhere |

## Documentation / Operational Notes

- README gets a hero section update in Unit 3
- CHANGELOG gets a v3.0.1 release-notes entry (already shipped in plan 001)
- A `docs/solutions/` retrospective note ships after the 6-week observation window (Unit 10)
- No runbook needed - distribution work is one-time-per-release

## Sources and References

- Research pass by repo-research-analyst on 2026-04-14 - [findings](https://github.com/anthropics/skills)
- [Anthropic Plugin/Skills Marketplace submissions](https://platform.claude.com/plugins/submit)
- [anthropics/skills](https://github.com/anthropics/skills) - 87k stars, canonical repo
- [SkillsMP](https://skillsmp.com), [claudeskills.info](https://claudeskills.info), [mcpmarket.com/tools/skills](https://mcpmarket.com/tools/skills) - aggregators
- [ComposioHQ/awesome-claude-skills](https://github.com/ComposioHQ/awesome-claude-skills)
- [sickn33/antigravity-awesome-skills](https://github.com/sickn33/antigravity-awesome-skills)
- [The Neuron Skill of the Day digest](https://www.theneuron.ai/explainer-articles/the-neurons-ai-skill-of-the-day-digest-april-2026-week-1/)
- Completed prerequisite: `docs/plans/2026-04-14-001-fix-skill-upload-200-file-limit-plan.md` (packaging fix)
- Related code: `SKILL.md` (frontmatter), `README.md`, `scripts/build-skill.sh`, `.github/workflows/`
- Install-count reference points from aggregators: self-improving-agent 357k, frontend-design 277k, skill-vetter 190k, github 148k, proactive-agent 135k
