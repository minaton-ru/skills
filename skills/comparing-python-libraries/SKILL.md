---
name: comparing-python-libraries
description: Compares a user-supplied shortlist of Python libraries or frameworks for one task and names a winner, or the finalists, using fixed weighted criteria (maintenance, CVEs, adoption, documentation, performance). Use when the user names two or more Python libraries or frameworks and asks which to choose, which is better, or how they compare for a task, such as "httpx vs aiohttp" or "click or typer for a CLI?". Not for finding libraries the user has not named, or for questions about how to use a library.
disable-model-invocation: true
argument-hint: "<task description>: <library>, <library>, ..."
compatibility: Requires Python 3.12+.
license: MIT
metadata:
  author: Konstantin Roshchupkin
  version: "0.3.0"
---

# Comparing Python libraries

Name the winner of a **shortlist**: Python libraries or frameworks the user has already found for one task. The user has done the discovery, so the verdict covers the shortlist, and the shortlist grows only when the user agrees to it after the report.

The user supplies a short description of the task and two or more library names. Ask for whichever is missing before starting.

Copy this checklist into your working notes and tick it off:
```
- [ ] Fit verdict for every library
- [ ] Every library labelled definite loser (with reason) or candidate
- [ ] Every evidence cell: figure + source / not applicable + reason / not found / not accessible / no equivalent
- [ ] Winner or named finalists
- [ ] Report self-check passed
```

The step numbers and labels below are working vocabulary. In messages to the user, describe what was done and found in plain words.

## 1. Check fit

Run `python3 scripts/collect_metrics.py <name> [<name> ...]` once for the whole shortlist; run it, don't read it. Where `python3` is missing, as is common on Windows, use `python` or `py -3` instead. Its JSON gives each library's repository, latest version and the figures for steps 2 and 3, each with a source link. Then read the README or docs landing page and decide whether the library solves the user's task.

The library name provided by the user may differ from the PyPI name (Django REST framework is `djangorestframework`): search PyPI and state the mapping. A library not on PyPI is marked as such and its repository is found by web search. When the repository is a monorepo holding more than this library, say that its stars, forks and issues are shared. When the script reports `on_pypi: false`, find the package or repository yourself, then rerun the script with the PyPI name if there is one.

A **completely unsuitable** library solves a different problem altogether, like an ORM on a shortlist of HTTP clients. When the user named a Python version, framework or platform, check the library supports it; an unsupported one is completely unsuitable. This is the one reason to pause before the report: tell the user which library and why, and ask whether to remove it from the comparison or keep it. Continue with their answer. A partial fit is a note to carry into the report, and the work continues.

Done when every library has a one-line fit verdict.

## 2. Screen out definite losers

A **definite loser** meets any one of these:

- **Stale**: the repository is archived, or the last commit on the default branch is more than a year old: a year without commits means bug and security fixes are not coming either. Commits decide this, whatever the release dates say (script: `archived`, `last_commit_date`).
- **Unfixed CVE**: the latest PyPI release is affected by a CVE. The script checks that version against OSV and the GitHub Advisory Database; any CVE under `cves.unfixed` makes the library a definite loser. For a CVE under `cves.needs_manual_check`, open its source and check whether the latest release is affected. Fixed CVEs go to the CVEs row in step 3 as a count with the date of the most recent one (`cves.count`, `cves.latest_published`). Advisories without a CVE id (`cves.advisories_without_cve`) are counted in that row but screen nothing out.
- **No async where the task already uses it**: the user's task is known to run on async Python (the description says so or names an async framework), and the library has no async support.

Every other library is a **candidate**. Steps 3 and 4 work on candidates only, so a definite loser needs no further evidence.

Done when every library is labelled definite loser, with its reason, or candidate.

## 3. Gather evidence

Fill every row of this table for every candidate. Weights are the user's: High outranks Medium, Medium outranks Low.

| Criterion | Weight | Better when | Where to look |
|---|---|---|---|
| Used by (dependent repositories) | High | more | script: `used_by`. When it is null, look at the repo page yourself; when no count is shown there either, write `not found` |
| Forks | High | more | script: `forks` |
| CVEs | High | none found; found long ago and fixed is acceptable | already gathered in step 2 |
| Stars | Medium | more | script: `stars` |
| Issues | Medium | more in total (open + closed): a sign of an active user base | script: `issues_total` |
| Pull requests | Medium | more, and they get merged or closed. A pile of old open pull requests is suspicious | script: `prs_total`, `prs_merged`, `prs_open` |
| Documentation quality | Medium | detailed: tutorial, API reference, examples | the official docs site, and what developers say about the docs |
| Recommended in articles | Medium | popular developer resources recommend it for this kind of task | web search |
| Performance and readiness for high load | Medium when the user's task needs it, otherwise Low | faster, and proven under heavy load | published benchmarks (independent ones outrank the library's own), docs, reports of large production use |
| Repository age | Low | older | script: `created_at` |
| Main contributors | Low | several active ones. A single contributor is a risk to future updates | script: `contributors_total`, `contributors_active_last_year` |
| License | Low | open source | script: `license` |
| Async support | Low | async supported; both sync and async is better still. Count it only when the user's task benefits from async but does not require it — when it requires async, step 2 has already handled it | docs |
| Extensibility | Low | documented ways to extend it: plugins, hooks, middleware, subclassing | docs |
| Scalability | Low | keeps working as the project and its load grow | docs, articles |
| Works with dependency injection | Low | its objects can be created and passed in explicitly, or it integrates with dependency injection frameworks | docs, articles |

A criterion that has no meaning for this kind of library, such as readiness for high load for a command-line parser, gets `not applicable` with a one-line reason in every candidate's cell, and no research.

While gathering, note every **outsider**: a library outside the shortlist that an article or any other source recommends for the user's task. The report needs them.

The script paces and retries GitHub calls itself. A field it still could not fetch is listed under `errors`: record `rate limited` as `not accessible`, and never estimate the figure.

The script covers GitHub only and returns other hosts with "host not supported". A repository hosted on GitLab, Bitbucket, Gitea or elsewhere is measured with that host's equivalents (stars, forks, issues, merge requests). Where a metric has no equivalent there, such as "Used by", write `no equivalent` and mention it in the report, because counts from different hosts are only roughly comparable.

Done when every cell holds a figure or finding with its source, `not applicable` with its reason, `not found` after a real attempt, `not accessible` when the source refused access (rate limit, login wall) after retries, or `no equivalent` when the host has no such metric.

## 4. Reach a verdict

For each criterion, mark which candidate leads. Figures within 5% of each other are level: popularity counts are too noisy for smaller gaps to mean anything. A `not found`, `not accessible`, `no equivalent` or `not applicable` cell gives no lead to anyone.

- **Winner**: the only candidate left, or the one ahead after counting leads in weight order: most High leads, then on a tie most Medium leads, then on a further tie most Low leads. A candidate ahead on High does not win when another candidate leads on more Medium criteria; both become finalists.
- **Finalists**: the candidates still level after all three counts, or the pair from the previous sentence. The choice between them is the user's.

Done when there is one winner or a named set of finalists.

## 5. Report

The report is a reply in the chat, shaped by the verdict:

- **A winner**: report the winner and why it wins, with a table of every criterion that shows the winner's figures beside the figures of each other candidate, so the user sees the size of the lead.
- **Several finalists**: name them, then give a brief table of only the criteria where they differ. Close with which way the weighted criteria lean, or say that they are level and the task's own needs must break the tie. Add one short tip: the user can compare the finalists on https://trends.domage.dev (names separated by `;`), which charts how many new GitHub repositories mention each name over time. Leave the tip out if the site does not load. It shows mentions, not adoption, so it never affects the verdict.
- **Every library is a definite loser**: say so plainly.

In every shape:

- Open with the research date and each library's latest PyPI version.
- Give each definite loser one line with its reason.
- State the CVE status of every library the report names as winner or finalists.
- Give each figure with a link to its source, so the user can check it. Articles are the exception: base what you say about them only on articles you actually opened, then report what they recommend without naming or linking them, which keeps the report short.
- Let the criteria tables be as full as the evidence needs, and keep the text around them brief: a few sentences per section.
- Carry over any partial-fit note from step 1 and any `not found` that could have changed the verdict.
- Keep to prose and tables. The user is choosing a library and has not asked how to use it, so code examples stay out.

**Outsiders** come last, after the verdict. List up to two, those most often recommended for this kind of task, each with a brief argument: what makes it worth comparing against the winner or finalists. Then ask the user whether to add any of them to the comparison. A library the user adds goes through steps 1 to 3, and the verdict is reached again between it and the winner or finalists. Leave this part out when there are no outsiders, or when the user has said the shortlist is closed.

Before sending, check the report: every figure carries a source link, every winner or finalist has its CVE status stated, every definite loser has its one-line reason, and the outsiders section is present or deliberately left out.
