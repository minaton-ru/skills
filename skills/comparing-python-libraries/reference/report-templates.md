# Report templates

Skeletons for the step 5 report. Fill the placeholders; drop rows only where SKILL.md allows it.

Example call: `/comparing-python-libraries async HTTP client for a FastAPI service: httpx, aiohttp, requests`

Cell formats: a figure is a link to its source, `[1.2k](<url>)`; an article finding is plain text with no link or article name; any other cell is `not applicable: <reason>`, `not found`, `not accessible` or `no equivalent`.

## Winner

```
Research date: <YYYY-MM-DD>. Latest versions: <lib> <ver>, <lib> <ver>, …

**Winner: <lib>**

<2–3 sentences: which High and Medium criteria it leads on, and by how much.>

| Criterion | Weight | <winner> | <other candidate> | … |
|---|---|---|---|---|
| Used by | High | [<figure>](<url>) | [<figure>](<url>) | |
| Forks | High | | | |
| CVEs | High | [<N>, latest <YYYY-MM-DD>](<url>) | | |
| Stars | Medium | | | |
| Issues | Medium | | | |
| Pull requests | Medium | [<total>, <merged> merged, <open> open](<url>) | | |
| Documentation quality | Medium | <finding> ([docs](<url>)) | | |
| Recommended in articles | Medium | <what the articles say, no links> | | |
| Performance and readiness for high load | <Medium or Low> | | | |
| Repository age | Low | | | |
| Main contributors | Low | [<total>, <active> active last year](<url>) | | |
| License | Low | | | |
| Async support | Low | | | |
| Extensibility | Low | | | |
| Scalability | Low | | | |
| Works with dependency injection | Low | | | |

**CVE status**
- <lib> <ver>: <N> CVEs, latest published <YYYY-MM-DD>, none affects <ver>; <M> advisories without a CVE id.

**Screened out**
- <lib>: <reason, such as "Stale: last commit <YYYY-MM-DD>">.

**Notes**
- <lib>: partial fit: <what it lacks for the task>.
- <lib>: <criterion> is <not found / not accessible>; <how it could change the verdict>.
- <lib>: staleness not accessible: <host> refused access.
- <lib>: <metric> has no equivalent on <host>, so its counts compare only roughly.
- <lib>: the repository is a monorepo, so its stars, forks and issues are shared.
- <name> is `<pypi-name>` on PyPI. / <lib> is not on PyPI; its repository was found on <where>.
```

The **CVE status** line goes to the winner only. Leave out **Screened out** when nothing was screened out, and **Notes** when there is nothing to note. **Outsiders** follow, as below.

## Finalists

```
Research date: <YYYY-MM-DD>. Latest versions: <lib> <ver>, <lib> <ver>, …

**Finalists: <lib>, <lib>**

| Criterion | Weight | <finalist> | <finalist> |
|---|---|---|---|
| <only criteria where they differ> | | | |

<1–2 sentences: which way the weighted criteria lean, or that they are level and the task's own needs decide.>

To see how often each name appears in new GitHub repositories over time, open https://trends.domage.dev/?search=<lib>;<lib>&showTrend=true and run the search.

<**CVE status**, **Screened out** and **Notes** as in Winner>
```

**CVE status** has one line per finalist. Leave out the trends tip when the site does not load. **Outsiders** follow, as below.

## All definite losers

```
Research date: <YYYY-MM-DD>. Latest versions: <lib> <ver>, <lib> <ver>, …

None of the shortlisted libraries passed screening.

- <lib>: <reason>.
- <lib>: <reason>.
```

Add **Notes** if any apply. **Outsiders** follow, as below; here they argue why the library could do the user's task.

## Outsiders

```
**Outsiders**
- **<lib>**: <what makes it worth comparing against the winner or finalists>.
- **<lib>**: <…>.

Add any of them to the comparison?
```

Two at most. Leave the block out when there are no outsiders, or when the user has said the shortlist is closed.
