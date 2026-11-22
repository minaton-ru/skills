# Some Skills for Python developers

Useful [agent skills](https://agentskills.io) for Python developers. Each skill does one job and follows the open `SKILL.md` format.

## Installation

### Claude Code

Install with the [`skills`](https://skills.sh) CLI:

```bash
# All skills, for every project
npx skills add minaton-ru/skills -a claude-code -g

# One skill
npx skills add minaton-ru/skills --skill comparing-python-libraries -a claude-code -g
```

Or copy a skill folder by hand:

```bash
git clone https://github.com/minaton-ru/skills.git
cp -r skills/skills/comparing-python-libraries ~/.claude/skills/            # every project
cp -r skills/skills/comparing-python-libraries <project>/.claude/skills/    # one project
```

### Other agents

```bash
npx skills add minaton-ru/skills
```

The CLI asks which agents to install for (Codex, Cursor, Gemini CLI and others). Pass `-a <agent>` to skip the prompt.

### Updating

```bash
npx skills check     # list available updates
npx skills update    # install them
```

## Skills

| Skill | Description |
|---|---|
| [comparing-python-libraries](skills/comparing-python-libraries/SKILL.md) | Compares a shortlist of Python libraries or frameworks you have already found for one task, and names a winner or the finalists. It screens out stale libraries and ones with unfixed CVEs, then scores the rest on fixed weighted criteria: adoption, maintenance, documentation and performance. Run it manually: `/comparing-python-libraries <task description>: <library>, <library>, ...` |

For `comparing-python-libraries`, install the [GitHub CLI](https://cli.github.com) and run `gh auth login`, or set `GITHUB_TOKEN`: without them the skill's script hits GitHub's anonymous rate limits, runs slower, and may report some figures as not accessible.

## License

MIT License - See [LICENSE](LICENSE) file for details.
