# Agent skills

## Code Style
- Write clear, short code without unnecessary complexity.
- If logic repeats - extract it into helper functions.
- Follow PEP 8 for formatting (99 characters per line, snake_case for functions/variables, PascalCase for classes, UPPER_SNAKE for constants).
- Use descriptive, unambiguous names for variables. Use descriptive names that start with a verb for functions. Functions and methods must consist of at least two words.
- Type annotations - required everywhere, including `-> None`.
- Write Google-style docstrings for every public function and method.
- Do not add unused imports.
- Apply KISS, DRY and SOLID principles to the code.

## Constraints
- Never edit: lock files, `.env`.
- Never commit `.env` files.
- Ask before adding dependencies.
- Before starting coding work, create a new git branch from up to date `main` according to the project's branch naming convention.
- Do not stage and commit, wait for the user ask you to do.
- If a mismatch causes you to think for too long, ask the user this question and suggest possible next steps.
- Do not look at the `__pycache__` folder unless the user has explicitly asked you to do so.
- Do not look at git branches other than `main` unless the user has explicitly asked you to do so.

## Git branch naming convention
Branches should be named according to the type of task.

Git branch name format: `<type>-<short-description>`, where:
- `type` - task type: `feat`, `fix`, `test`, `refactor`, `docs`, `ci`, `chore`, `style`, according to the Conventional Commits
- `short-description` - a short description in the style of `kebab-case`

## Commit tag rules
Each commit must be marked with a tag in square brackets at the beginning of the message:
- `[agent]` - the diff from the agent was accepted without significant edits
- `[assisted]` - the agent did the bulk of the work, but the developer rewrote a significant portion (logic, structure, >20% of lines)
- `[manual]` - the code was written manually without the agent's assistance

Each commit must include the Conventional Commits type after the tag so following such format `[tag] type: description`.
