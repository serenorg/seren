# Git Hooks (Seren CLI/API)

This workspace uses a shared git hooks directory to enforce commit conventions.

## Setup

Configure git to use the hooks in this workspace:

```bash
git config core.hooksPath .githooks
```

This tells git to use `.githooks` instead of `.git/hooks/` for all hooks in this repo.

## Hooks

### commit-msg

The `commit-msg` hook enforces:

1. **Conventional Commits**  
   Commit messages must follow the conventional commit format:

   ```text
   <type>(<optional-scope>): <description>
   ```

   Valid types:

   - `feat`
   - `fix`
   - `docs`
   - `style`
   - `refactor`
   - `perf`
   - `test`
   - `build`
   - `ci`
   - `chore`
   - `revert`

   Examples:

   ```text
   feat(cli): add billing health command
   fix(api): handle invalid usage summary response
   docs: update README with CLI usage examples
   ```

2. **No AI Tool References**  
   Commit messages must not contain references to "claude" or "claude code".

If a commit message does not meet these rules, the commit is rejected with an explanation.

## Notes

- Hooks are local configuration; they are not enforced on remote pushes unless your CI also validates commit messages.
- To bypass hooks in an emergency (not recommended), you can use `git commit --no-verify`.

