# Quickstart for coding agents

Read these files in order before touching code:

1. `.speckit/constitution.md` — non-negotiable rules and quality gates
2. `specs/001-advanced-toolkit/spec.md` — requirements and acceptance criteria
3. `specs/001-advanced-toolkit/plan.md` — architecture and decisions
4. `specs/001-advanced-toolkit/data-model.md` — exact schemas
5. `specs/001-advanced-toolkit/tasks.md` — pick the first unchecked task whose dependencies are satisfied

## Working loop

```bash
make test          # bash tests/run.sh
make lint          # shellcheck -x -S warning + py_compile
```

For generator tasks:

```bash
make docs completions
git diff --exit-code   # must be clean after committing generated files
```

## Rules while implementing

- One task per focused commit; message references the task id, e.g. `T017: add discovery probe flags`.
- Never edit generated help/completion/config/docs by hand — edit `lib/options.sh` and regenerate.
- Never use `eval`, never source config files, never build Nmap command strings from user input.
- Every new flag: registry entry + validator + positive test + negative test + regenerated artifacts.
- Every new finding rule: fixture with a hostile banner and escaping assertions.
- Use `--no-color --no-banner --dry-run` in tests so no files are created and no network is touched.
- Stop and ask if a task would introduce a new runtime dependency or violate the constitution.

## Definition of done for a task

- Its verification command passes.
- `tasks.md` checkbox is ticked in the same commit.
- No generated artifact drift, no secrets, no unrelated changes.
