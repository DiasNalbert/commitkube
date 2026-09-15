# CI

`ci.yml` runs on every push to `main` and on every pull request.

**backend** — build, `go vet`, the test suite, and a gofmt check.

`JWT_SECRET` and `ENCRYPTION_KEY` are set to fixed throwaway values: the
`handlers` package aborts in `init` without them, and a run that dies there
reports the same "ok, no tests" as a healthy one. They are not secrets and must
never be the values a deployment uses.

The gofmt check skips a handful of files that were not formatted before this
convention existed. Reformatting them in one commit would bury real changes in
whitespace; format them when you are already editing them.

**frontend** — type check and build. `next build` runs ESLint, so lint is
covered by it rather than by a separate step.
