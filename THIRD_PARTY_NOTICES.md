# Third-party notices

## Argo CD gitops-engine

`backend/handlers/gitops_health.go` ports the resource health rules, and
`backend/handlers/gitops_engine.go` the kind order used when applying
objects, from [argoproj/gitops-engine](https://github.com/argoproj/gitops-engine)
(`pkg/health`, `pkg/sync/sync_tasks.go`).

Copyright 2020 The Argo Authors. Licensed under the Apache License,
Version 2.0. A copy of the license is at
<https://www.apache.org/licenses/LICENSE-2.0>. The code was rewritten, not
copied verbatim, and changes from the original are CommitKube's.

## Fonts

Onest and JetBrains Mono are bundled from the `@fontsource-variable/onest`
and `@fontsource-variable/jetbrains-mono` npm packages, under the SIL Open
Font License 1.1.
