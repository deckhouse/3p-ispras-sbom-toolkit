# Docker image and upstream sync

This repository is a downstream mirror of the ISPRAS `sbom-checker`:
<https://gitlab.community.ispras.ru/sdl-tools/sbom-checker>

`master` is `upstream/master` plus a few commits on top that add only files
absent upstream: `Dockerfile`, `.dockerignore`, `.github/`, and this file.
Upstream files (`README.md`, `*.py`, `schemas/`, ...) are never modified here,
so the sync below is always a mechanical rebase.

## Upstream sync

Workflow: `.github/workflows/sync-upstream.yml` (monthly cron + manual run).

1. Fetches `upstream/master`.
2. Rebases our commits on top of it and force-pushes `master`
   (`--force-with-lease`).
3. If upstream moved, opens a GitHub issue labelled `upstream-sync` with the
   list of new upstream commits and changed files, and states whether the
   change affects checker functionality (`*.py`, `schemas/`, `requirements.txt`)
   or only docs. Building and tagging an image is a manual decision.
4. If the rebase conflicts, the job fails and opens an issue with the
   conflicting files. Resolve manually:

   ```sh
   git fetch upstream master
   git rebase upstream/master master
   # fix conflicts, git rebase --continue
   git push --force-with-lease origin master
   ```

Manual sync is the same three commands.

## Docker image

Workflow: `.github/workflows/docker-manual-publish.yml`.

Triggers:

- push of a git tag starting with `v`
- manual run (`workflow_dispatch`) from the **Actions** tab, optional
  `version` input (defaults to the branch name)

Published tags:

- `<WERF_REGISTRY>/3p-ispras-sbom-checker:<version-or-branch-or-git-tag>`
- `<WERF_REGISTRY>/3p-ispras-sbom-checker:sha-<commit_sha>`

Public image:

- `registry.werf.io/sbom-toolkit/3p-ispras-sbom-checker:<tag>`

Usage:

```sh
docker run --rm -v "$PWD/sbom.json:/sbom.json" \
  registry.werf.io/sbom-toolkit/3p-ispras-sbom-checker:<tag> /sbom.json
```

The entrypoint is `sbom-checker.py`; pass its options after the image name.
