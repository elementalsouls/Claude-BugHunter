# Releasing the `cbh` CLI to PyPI

The `cbh` command ships as the PyPI package **`claude-bughunter`**. Publishing is
automated by `.github/workflows/publish.yml` using **PyPI Trusted Publishing**
(OIDC) — no API token is ever stored in the repo.

## One-time setup (maintainer, once)

1. **Claim the name with a pending publisher** (before the first release, so no
   token is ever needed): on <https://pypi.org/manage/account/publishing/> add a
   *pending publisher* with exactly:
   - PyPI project name: `claude-bughunter`
   - Owner: `elementalsouls`
   - Repository: `Claude-BugHunter`
   - Workflow name: `publish.yml`
   - Environment name: `pypi`
2. **Create the `pypi` GitHub environment**: repo → Settings → Environments →
   *New environment* → `pypi`. Optionally add yourself as a required reviewer, so
   a tag can't publish without one click of approval.

That's it — no secrets to manage. The pending publisher becomes a normal Trusted
Publisher automatically on the first successful upload.

## Cutting a release

1. Bump the version in **both** `pyproject.toml` (`project.version`) and
   `cbh/__init__.py` (`__version__`) to the same value, e.g. `2.1.1`.
2. Commit on `main`.
3. Tag and push:
   ```bash
   git tag v2.1.1
   git push origin v2.1.1
   ```
4. The workflow builds the sdist + wheel, **fails closed if the tag and the
   `pyproject` version disagree**, runs `twine check`, and publishes to PyPI via
   OIDC. Watch it under the repo's Actions tab.

## After the first successful publish

Flip the install docs from the git URL to the released package (three spots):
`README.md`, `docs/cbh-cli.md` (×2). The git-install and the zero-install
`python3 scripts/cbh.py` paths stay valid as alternatives:

```bash
pipx install claude-bughunter      # released, version-pinnable
# or, for the unreleased tip of main:
pipx install git+https://github.com/elementalsouls/Claude-BugHunter
```

## Verifying a build locally (optional, no publish)

```bash
python3 -m venv /tmp/cbhv && /tmp/cbhv/bin/pip install build twine
/tmp/cbhv/bin/python -m build          # writes dist/*.whl and dist/*.tar.gz
/tmp/cbhv/bin/twine check dist/*
/tmp/cbhv/bin/pip install dist/*.whl && /tmp/cbhv/bin/cbh --help
```

Note: `cbh diff` needs a full repo clone (it uses `engine/diff.py`, which is not
bundled in the package); it prints a clear message and exits non-zero when run
from a pip install. Every other subcommand is self-contained.
