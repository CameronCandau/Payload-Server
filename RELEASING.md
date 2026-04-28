# Releasing payload-server

## Preflight

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall src tests
python3 -m pip wheel --no-build-isolation --no-deps --wheel-dir /tmp/payload-server-wheel .
```

## Publish To PyPI

Preferred build flow:

```bash
python3 -m build
python3 -m twine check dist/*
```

If you only want a local wheel smoke test before the real build:

```bash
python3 -m pip wheel --no-build-isolation --no-deps --wheel-dir /tmp/payload-server-wheel .
```

Upload:

```bash
python3 -m twine upload dist/*
```

If available, prefer Trusted Publishing over long-lived API tokens for PyPI.

GitHub Actions:

- bump `project.version` in `pyproject.toml`
- commit and push that change
- create and push a matching release tag such as `v0.1.0`
- pushes of tags matching `v*` trigger `.github/workflows/publish-pypi.yml`
- old `payload-server-v*` tags are obsolete and are not part of the release process anymore
- configure the PyPI project to trust this repository/workflow
- the workflow validates that the pushed tag version matches `pyproject.toml`
- `workflow_dispatch` is preflight-only: it builds and checks distributions but does not publish
- the workflow builds, runs `twine check`, and publishes via Trusted Publishing only for tag pushes

## Post-release Checks

- verify `pipx install payload-server` works from a clean environment
- verify `payload-server linux --help` and `payload-server windows --help`
- verify the README still matches the published console-script workflow
- verify the PyPI page renders the README and project URLs as expected
