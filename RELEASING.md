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

- pushes of tags matching `payload-server-v*` trigger `.github/workflows/publish-pypi.yml`
- configure the PyPI project to trust this repository/workflow
- the workflow builds, runs `twine check`, and publishes via Trusted Publishing

## Post-release Checks

- verify `pipx install payload-server` works from a clean environment
- verify `payload-server linux --help` and `payload-server windows --help`
- verify the README still matches the published console-script workflow
- verify the PyPI page renders the README and project URLs as expected
