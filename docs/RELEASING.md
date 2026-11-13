# Releasing

Releases are published to PyPI as `secretsentinel-scanner` by
`.github/workflows/release.yml` when a version tag such as `v1.0.0` is pushed.
No API token is stored: PyPI trusts this repository's workflow directly
(trusted publishing).

PyPI never accepts the same version twice. If a release is broken, fix it and
release the next patch version.

## One-time setup

1. **PyPI account.** Register at pypi.org and turn on two-factor
   authentication.
2. **GitHub environment.** Repository **Settings → Environments → New
   environment**, named `pypi`. Under **Deployment branches and tags**, allow
   only tags matching `v*`. Optionally add yourself as a **required reviewer**,
   so every publish waits for your approval.
3. **PyPI trusted publisher.** On PyPI: **Account → Publishing → Add a new
   pending publisher → GitHub**, with:
   - PyPI project name: `secretsentinel-scanner`
   - Owner: `SaIdEeVaN`
   - Repository name: `secretsentinel`
   - Workflow name: `release.yml`
   - Environment name: `pypi`
4. **Private vulnerability reporting.** Repository **Settings → Code security →
   Private vulnerability reporting → Enable**, so the link in `SECURITY.md` works.

## Each release

1. Set the new version in `backend/pyproject.toml` and add a section to
   `CHANGELOG.md`. Commit and push to `main`.
2. Wait until every check on that commit is green, including the **package**
   job (it builds the wheel, installs it and scans the demo).
3. Tag and push:

   ```bash
   git checkout main && git pull
   ```

   ```bash
   git tag -a v1.0.0 -m "SecretSentinel Scanner 1.0.0"
   ```

   ```bash
   git push origin v1.0.0
   ```

4. **Actions → Release to PyPI**: the build job checks that the tag matches the
   version, builds, and repeats the package check. If you set a required
   reviewer, approve the `pypi` deployment; the publish job then uploads.
5. **Releases → Draft a new release**, choose the tag, paste the `CHANGELOG.md`
   section, and publish. To list the Action on the GitHub Marketplace, tick
   **Publish this Action to the GitHub Marketplace** here (needs two-factor
   authentication on your GitHub account).
6. Move the major tag, so `uses: SaIdEeVaN/secretsentinel@v1` and the
   documented examples pick up the release:

   ```bash
   git tag -f v1 v1.0.0
   ```

   ```bash
   git push -f origin v1
   ```

7. Check it in a fresh virtualenv:

   ```bash
   pip install secretsentinel-scanner==1.0.0
   ```

   ```bash
   secretsentinel doctor
   ```
