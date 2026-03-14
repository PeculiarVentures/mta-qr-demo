# Repository Setup Checklist

Two things in this repository contain a placeholder that must be replaced
before the first `git push`. Everything else is ready to commit as-is.

---

## 1. Go module path

`go/go.mod` currently declares:

```
module github.com/mta-qr/demo
```

This is a placeholder. Replace it with the actual GitHub path for this repo.
For example, if the repo will live at `github.com/PeculiarVentures/mta-qr-demo`:

```bash
# From the repo root
find go/ -name "*.go" -exec \
  sed -i 's|github.com/mta-qr/demo|github.com/PeculiarVentures/mta-qr-demo|g' {} +
sed -i 's|module github.com/mta-qr/demo|module github.com/PeculiarVentures/mta-qr-demo|' go/go.mod
```

Then verify the build still passes:

```bash
cd go && go build ./... && go test ./... -count=1
```

## 2. CI badge in README

`README.md` line 3 contains:

```
![CI](https://github.com/REPO_PATH/actions/workflows/ci.yml/badge.svg)
```

Replace `REPO_PATH` with the actual `org/repo` value, e.g. `PeculiarVentures/mta-qr-demo`.

---

Both changes are two find-and-replace operations. Nothing else in the repo
requires manual editing before the first push.
