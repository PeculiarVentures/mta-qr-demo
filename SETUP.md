# Repository Setup

This file documents the two pre-push configuration steps that were required
when this repository was first created. Both have been completed.

---

## 1. Go module path — done

`go/go.mod` declares the module path as `github.com/PeculiarVentures/mta-qr-demo`.
All Go source files import using this path. No action required.

## 2. CI badge in README — done

`README.md` contains the correct badge URL for `PeculiarVentures/mta-qr-demo`.
No action required.

---

If you fork this repository and host it elsewhere, update both:

```bash
# Replace module path throughout Go source
find go/ -name "*.go" -exec \
  sed -i 's|github.com/PeculiarVentures/mta-qr-demo|github.com/YOUR_ORG/YOUR_REPO|g' {} +
sed -i 's|module github.com/PeculiarVentures/mta-qr-demo|module github.com/YOUR_ORG/YOUR_REPO|' go/go.mod

# Update CI badge in README.md line 3
sed -i 's|PeculiarVentures/mta-qr-demo|YOUR_ORG/YOUR_REPO|g' README.md
```
