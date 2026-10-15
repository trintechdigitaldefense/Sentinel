# Verify SENTINEL downloads

## install.sh (main branch)

```bash
curl -sSL -o install.sh https://raw.githubusercontent.com/trintechdigitaldefense/Sentinel/main/install.sh
sha256sum install.sh
# Compare to SHA256SUMS in this repo (or release notes).
```

## v3.0.0 source tarball

```bash
curl -sL -o sentinel-v3.0.0.tar.gz \
  https://github.com/trintechdigitaldefense/Sentinel/archive/refs/tags/v3.0.0.tar.gz
sha256sum sentinel-v3.0.0.tar.gz
```

See `SHA256SUMS` in the repository root for published digests.
