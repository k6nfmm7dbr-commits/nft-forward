#!/usr/bin/env bash
# Publish the checked artifact set as a fast-forward commit without editing the checkout.
set -euo pipefail
artifacts=${1:?artifact directory required}
export LC_ALL=C
src=$(git rev-parse HEAD)
version=
while IFS= read -r line; do
  if [[ "$line" =~ ^const\ Version\ =\ \"([0-9]+\.[0-9]+\.[0-9]+)\"$ ]]; then
    version=${BASH_REMATCH[1]}
  fi
done <<< "$(git show "$src:internal/version/version.go")"
[[ -n "$version" ]]
mapfile -t names < scripts/dist-manifest.txt
[[ ${#names[@]} -gt 2 ]]
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
export GIT_INDEX_FILE="$work/index"
ref=refs/heads/dist
refs=$(git ls-remote --refs origin "$ref")
parents=()
if [[ -n "$refs" ]]; then
  git fetch --no-tags origin "$ref"
  prior=$(git rev-parse FETCH_HEAD)
  parents=(-p "$prior")
  # Concurrent workflow jobs must not publish an older source over a newer build.
  last_src=$(git show -s --format=%B "$prior" | git interpret-trailers --parse | while IFS=' ' read -r key value; do
    if [[ "$key" == Source-commit: ]]; then printf '%s\n' "$value"; fi
  done)
  if [[ -n "$last_src" ]]; then
    if ! [[ "$last_src" =~ ^[0-9a-f]{40}$ ]] || ! git merge-base --is-ancestor "$last_src" "$src"; then
      echo "Published source is newer or divergent; refusing to replace it" >&2
      exit 1
    fi
  fi
fi
git read-tree --empty
for name in "${names[@]}"; do
  [[ "$name" =~ ^(nft-forward-linux-[a-z0-9]+|SHA256SUMS|install\.sh(\.sha256)?)$ ]]
  file="$artifacts/$name"
  [[ -f "$file" && ! -L "$file" ]]
  mode=100644
  if [[ "$name" == nft-forward-linux-* || "$name" == install.sh ]]; then mode=100755; fi
  hash=$(git hash-object -w -- "$file")
  git update-index --add --cacheinfo "$mode,$hash,$name"
done
expected=$(printf '%s\n' "${names[@]}" | sort)
[[ $(git ls-files | sort) == "$expected" ]]
tree=$(git write-tree)
sha=$(printf 'dist: rebuild from %.7s (v%s)\n\nSource-commit: %s\n' "$src" "$version" "$src" \
      | git -c user.name=nff-dist-bot -c user.email=actions@users.noreply.github.com commit-tree "$tree" "${parents[@]}")
git push origin "$sha:$ref"
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then printf 'sha=%s\n' "$sha" >> "$GITHUB_OUTPUT"; fi
printf 'Published %s\n' "$sha"
