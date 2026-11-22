#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
git init -q --bare "$tmp/remote"
git init -q "$tmp/repo"
cd "$tmp/repo"
git config user.name Test
git config user.email test@example.invalid
git remote add origin "$tmp/remote"
mkdir -p scripts internal/version dist
cp "$root/scripts/dist-manifest.txt" scripts/
cp "$root/scripts/dist-docs-only.sh" scripts/
printf 'package version\nconst Version = "0.4.0"\n' > internal/version/version.go
printf 'old\n' > README.md
git add -- scripts internal README.md
git commit -qm "first source snapshot"
old=$(git rev-parse HEAD)
while IFS= read -r f; do printf 'fixture: %s\n' "$f" > "dist/$f"; done < scripts/dist-manifest.txt
bash "$root/scripts/publish-dist.sh" dist
first=$(git --git-dir="$tmp/remote" rev-parse refs/heads/dist)
[[ $(git --git-dir="$tmp/remote" ls-tree --name-only -r "$first" | sort) == "$(sort scripts/dist-manifest.txt)" ]]
[[ $(git rev-parse HEAD) == "$old" && -z $(git diff --cached --name-only) ]]
printf '\n// source change\n' >> internal/version/version.go
git commit -qam 'change code'
code=$(git rev-parse HEAD)
printf 'new docs\n' > README.md
git commit -qam 'update docs'
new=$(git rev-parse HEAD)
[[ $(bash scripts/dist-docs-only.sh push "$old" "$new") == false ]]
[[ $(bash scripts/dist-docs-only.sh push "$code" "$new") == true ]]
[[ $(bash scripts/dist-docs-only.sh workflow_dispatch "$code" "$new") == false ]]
[[ $(bash scripts/dist-docs-only.sh push 1111111111111111111111111111111111111111 "$new") == false ]]
printf 'new installer\n' > dist/install.sh
bash "$root/scripts/publish-dist.sh" dist
second=$(git --git-dir="$tmp/remote" rev-parse refs/heads/dist)
[[ $(git --git-dir="$tmp/remote" rev-parse "$second^") == "$first" ]]
[[ $(git --git-dir="$tmp/remote" show "$first:install.sh") == 'fixture: install.sh' ]]
[[ $(git --git-dir="$tmp/remote" show "$second:install.sh") == 'new installer' ]]
git checkout -q --detach "$old"
if bash "$root/scripts/publish-dist.sh" dist; then
  echo 'stale release was published' >&2
  exit 1
fi
[[ $(git --git-dir="$tmp/remote" rev-parse refs/heads/dist) == "$second" ]]
printf '%s\n' 'PASS: artifact-only fast-forward, old commit download, stale release rejection, whole-push docs detection'
