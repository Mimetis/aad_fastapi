#!/usr/bin/env bash
latest_tag=$(git describe --tags --abbrev=0)
previous_tag=$(git describe --tags --abbrev=0 --always "$latest_tag^")

# hand-written release notes, if any, before the list of commits
notes_file="$(dirname "$0")/release_notes/$latest_tag.md"
if [ -f "$notes_file" ]; then
  cat "$notes_file"
  printf '\n## Commits\n\n'
fi

git shortlog "$previous_tag..$latest_tag" | sed 's/^./    &/'
