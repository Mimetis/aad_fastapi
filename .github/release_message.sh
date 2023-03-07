#!/usr/bin/env bash
latest_tag=$(git describe --tags --abbrev=0)
previous_tag=$(git describe --tags --abbrev=0 --always "$latest_tag^")
git shortlog "$previous_tag..$latest_tag" | sed 's/^./    &/'