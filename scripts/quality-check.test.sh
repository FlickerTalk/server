#!/usr/bin/env bash
set -u

scripts="$(cd "$(dirname "$0")" && pwd)"
root="$(dirname "$scripts")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.com
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.com

mkdir "$work/failing-cargo"
printf '#!/bin/sh\nexit 1\n' > "$work/failing-cargo/cargo"
chmod +x "$work/failing-cargo/cargo"

passed=0
failed=0

record() {
  if [ "$2" = yes ]; then
    passed=$((passed + 1))
    echo "ok   $1"
  else
    failed=$((failed + 1))
    echo "FAIL $1"
    printf '%s\n' "$output" | sed 's/^/     /'
  fi
}

check() {
  want_status="$2"
  want_text="${3:-}"
  output="$(scripts/quality-check.sh base 2>&1)"
  status=$?
  ok=no
  if [ "$status" = "$want_status" ]; then
    case "$output" in *"$want_text"*) ok=yes ;; esac
  fi
  if [ "$ok" = no ]; then
    output="exit $status, wanted $want_status${want_text:+ and \"$want_text\"}"$'\n'"$output"
  fi
  record "$1" "$ok"
}

new_repo() {
  repo="$work/$1"
  mkdir -p "$repo/src" "$repo/scripts"
  cd "$repo" || exit 1
  cp "$root/scripts/quality-check.sh" "$root/scripts/clippy.toml" scripts/
  printf '[package]\nname = "sample"\nversion = "0.1.0"\nedition = "2021"\n\n[workspace]\n' > Cargo.toml
  echo "target/" > .gitignore
  printf 'pub fn one() -> u32 {\n    1\n}\n' > src/lib.rs
}

commit_base() {
  cargo generate-lockfile --offline --quiet
  git init --quiet
  git add .
  git commit --quiet -m base
  git tag base
}

add_module() {
  echo "pub mod $1;" >> src/lib.rs
}

touch_lib() {
  printf '\npub fn two() -> u32 {\n    2\n}\n' >> src/lib.rs
}

consts() {
  for i in $(seq "$1"); do
    echo "pub const C$i: u32 = $i;"
  done
}

long_function() {
  echo "pub fn long() -> u32 {"
  echo "    let mut total = 0;"
  for _ in $(seq 120); do
    echo "    total += 1;"
  done
  echo "    total"
  echo "}"
}

deep_function() {
  cat <<'EOF'
pub fn deep(x: u32) -> u32 {
    let mut n = 0;
    for a in 0..x {
        for b in 0..a {
            for c in 0..b {
                for d in 0..c {
                    for e in 0..d {
                        for f in 0..e {
                            n += f;
                        }
                    }
                }
            }
        }
    }
    n
}
EOF
}

new_repo nothing-changed
commit_base
check "nothing changed passes" 0 "passed"

new_repo no-rust-changed
commit_base
echo "notes" > NOTES.txt
PATH="$work/failing-cargo:$PATH" check "a change without Rust files passes without running cargo" 0 "passed"

new_repo long-touched
commit_base
long_function >> src/lib.rs
git commit --quiet -am "add a long function"
check "a touched file with a 120-line function fails" 1 "src/lib.rs:4: this function has too many lines"

new_repo long-coloured
commit_base
long_function >> src/lib.rs
CARGO_TERM_COLOR=always check "a long function is found when cargo output is coloured" 1 "src/lib.rs:4: this function has too many lines"

new_repo long-untouched
long_function > src/long.rs
add_module long
commit_base
touch_lib
check "an untouched file with a 120-line function passes" 0 "passed"

new_repo deep-touched
commit_base
deep_function >> src/lib.rs
check "nesting deeper than 5 in a touched file fails" 1 "this block is too nested"

new_repo unformatted-touched
commit_base
echo "pub fn  messy( )->u32{2}" >> src/lib.rs
check "a touched unformatted file fails" 1 "src/lib.rs: not formatted"

new_repo unformatted-untouched
echo "pub fn  messy( )->u32{2}" > src/messy.rs
add_module messy
commit_base
touch_lib
check "an untouched unformatted file passes" 0 "passed"

new_repo big-same-size
consts 600 > src/big.rs
add_module big
commit_base
consts 599 > src/big.rs
echo "pub const LAST: u32 = 600;" >> src/big.rs
check "an old 600-line file that does not grow passes" 0 "passed"

new_repo big-grows
consts 600 > src/big.rs
add_module big
commit_base
consts 601 > src/big.rs
check "an old 600-line file that grows fails" 1 "src/big.rs: grew from 600 to 601 lines"

new_repo big-new
commit_base
consts 600 > src/big.rs
add_module big
check "a new 600-line file fails" 1 "src/big.rs: new file has 600 lines"

new_repo big-in-tests
commit_base
mkdir tests
consts 600 > tests/big.rs
check "a 600-line file under tests/ passes" 0 "passed"

new_repo deleted
consts 600 > src/old.rs
add_module old
commit_base
git rm --quiet src/old.rs
printf 'pub fn one() -> u32 {\n    1\n}\n' > src/lib.rs
check "a deleted file is ignored" 0 "passed"

new_repo broken
commit_base
printf '\npub fn broken() -> u32 {\n    missing\n}\n' >> src/lib.rs
check "a change that does not compile fails and shows why" 1 "cannot find value"

new_repo plain-clippy
deep_function >> src/lib.rs
long_function >> src/lib.rs
commit_base
output="$(cargo clippy --locked -- -D warnings 2>&1)" && ok=yes || ok=no
record "the limits do not apply to a plain cargo clippy" "$ok"

echo
echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
