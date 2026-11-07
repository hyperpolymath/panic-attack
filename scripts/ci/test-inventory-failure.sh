#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/repo/tests"
printf '' > "$work/repo/tests/broken.rs"
cat > "$work/bin/cargo" <<'MOCK'
#!/usr/bin/env bash
case " $* " in
  *' --lib '*) printf 'library_control: test\n' ;;
  *) exit 42 ;;
esac
MOCK
chmod +x "$work/bin/cargo"
cd "$work/repo"
set +e
PATH="$work/bin:$PATH" bash "$root/scripts/proven/inventory.sh" "$work/inventory.json"
status=$?
set -e
[ "$status" -eq 42 ] || { echo 'failed enumeration was not preserved' >&2; exit 1; }
[ ! -e "$work/inventory.json" ] || { echo 'partial inventory was emitted' >&2; exit 1; }
cat > "$work/bin/cargo" <<'MOCK'
#!/usr/bin/env bash
exit 0
MOCK
set +e
PATH="$work/bin:$PATH" bash "$root/scripts/proven/inventory.sh" "$work/empty.json"
status=$?
set -e
[ "$status" -eq 1 ] && [ ! -e "$work/empty.json" ] || { echo 'empty inventory was certified' >&2; exit 1; }
echo 'Inventory failure and empty-suite controls passed.'
