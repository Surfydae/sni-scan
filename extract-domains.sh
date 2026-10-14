#!/usr/bin/env bash
#
# extract-domains.sh — вытаскивает домены из JSON-скана (поля "cn" и "sans"),
# выкидывает wildcard-записи (*.example.com), убирает дубликаты
# и пишет результат по одному домену на строку.
#
# Примеры:
#   ./extract-domains.sh scan.json                   # -> domains.txt
#   ./extract-domains.sh scan.json -o out.txt
#   ./extract-domains.sh scan.json -s                # только валидно выглядящие домены
#   ./extract-domains.sh scan.json -o - | head       # в stdout
#   cat scan.json | ./extract-domains.sh -
#
# jq используется, если он есть и JSON валиден; иначе включается
# резервный парсер на awk (работает даже с обрезанным/битым файлом).

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"

usage() {
	cat <<EOF
$SCRIPT_NAME <input.json> [опции]

Извлекает домены из полей "cn" и "sans", убирает wildcard (*) и дубликаты.

Опции:
  -o, --output FILE    куда писать (по умолчанию domains.txt, "-" = stdout)
  -s, --strict         оставить только валидно выглядящие домены (есть точка и буквенный TLD)
  -k, --keep-order     сохранить порядок первого появления (по умолчанию сортировка)
  -e, --exclude REGEX  дополнительно выкинуть домены по regex (можно указывать несколько раз)
  -h, --help           эта справка
EOF
}

INPUT=""
OUTPUT="domains.txt"
STRICT=0
KEEP_ORDER=0
EXCLUDES=""

while [[ $# -gt 0 ]]; do
	case "$1" in
		-o|--output)
			[[ $# -ge 2 ]] || { echo "$SCRIPT_NAME: для $1 нужен аргумент" >&2; exit 1; }
			OUTPUT="$2"; shift 2 ;;
		-e|--exclude)
			[[ $# -ge 2 ]] || { echo "$SCRIPT_NAME: для $1 нужен аргумент" >&2; exit 1; }
			if [[ -z "$EXCLUDES" ]]; then EXCLUDES="$2"; else EXCLUDES="$EXCLUDES|$2"; fi
			shift 2 ;;
		-s|--strict)     STRICT=1; shift ;;
		-k|--keep-order) KEEP_ORDER=1; shift ;;
		-h|--help)       usage; exit 0 ;;
		--)              shift; break ;;
		-)
			if [[ -z "$INPUT" ]]; then INPUT="-"; else echo "$SCRIPT_NAME: лишний аргумент: $1" >&2; exit 1; fi
			shift ;;
		-*)              echo "$SCRIPT_NAME: неизвестная опция: $1" >&2; usage >&2; exit 1 ;;
		*)
			if [[ -z "$INPUT" ]]; then INPUT="$1"; else echo "$SCRIPT_NAME: лишний аргумент: $1" >&2; exit 1; fi
			shift ;;
	esac
done

if [[ -z "$INPUT" ]]; then
	usage >&2
	exit 1
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

if [[ "$INPUT" == "-" ]]; then
	cat > "$tmpdir/input.json"
	INPUT="$tmpdir/input.json"
fi

if [[ ! -r "$INPUT" ]]; then
	echo "$SCRIPT_NAME: не могу прочитать файл: $INPUT" >&2
	exit 1
fi

# --- 1. Достаём сырые значения cn/sans -------------------------------------
extract_raw() {
	if command -v jq >/dev/null 2>&1 && jq -e . "$INPUT" >/dev/null 2>&1; then
		jq -r '.. | objects | ((.cn // empty), (.sans // [] | .[]?)) | select(type == "string")' "$INPUT"
	else
		# Резервный режим: построчный разбор, jq не нужен, битый JSON не страшен.
		awk '
			function emit(s,   v) {
				while (match(s, /"[^"]*"/) > 0) {
					v = substr(s, RSTART + 1, RLENGTH - 2)
					if (v != "") print v
					s = substr(s, RSTART + RLENGTH)
				}
			}
			{
				line = $0
				if (in_sans) {
					if (index(line, "]") > 0) { sub(/\].*$/, "", line); in_sans = 0 }
					emit(line)
					next
				}
				if (match(line, /"sans"[ \t]*:[ \t]*\[/) > 0) {
					rest = substr(line, RSTART + RLENGTH)
					if (index(rest, "]") > 0) { sub(/\].*$/, "", rest) } else { in_sans = 1 }
					emit(rest)
					next
				}
				if (match(line, /"cn"[ \t]*:[ \t]*"[^"]*"/) > 0) {
					v = substr(line, RSTART, RLENGTH)
					sub(/^"cn"[ \t]*:[ \t]*"/, "", v)
					sub(/"$/, "", v)
					if (v != "") print v
					next
				}
			}
		' "$INPUT"
	fi
}

# --- 2. Чистим, фильтруем, дедуплицируем ------------------------------------
extract_raw | awk -v strict="$STRICT" -v excl="$EXCLUDES" '
	{
		d = $0
		gsub(/\r/, "", d)
		sub(/^[ \t]+/, "", d)
		sub(/[ \t]+$/, "", d)
		d = tolower(d)
		sub(/\.$/, "", d)                    # убрать точку в конце FQDN

		if (d == "") next
		if (index(d, "*") > 0) next          # wildcard: *.ozon.ru и подобное
		if (d !~ /^[a-z0-9._-]+$/) next      # мусор вида "TRAEFIK DEFAULT CERT"
		if (strict && d !~ /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.[a-z][a-z]+$/) next
		if (excl != "" && d ~ excl) next

		if (!(d in seen)) { seen[d] = 1; print d }
	}
' > "$tmpdir/out.txt"

if [[ "$KEEP_ORDER" -eq 0 ]]; then
	LC_ALL=C sort "$tmpdir/out.txt" > "$tmpdir/sorted.txt"
	mv "$tmpdir/sorted.txt" "$tmpdir/out.txt"
fi

count=$(wc -l < "$tmpdir/out.txt" | tr -d ' ')

if [[ "$OUTPUT" == "-" ]]; then
	cat "$tmpdir/out.txt"
	echo "$SCRIPT_NAME: домены: $count" >&2
else
	cat "$tmpdir/out.txt" > "$OUTPUT"
	echo "$SCRIPT_NAME: записано $count уникальных доменов в $OUTPUT" >&2
fi
