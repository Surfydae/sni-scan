#!/usr/bin/env bash
# =============================================================================
#  sni-scan.sh v1.2 — перебор SNI для СВОЕГО VLESS-сервера (Reality / TLS+Vision)
#
#  Что делает:
#   1) читает файл со списком доменов-кандидатов   (ключ -f / --file);
#   2) делает контрольный хендшейк со СЛУЧАЙНЫМ SNI — видно, какой
#      сертификат сервер отдаёт "по умолчанию"; у Reality это сертификат dest,
#      т.е. прямая подсказка, какой SNI надо ставить;
#   3) перебором пробует каждый SNI на указанный IP:PORT (ключи -i и -p):
#      TLS-хендшейк, версия TLS, шифр, ALPN, ключевой обмен (X25519),
#      валидность цепочки + совпадение имени, время хендшейка;
#   4) печатает таблицу, сортирует кандидатов по качеству, пишет TSV (-o).
#
#  Нужно: bash 4+, openssl 1.1.1+ (лучше 3.x), coreutils (timeout), xargs.
#  Лицензия: public domain / делай что хочешь.
# =============================================================================

set -uo pipefail

VERSION="1.2"

SELF="${BASH_SOURCE[0]}"
[[ "$SELF" == /* ]] || SELF="$PWD/$SELF"

# ------------------------------------------------------------- параметры -----
# Значения по умолчанию берутся из окружения: так их получают воркеры xargs.
FILE="${SNIS_FILE:-}"
HOSTIP="${SNIS_IP:-}"
PORT="${SNIS_PORT:-443}"
TMO="${SNIS_TIMEOUT:-5}"
JOBS="${SNIS_JOBS:-16}"
OUT="${SNIS_OUT:-}"
ALPN="${SNIS_ALPN:-h2,http/1.1}"
ANY_TLS="${SNIS_ANY_TLS:-0}"
DO_HTTP="${SNIS_DO_HTTP:-0}"
HTTP_WAIT="${SNIS_HTTP_WAIT:-1}"
ONLY_GOOD="${SNIS_ONLY_GOOD:-0}"
NEED_DNS="${SNIS_NEED_DNS:-0}"
NO_BASELINE="${SNIS_NO_BASELINE:-0}"
TOPN="${SNIS_TOPN:-20}"
NOCOLOR="${SNIS_NOCOLOR:-0}"
MODE="scan"
PROBE_SNI=""

usage() {
	cat <<'EOF'
sni-scan.sh — перебор SNI для VLESS-сервера (Reality / TLS + Vision)

ИСПОЛЬЗОВАНИЕ
  ./sni-scan.sh -f <файл-со-SNI> -i <IP-сервера> [-p 443] [опции]

ОБЯЗАТЕЛЬНЫЕ КЛЮЧИ
  -f, --file PATH     файл со списком доменов-кандидатов: по одному в строке,
                      "#" — комментарий; https://, :порт, /путь, "*." срезаются
  -i, --ip ADDR       IP (или хост) вашего VLESS-сервера

ОПЦИИ
  -p, --port N        TLS-порт сервера                      (по умолчанию 443)
  -t, --timeout SEC   таймаут одной попытки                                (5)
  -j, --jobs N        сколько проверок параллельно                        (16)
  -o, --out PATH      сохранить полный результат в TSV-файл
  -a, --alpn LIST     ALPN-список, "" — не отправлять            (h2,http/1.1)
  -n, --top N         сколько лучших кандидатов показать в итоге          (20)
  -g, --only-good     в процессе печатать только GOOD/OK
      --any-tls       не требовать TLS 1.3 (по умолчанию хендшейк -tls1_3)
      --http          доп. проверка: отдаёт ли сервер HTTP-ответ (медленнее)
      --http-wait SEC сколько ждать HTTP-ответ                            (1)
      --need-dns      пропускать домены, которые не резолвятся
      --no-baseline   не делать контрольный запрос со случайным SNI
      --no-color      без цвета
  -h, --help          справка
  -V, --version       версия

ПРИМЕРЫ
  ./sni-scan.sh -f sni.txt -i 203.0.113.10
  ./sni-scan.sh -f sni.txt -i 203.0.113.10 -p 8443 -j 32 -t 4 -g -o good.tsv
  ./sni-scan.sh -f sni.txt -i vps.example.net --http --need-dns -o all.tsv
  ./sni-scan.sh -f sni.txt -i 203.0.113.10 --any-tls -a ''      # самый мягкий режим

ВЕРДИКТЫ
  GOOD  хендшейк ок, TLS 1.3, сертификат валиден И выдан на этот же домен
        (обычно ещё X25519 + h2) — лучший кандидат для sni/serverName
  OK    хендшейк ок, TLS 1.3, но сертификат на другое имя / не проверился
  WEAK  соединение есть, но TLS ниже 1.3 либо сертификата нет
  FAIL  не подключилось: timeout / refused / TLS alert

ПРО REALITY (важно)
  Reality-сервер проксирует чужой (не своего клиента) TLS-хендшейк на свой dest,
  поэтому контрольный запрос со случайным SNI показывает сертификат именно dest.
  Имена из этого сертификата (CN и SAN) — и есть то, что надо ставить в sni /
  serverName на клиенте и в serverNames на сервере. Хороший кандидат:
  TLS 1.3 + X25519 + h2 + verify=ok.

Скрипт просто делает TLS-хендшейк к тому серверу, который вы указали.
Предназначен для диагностики своих серверов.
EOF
}

need_val() {
	[[ $# -ge 2 && -n "${2:-}" ]] || {
		echo "Ошибка: у ключа $1 нет значения" >&2
		exit 2
	}
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	-f | --file)
		need_val "$@"
		FILE="$2"
		shift 2
		;;
	-i | --ip | --host)
		need_val "$@"
		HOSTIP="$2"
		shift 2
		;;
	-p | --port)
		need_val "$@"
		PORT="$2"
		shift 2
		;;
	-t | --timeout)
		need_val "$@"
		TMO="$2"
		shift 2
		;;
	-j | --jobs)
		need_val "$@"
		JOBS="$2"
		shift 2
		;;
	-o | --out | --output)
		need_val "$@"
		OUT="$2"
		shift 2
		;;
	-a | --alpn)
		ALPN="${2:-}"
		shift 2
		;;
	-n | --top)
		need_val "$@"
		TOPN="$2"
		shift 2
		;;
	-g | --only-good)
		ONLY_GOOD=1
		shift
		;;
	--any-tls)
		ANY_TLS=1
		shift
		;;
	--http)
		DO_HTTP=1
		shift
		;;
	--no-http)
		DO_HTTP=0
		shift
		;;
	--http-wait)
		need_val "$@"
		HTTP_WAIT="$2"
		DO_HTTP=1
		shift 2
		;;
	--need-dns)
		NEED_DNS=1
		shift
		;;
	--no-baseline)
		NO_BASELINE=1
		shift
		;;
	--no-color)
		NOCOLOR=1
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	-V | --version)
		echo "sni-scan.sh $VERSION"
		exit 0
		;;
	--_probe) # внутренний режим: одна проверка, вывод одной TSV-строкой
		need_val "$@"
		MODE="probe"
		PROBE_SNI="$2"
		shift 2
		;;
	*)
		echo "Неизвестный ключ: $1" >&2
		echo "Справка: $0 --help" >&2
		exit 2
		;;
	esac
done

# ---------------------------------------------------------------- цвета ------
if [[ "$NOCOLOR" == "1" || ! -t 1 ]]; then
	C_R="" C_G="" C_Y="" C_B="" C_D="" C_0=""
else
	C_R=$'\033[31m' C_G=$'\033[32m' C_Y=$'\033[33m' C_B=$'\033[36m' C_D=$'\033[2m' C_0=$'\033[0m'
fi

die() {
	echo "${C_R}Ошибка:${C_0} $*" >&2
	exit 1
}

command -v openssl >/dev/null 2>&1 || die "не найден openssl (установи: apt install openssl / dnf install openssl)"
TIMEOUT_BIN="$(command -v timeout || true)"

run_tmo() {
	if [[ -n "$TIMEOUT_BIN" ]]; then "$TIMEOUT_BIN" -k 1 "$TMO" "$@"; else "$@"; fi
}

now_ms() {
	local n
	n="$(date +%s%N 2>/dev/null)"
	if [[ -z "$n" || "$n" == *N* ]]; then echo $(($(date +%s) * 1000)); else echo $((n / 1000000)); fi
}

short() { # short <строка> <макс-длина>
	local s="${1:--}" n="$2"
	[[ -z "$s" ]] && s="-"
	if ((${#s} > n)); then echo "${s:0:n-1}~"; else echo "$s"; fi
}

verify_txt() { # код openssl -> человеческое объяснение
	case "${1%% *}" in
	"") echo "-" ;;
	0) echo "ok" ;;
	10) echo "expired" ;;
	18 | 19) echo "self-signed" ;;
	20 | 21) echo "no-chain" ;;
	62) echo "name-mismatch" ;;
	*) echo "code=${1%% *}" ;;
	esac
}

# ============================== одна проверка ================================
probe_one() {
	local sni="$1"

	local -a args=(-connect "$HOSTIP:$PORT" -servername "$sni" -verify_hostname "$sni" -verify 5)
	[[ -n "$ALPN" ]] && args+=(-alpn "$ALPN")
	[[ "$ANY_TLS" == "1" ]] || args+=(-tls1_3)

	# --- фаза 1: только хендшейк (быстро, сразу закрываем соединение) ---
	local raw rc t0 t1 ms
	t0="$(now_ms)"
	raw="$(run_tmo openssl s_client "${args[@]}" </dev/null 2>&1)"
	rc=$?
	t1="$(now_ms)"
	ms=$((t1 - t0))

	local tls cipher alpn_neg tempkey verify cn http reason verdict score
	tls="$(sed -n -E 's/^[[:space:]]*Protocol[[:space:]]*:[[:space:]]*//p' <<<"$raw" | head -1)"
	[[ -z "$tls" ]] && tls="$(grep -o 'New, TLSv[0-9.]*' <<<"$raw" | head -1 | sed 's/New, //')"
	cipher="$(sed -n -E 's/.*Cipher is ([^ ]+).*/\1/p' <<<"$raw" | head -1)"
	[[ -z "$cipher" ]] && cipher="$(sed -n -E 's/^[[:space:]]*Cipher[[:space:]]*:[[:space:]]*//p' <<<"$raw" | head -1)"
	alpn_neg="$(sed -n -E 's/^ALPN protocol: //p' <<<"$raw" | head -1)"
	[[ -z "$alpn_neg" ]] && alpn_neg="-"
	# openssl 1.1.1 пишет "Server Temp Key", openssl 3.x — "Peer Temp Key"
	tempkey="$(sed -n -E 's/^(Server|Peer) Temp Key: //p' <<<"$raw" | head -1)"
	[[ -z "$tempkey" ]] && tempkey="-"
	verify="$(sed -n -E 's/^[[:space:]]*Verify return code:[[:space:]]*//p' <<<"$raw" | head -1)"
	cn="$(sed -n -E 's/^subject=.*CN[[:space:]]*=[[:space:]]*//p' <<<"$raw" | head -1)"
	[[ -z "$cn" ]] && cn="$(sed -n -E 's/^depth=0 .*CN[[:space:]]*=[[:space:]]*//p' <<<"$raw" | head -1)"
	http="-"
	reason=""

	if [[ -z "$tls" || "$tls" == "0000" ]]; then
		# ------------------------- разбор причины неудачи -------------------
		verdict="FAIL"
		score=0
		if [[ "$rc" == "124" || "$rc" == "137" ]]; then
			reason="timeout ${TMO}s"
		elif grep -qi 'connection refused' <<<"$raw"; then
			reason="connection refused"
		elif grep -qi 'connection reset\|reset by peer' <<<"$raw"; then
			reason="connection reset"
		elif grep -qi 'name or service not known\|nodename nor servname\|temporary failure in name' <<<"$raw"; then
			reason="dns/host error"
		elif grep -qi 'no protocols available\|unsupported protocol\|wrong version number' <<<"$raw"; then
			reason="нет TLS 1.3 (попробуй --any-tls)"
		elif grep -qi 'no application protocol' <<<"$raw"; then
			reason="ALPN отклонён (попробуй -a '' или -a http/1.1)"
		elif grep -qi 'unrecognized name' <<<"$raw"; then
			reason="SNI отклонён сервером (unrecognized_name)"
		elif grep -qi 'alert' <<<"$raw"; then
			reason="TLS alert: $(grep -o -i -m1 'alert [a-z_ ]*' <<<"$raw" | head -1 | cut -c1-40)"
		else
			reason="$(grep -m1 -i 'error\|errno\|refused' <<<"$raw" | sed -E 's/^[[:space:]]+//' | cut -c1-60)"
			[[ -z "$reason" ]] && reason="хендшейк не состоялся (rc=$rc)"
		fi
	else
		# --- фаза 2 (по желанию): отвечает ли сервер на HTTP-запрос ---
		# Отдельное соединение с ALPN http/1.1 (по h2 текстовый запрос не пройдёт).
		# stdin держим открытым ровно HTTP_WAIT секунд — чтоб успеть считать ответ.
		if [[ "$DO_HTTP" == "1" ]]; then
			local -a hargs=(-connect "$HOSTIP:$PORT" -servername "$sni" -alpn http/1.1 -quiet)
			[[ "$ANY_TLS" == "1" ]] || hargs+=(-tls1_3)
			local hraw
			hraw="$({
				printf 'GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36\r\nAccept: */*\r\nConnection: close\r\n\r\n' "$sni"
				sleep "$HTTP_WAIT"
			} | run_tmo openssl s_client "${hargs[@]}" 2>&1)"
			http="$(grep -m1 -o -E 'HTTP/[0-9.]+ [0-9]{3}' <<<"$hraw" | awk '{print $2}')"
			[[ -z "$http" ]] && http="-"
		fi

		# ------------------------------- оценка ----------------------------------
		score=2
		[[ "$tls" == "TLSv1.3" ]] && score=$((score + 3))
		[[ "${verify%% *}" == "0" ]] && score=$((score + 3))
		[[ "$tempkey" == X25519* ]] && score=$((score + 1))
		[[ "$alpn_neg" == "h2" ]] && score=$((score + 1))
		[[ "$http" != "-" ]] && score=$((score + 1))

		if [[ "$tls" == "TLSv1.3" && "${verify%% *}" == "0" ]]; then
			verdict="GOOD"
		elif [[ "$tls" == "TLSv1.3" ]]; then
			verdict="OK"
		else
			verdict="WEAK"
		fi
		if [[ -z "$cn" ]]; then
			verdict="WEAK"
			reason="без сертификата"
		fi
		[[ -z "$reason" ]] && reason="$(verify_txt "$verify")"
	fi

	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
		"$verdict" "$score" "$ms" "$sni" "${tls:--}" "${cipher:--}" "$alpn_neg" \
		"$tempkey" "$(verify_txt "$verify")" "$http" "${cn:--}" "${reason:--}"
}

if [[ "$MODE" == "probe" ]]; then
	probe_one "$PROBE_SNI"
	exit 0
fi

# ================================== main =====================================
[[ -n "$FILE" ]] || {
	usage >&2
	echo >&2
	die "не указан файл со списком SNI (-f/--file)"
}
[[ -r "$FILE" ]] || die "файл '$FILE' не найден или не читается"
[[ -n "$HOSTIP" ]] || die "не указан адрес сервера (-i/--ip)"
[[ "$PORT" =~ ^[0-9]+$ ]] || die "порт должен быть числом (получено: '$PORT')"
[[ "$JOBS" =~ ^[0-9]+$ && "$JOBS" -gt 0 ]] || die "-j должно быть числом > 0"

print_row() { # вердикт score ms sni tls cipher alpn tempkey verify http cn reason
	local color info
	case "$1" in
	GOOD) color="$C_G" ;;
	OK) color="$C_B" ;;
	WEAK) color="$C_Y" ;;
	*) color="$C_R" ;;
	esac
	if [[ "$1" == "FAIL" ]]; then
		info="${12}"
	else
		info="cert:$(short "${11}" 28) [${9}]"
	fi
	printf "%s%-4s%s %-30s %-6s %-9s %-8s %-5s %6s %s\n" \
		"$color" "$1" "$C_0" "$(short "$4" 30)" "${5#TLS}" "$(short "${8%%,*}" 9)" \
		"${7}" "${10}" "${3}ms" "$info"
}

hdr() {
	printf "${C_D}%-4s %-30s %-6s %-9s %-8s %-5s %6s %s${C_0}\n" \
		"итог" "SNI" "TLS" "KEX" "ALPN" "HTTP" "время" "детали"
}

# ------------------------------------------------- чтение списка кандидатов --
# чистим: CRLF, комментарии, пробелы, схему, путь, порт, "*.", точку в конце, регистр
mapfile -t RAWLIST < <(
	tr -d '\r' <"$FILE" |
		sed -e 's/#.*//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' |
		sed -E -e 's#^[a-zA-Z][a-zA-Z0-9+.-]*://##' -e 's#/.*$##' -e 's/:[0-9]+$//' \
			-e 's/^\*\.//' -e 's/\.$//' |
		tr 'A-Z' 'a-z' |
		awk 'NF && !seen[$0]++'
)

CANDS=()
SKIPPED=0
for h in "${RAWLIST[@]}"; do
	if [[ "$h" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ && "$h" == *.* ]]; then
		if [[ "$NEED_DNS" == "1" ]] && ! getent hosts "$h" >/dev/null 2>&1; then
			SKIPPED=$((SKIPPED + 1))
			continue
		fi
		CANDS+=("$h")
	else
		SKIPPED=$((SKIPPED + 1))
	fi
done

TOTAL="${#CANDS[@]}"
((TOTAL > 0)) || die "в файле '$FILE' не нашлось ни одного валидного домена"

echo
echo "${C_B}==> sni-scan $VERSION${C_0}  цель: ${HOSTIP}:${PORT}   кандидатов: ${TOTAL}$([[ $SKIPPED -gt 0 ]] && echo " (пропущено: $SKIPPED)")"
echo "    таймаут ${TMO}s | потоков ${JOBS} | ALPN '${ALPN:-нет}' | TLS $([[ "$ANY_TLS" == "1" ]] && echo "любой" || echo "только 1.3")$([[ "$DO_HTTP" == "1" ]] && echo " | +HTTP")"

# ------------------------------------------- контрольный запрос (baseline) ---
if [[ "$NO_BASELINE" != "1" ]]; then
	RND="$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom 2>/dev/null | head -c 12).com"
	echo
	echo "${C_B}--- контроль: случайный SNI (${RND}) ---${C_0}"
	BASE_RAW="$(run_tmo openssl s_client -connect "$HOSTIP:$PORT" -servername "$RND" \
		${ALPN:+-alpn "$ALPN"} -showcerts </dev/null 2>&1)"
	BASE_PEM="$(awk '/-BEGIN CERTIFICATE-/{f=1} f{print} /-END CERTIFICATE-/{if(f) exit}' <<<"$BASE_RAW")"
	BASE_TLS="$(sed -n -E 's/^[[:space:]]*Protocol[[:space:]]*:[[:space:]]*//p' <<<"$BASE_RAW" | head -1)"
	BASE_ALPN="$(sed -n -E 's/^ALPN protocol: //p' <<<"$BASE_RAW" | head -1)"
	BASE_KEX="$(sed -n -E 's/^(Server|Peer) Temp Key: //p' <<<"$BASE_RAW" | head -1)"
	if [[ -n "$BASE_PEM" ]]; then
		BASE_SUBJ="$(openssl x509 -noout -subject <<<"$BASE_PEM" 2>/dev/null | sed -E 's/^subject=[[:space:]]*//')"
		BASE_ISS="$(openssl x509 -noout -issuer <<<"$BASE_PEM" 2>/dev/null | sed -E 's/^issuer=[[:space:]]*//')"
		BASE_SAN="$(openssl x509 -noout -ext subjectAltName <<<"$BASE_PEM" 2>/dev/null |
			tr -d ' ' | tr ',' '\n' | sed -n 's/^DNS://p' | paste -sd, -)"
		if [[ -z "$BASE_SAN" ]]; then
			BASE_SAN="$(openssl x509 -noout -text <<<"$BASE_PEM" 2>/dev/null |
				grep -A1 'Subject Alternative Name' | tail -1 | tr -d ' ' | tr ',' '\n' |
				sed -n 's/^DNS://p' | paste -sd, -)"
		fi
		echo "  TLS/KEX/ALPN : ${BASE_TLS:-—} | ${BASE_KEX:-—} | ${BASE_ALPN:-—}"
		echo "  subject      : ${BASE_SUBJ:-—}"
		echo "  issuer       : ${BASE_ISS:-—}"
		echo "  SAN          : ${BASE_SAN:--}"
		echo "  ${C_G}Подсказка:${C_0} сервер отдаёт этот сертификат даже на случайный SNI."
		echo "  У Reality это сертификат его dest — имена выше (CN/SAN) и есть главные"
		echo "  кандидаты в sni/serverName. Добавь их в список и проверь перебором."
	else
		echo "  сертификат не получен: $(grep -m1 -i 'error\|alert\|refused\|timeout' <<<"$BASE_RAW" | sed -E 's/^[[:space:]]+//' | cut -c1-70)"
		echo "  ${C_D}значит сервер фильтрует SNI (или порт закрыт) — перебор ниже покажет${C_0}"
	fi
fi

# ------------------------------------------------------------- сам перебор ---
RAW_RES="$(mktemp -t sniscan.XXXXXX)"
trap 'rm -f "$RAW_RES"' EXIT

export SNIS_IP="$HOSTIP" SNIS_PORT="$PORT" SNIS_TIMEOUT="$TMO" SNIS_ALPN="$ALPN" \
	SNIS_ANY_TLS="$ANY_TLS" SNIS_DO_HTTP="$DO_HTTP" SNIS_HTTP_WAIT="$HTTP_WAIT" SNIS_NOCOLOR=1

echo
echo "${C_B}--- перебор (${TOTAL}) ---${C_0}"
hdr

printf '%s\n' "${CANDS[@]}" |
	xargs -P "$JOBS" -I '{}' "${BASH:-/bin/bash}" "$SELF" --_probe '{}' |
	tee "$RAW_RES" |
	while IFS=$'\t' read -r v sc ms sni tls ciph alpn tk vr ht cn rs; do
		[[ "$ONLY_GOOD" == "1" && "$v" != "GOOD" && "$v" != "OK" ]] && continue
		print_row "$v" "$sc" "$ms" "$sni" "$tls" "$ciph" "$alpn" "$tk" "$vr" "$ht" "$cn" "$rs"
	done

# ---------------------------------------------------------------- итоги ------
cnt() { awk -F'\t' -v v="$1" '$1==v' "$RAW_RES" | wc -l | tr -d ' '; }
n_good="$(cnt GOOD)"
n_ok="$(cnt OK)"
n_weak="$(cnt WEAK)"
n_fail="$(cnt FAIL)"

echo
echo "${C_B}--- итог ---${C_0}  GOOD: ${C_G}${n_good}${C_0} | OK: ${C_B}${n_ok}${C_0} | WEAK: ${C_Y}${n_weak}${C_0} | FAIL: ${C_R}${n_fail}${C_0} | всего: ${TOTAL}"

if ((n_good + n_ok > 0)); then
	echo
	echo "Лучшие кандидаты (до ${TOPN}, сначала самые подходящие и быстрые):"
	hdr
	awk -F'\t' '$1=="GOOD" || $1=="OK"' "$RAW_RES" |
		sort -t$'\t' -k2,2nr -k3,3n |
		head -n "$TOPN" |
		while IFS=$'\t' read -r v sc ms sni tls ciph alpn tk vr ht cn rs; do
			print_row "$v" "$sc" "$ms" "$sni" "$tls" "$ciph" "$alpn" "$tk" "$vr" "$ht" "$cn" "$rs"
		done
	echo
	echo "${C_D}Бери SNI с вердиктом GOOD (TLS1.3 + X25519 + h2 + cert ok) и подставляй в клиент:${C_0}"
	echo "${C_D}  vless://<uuid>@${HOSTIP}:${PORT}?type=tcp&security=reality&sni=<SNI>&fp=chrome&pbk=<publicKey>&sid=<shortId>&flow=xtls-rprx-vision${C_0}"
	echo "${C_D}Для Reality это же имя должно быть в serverNames на сервере (и совпадать с dest).${C_0}"
else
	echo
	echo "${C_Y}Ни один SNI не прошёл.${C_0} Что попробовать:"
	echo "  • проверить, что порт вообще слушает:  nc -vz ${HOSTIP} ${PORT}"
	echo "  • увеличить таймаут и снизить параллельность:  -t 10 -j 4"
	echo "  • разрешить TLS ниже 1.3:  --any-tls"
	echo "  • убрать ALPN:  -a ''"
	echo "  • взять список пожирнее (домены с TLS 1.3 + h2 + X25519, без CDN-редиректов)"
fi

if [[ -n "$OUT" ]]; then
	{
		printf 'verdict\tscore\tms\tsni\ttls\tcipher\talpn\ttemp_key\tverify\thttp\tcert_cn\treason\n'
		sort -t$'\t' -k2,2nr -k3,3n "$RAW_RES"
	} >"$OUT" && echo && echo "Полный результат (TSV): $OUT"
fi
