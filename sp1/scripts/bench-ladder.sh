#!/usr/bin/env bash
# Run one compressed proof per (program, n) in its own process under `/usr/bin/time -l` (peak RSS)
# with a wall-clock cap, appending to bench-results/. Usage:
#   scripts/bench-ladder.sh mldsa 4 16 64      scripts/bench-ladder.sh payroll 16 1024
# Env: CAP_SECS (default 1800), SAVE=1 to also write the proofs to fixtures/.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/canggu-sp1-target}"
BENCH="$CARGO_TARGET_DIR/release/bench"
CAP_SECS="${CAP_SECS:-1800}"
# SP1's defaults (4 parallel core-shard provers, 8 recursion provers, 24 GiB memory limit, 2^22
# row shards) need > 30 GB on this workload and swap on a 24 GB machine. These settings keep
# the peak footprint around 20 GB at ~15% extra wall time. Override by exporting them.
export SP1_WORKER_NUM_CORE_WORKERS="${SP1_WORKER_NUM_CORE_WORKERS:-1}"
export SP1_WORKER_CORE_BUFFER_SIZE="${SP1_WORKER_CORE_BUFFER_SIZE:-1}"
export SP1_WORKER_NUM_RECURSION_PROVER_WORKERS="${SP1_WORKER_NUM_RECURSION_PROVER_WORKERS:-2}"
export SP1_WORKER_RECURSION_PROVER_BUFFER_SIZE="${SP1_WORKER_RECURSION_PROVER_BUFFER_SIZE:-2}"
export SP1_WORKER_NUM_RECURSION_EXECUTOR_WORKERS="${SP1_WORKER_NUM_RECURSION_EXECUTOR_WORKERS:-2}"
export SP1_WORKER_RECURSION_EXECUTOR_BUFFER_SIZE="${SP1_WORKER_RECURSION_EXECUTOR_BUFFER_SIZE:-2}"
export SP1_WORKER_NUM_SPLICING_WORKERS="${SP1_WORKER_NUM_SPLICING_WORKERS:-1}"
export SP1_WORKER_SPLICING_BUFFER_SIZE="${SP1_WORKER_SPLICING_BUFFER_SIZE:-1}"
export ELEMENT_THRESHOLD="${ELEMENT_THRESHOLD:-201326592}" # (2^28 + 2^27) / 2
export HEIGHT_THRESHOLD="${HEIGHT_THRESHOLD:-2097152}"     # 2^22 / 2
PROGRAM="$1"; shift
mkdir -p "$ROOT/bench-results"
# Disk guard: proving large batches swaps heavily on a 24 GB machine; kill the prover if free
# space on the home volume drops below MIN_FREE_GB (default 6.5).
MIN_FREE_GB="${MIN_FREE_GB:-6.5}"
(
	while sleep 3; do
		FREE_KB=$(df -k ~ | tail -1 | awk '{print $4}')
		if awk -v f="$FREE_KB" -v m="$MIN_FREE_GB" 'BEGIN { exit !(f < m * 1048576) }'; then
			echo "disk guard: free space below ${MIN_FREE_GB} GB, killing bench" \
				| tee -a "$ROOT/bench-results/rss.txt"
			pkill -f "$BENCH prove" || true
		fi
	done
) &
GUARD=$!
trap 'kill $GUARD 2>/dev/null' EXIT
for N in "$@"; do
	LOG="$ROOT/bench-results/$PROGRAM-n$N.log"
	echo "== $PROGRAM n=$N (cap ${CAP_SECS}s) -> $LOG"
	EXTRA=()
	[ "${SAVE:-0}" = 1 ] && EXTRA=(--save)
	# `timeout` is not on stock macOS; use perl's alarm, which `exec`s so the timed process is
	# the bench itself.
	/usr/bin/time -l perl -e 'alarm shift; exec @ARGV' "$CAP_SECS" \
		"$BENCH" prove "$PROGRAM" "$N" ${EXTRA[@]+"${EXTRA[@]}"} > "$LOG" 2>&1
	STATUS=$?
	RSS=$(grep "maximum resident set size" "$LOG" | awk '{print $1}')
	REAL=$(grep -E "^ +[0-9.]+ real" "$LOG" | awk '{print $1}')
	echo "$PROGRAM n=$N status=$STATUS wall=${REAL}s peak_rss_bytes=$RSS" \
		| tee -a "$ROOT/bench-results/rss.txt"
	grep '^{' "$LOG" || tail -5 "$LOG"
	df -h ~ | tail -1
done
