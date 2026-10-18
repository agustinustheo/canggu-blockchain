#!/usr/bin/env bash
# Two validators, two crypto backends, one chain.
#
# Alice verifies ML-DSA batches on the GPU (Metal), Bob on the CPU. Aura alternates block authors,
# so every batch is verified by one backend while authoring and by the other while importing. If
# the GPU ever disagreed with the CPU, the importing node would compute a different state root and
# reject the block, and the two nodes would stop agreeing on finalized blocks.
#
# Usage: scripts/mixed-backends.sh [batches] [intents-per-batch]
set -euo pipefail

BATCHES=${1:-4}
COUNT=${2:-256}
BIN=${BIN:-./target/release}
ALICE_BACKEND=${ALICE_BACKEND:-metal}
BOB_BACKEND=${BOB_BACKEND:-cpu}
WORK=$(mktemp -d)
ALICE_PEER=12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp # node key 0x..01

cleanup() { kill "${PIDS[@]}" 2>/dev/null || true; }
trap cleanup EXIT
PIDS=()

"$BIN/canggu-node" --chain local --alice --base-path "$WORK/alice" --port 30333 --rpc-port 9944 \
	--node-key 0000000000000000000000000000000000000000000000000000000000000001 \
	--crypto-backend "$ALICE_BACKEND" >"$WORK/alice.log" 2>&1 &
PIDS+=($!)
"$BIN/canggu-node" --chain local --bob --base-path "$WORK/bob" --port 30334 --rpc-port 9945 \
	--node-key 0000000000000000000000000000000000000000000000000000000000000002 \
	--bootnodes "/ip4/127.0.0.1/tcp/30333/p2p/$ALICE_PEER" \
	--crypto-backend "$BOB_BACKEND" >"$WORK/bob.log" 2>&1 &
PIDS+=($!)

rpc_raw() { # rpc_raw <port> <method> [params-json]
	curl -s -H 'Content-Type: application/json' \
		-d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":${3:-[]}}" "http://127.0.0.1:$1"
}
rpc() { # string result only
	rpc_raw "$@" | sed -E 's/.*"result":"([^"]*)".*/\1/'
}
header_number() { # header_number <port> [block-hash]
	local params="[]"
	[ -n "${2:-}" ] && params="[\"$2\"]"
	printf '%d' "0x$(rpc_raw "$1" chain_getHeader "$params" | sed -E 's/.*"number":"0x([0-9a-f]+)".*/\1/')"
}
finalized_number() {
	header_number "$1" "$(rpc "$1" chain_getFinalizedHead)"
}

alive() { kill -0 "${PIDS[0]}" 2>/dev/null && kill -0 "${PIDS[1]}" 2>/dev/null || {
	echo "a validator exited; see $WORK/*.log" >&2
	exit 1
}; }

echo "logs: $WORK"
echo "waiting for both validators to finalize blocks..."
until [ "$(finalized_number 9944 2>/dev/null || echo 0)" -ge 2 ] && \
	[ "$(finalized_number 9945 2>/dev/null || echo 0)" -ge 2 ]; do alive; sleep 1; done

for i in $(seq 1 "$BATCHES"); do
	# Alternate the RPC endpoint; the transaction is gossiped to whichever validator authors next.
	port=$((i % 2 == 0 ? 9945 : 9944))
	echo "--- batch $i via :$port"
	"$BIN/canggu" --url "http://127.0.0.1:$port" intents --count "$COUNT" --senders 64 --forge 2 |
		tee -a "$WORK/batches.log"
done

target=$(header_number 9944)
echo "waiting until both validators finalize block #$target..."
until [ "$(finalized_number 9944)" -ge "$target" ] && [ "$(finalized_number 9945)" -ge "$target" ]; do
	alive
	sleep 1
done

echo
echo "=== batch verifications (each batch appears once per validator) ==="
echo "--- Alice ($ALICE_BACKEND):"
grep -h "⚡" "$WORK/alice.log" | sed -E 's/^[0-9-]+ [0-9:]+ //'
echo "--- Bob ($BOB_BACKEND):"
grep -h "⚡" "$WORK/bob.log" | sed -E 's/^[0-9-]+ [0-9:]+ //'

echo
echo "=== block hashes on both validators (must be identical) ==="
mismatch=0
for n in $(seq 1 "$target"); do
	a=$(rpc 9944 chain_getBlockHash "[$n]")
	b=$(rpc 9945 chain_getBlockHash "[$n]")
	[ "$a" = "$b" ] || { echo "#$n MISMATCH alice=$a bob=$b"; mismatch=1; }
done
echo "blocks 1..$target: $([ $mismatch -eq 0 ] && echo identical || echo DIFFERENT)"
echo "finalized: alice #$(finalized_number 9944), bob #$(finalized_number 9945)"
echo
echo "=== who authored each batch block (the other validator re-executed it on import) ==="
for n in $(sed -nE 's/.*block #([0-9]+):.*/\1/p' "$WORK/batches.log"); do
	if grep -q "Prepared block for proposing at $n " "$WORK/alice.log"; then
		echo "#$n: authored by Alice ($ALICE_BACKEND), imported by Bob ($BOB_BACKEND)"
	else
		echo "#$n: authored by Bob ($BOB_BACKEND), imported by Alice ($ALICE_BACKEND)"
	fi
done
exit $mismatch
