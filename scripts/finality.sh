#!/usr/bin/env bash
# How fast can Aura + GRANDPA finalize? Runs two validators (Alice, Bob) on localhost and measures,
# for every block, the time from its first appearance to its finalization.
#
#   scripts/finality.sh [seconds]
#
# Knobs:
#   GOSSIP_MS     GRANDPA gossip duration (node flag --grandpa-gossip-ms, default 333)
#   VOTE_LAG      blocks behind best that GRANDPA votes (node flag --grandpa-vote-lag, default 2)
#   BIN           directory with canggu-node and canggu (default ./target/release)
# The slot duration is compiled into the runtime: CANGGU_SLOT_MS=500 cargo build --release.
#
# Localhost has ~0 network latency, so this measures the protocol's own floor. Real validators
# add at least two network round trips per GRANDPA round.
set -euo pipefail

SECONDS_TO_MEASURE=${1:-60}
BIN=${BIN:-./target/release}
GOSSIP_MS=${GOSSIP_MS:-333}
VOTE_LAG=${VOTE_LAG:-2}
WORK=$(mktemp -d)
ALICE_PEER=12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp # node key 0x..01

PIDS=()
cleanup() { kill "${PIDS[@]}" 2>/dev/null || true; }
trap cleanup EXIT

"$BIN/canggu-node" --chain local --alice --base-path "$WORK/alice" --port 30333 --rpc-port 9944 \
	--node-key 0000000000000000000000000000000000000000000000000000000000000001 \
	--grandpa-gossip-ms "$GOSSIP_MS" --grandpa-vote-lag "$VOTE_LAG" >"$WORK/alice.log" 2>&1 &
PIDS+=($!)
"$BIN/canggu-node" --chain local --bob --base-path "$WORK/bob" --port 30334 --rpc-port 9945 \
	--node-key 0000000000000000000000000000000000000000000000000000000000000002 \
	--bootnodes "/ip4/127.0.0.1/tcp/30333/p2p/$ALICE_PEER" \
	--grandpa-gossip-ms "$GOSSIP_MS" --grandpa-vote-lag "$VOTE_LAG" >"$WORK/bob.log" 2>&1 &
PIDS+=($!)

# Let both validators connect and finalize a few blocks before measuring.
until grep -q "finalized #[1-9]" "$WORK/alice.log" 2>/dev/null; do
	kill -0 "${PIDS[0]}" "${PIDS[1]}" 2>/dev/null || { echo "a validator exited; see $WORK" >&2; exit 1; }
	sleep 1
done
sleep 5

echo "slot: ${CANGGU_SLOT_MS:-2000} ms (must match the build)  gossip: ${GOSSIP_MS} ms  vote lag: ${VOTE_LAG}  logs: $WORK"
"$BIN/canggu" --url http://127.0.0.1:9944 finality --seconds "$SECONDS_TO_MEASURE"
