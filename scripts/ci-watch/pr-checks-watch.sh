#!/usr/bin/env bash
# PR check-run terminal-detection watch for run_workflow 'command' handler.
# Reads ONE JSON object on stdin {cursor, config:{pr, repo, min_checks?, grace_seconds?, require_names?}}
# Prints ONE JSON object on stdout {outcome, cursor, payload} and exits 0.
# `payload` is a JSON-ENCODED STRING, not a nested object: the handler rejects an object
# there and fails the node. Read it downstream as the text of {{<watchId>.output}}.
# Terminal detection keys on CHECK-RUN buckets, never on the REST combined status.
#
# -----------------------------------------------------------------------------
# Why this exists
# -----------------------------------------------------------------------------
# This project's repos (and the related Amazon FSx for NetApp ONTAP repos, e.g. the
# Observability-integrations and S3 Access Points pattern repos) run CI entirely as
# GitHub Actions check runs, never as legacy commit statuses. A `github-pr` watch keys
# terminal detection on the REST combined commit status, which stays `pending` forever
# when there are no commit statuses -- so it never surfaces terminal on these PRs,
# whether the checks are all green or one has failed. This command-handler watch reads
# `gh pr checks` buckets instead, so it reports terminal success and terminal failure
# correctly on FSx for ONTAP repos that use Actions-only CI.
#
# -----------------------------------------------------------------------------
# stdin / stdout contract (run_workflow `command` watch)
# -----------------------------------------------------------------------------
# stdin  (ONE JSON object):
#   { "cursor": <previous cursor or null>,
#     "config": { "pr": 464,
#                 "repo": "Yoshiki0705/FSx-for-ONTAP-S3AccessPoints-Serverless-Patterns",
#                 "min_checks": 1, "grace_seconds": 180, "require_names": [] },
#     "workspacePath": "...", "additionalDirectories": [] }
#
# stdout (ONE JSON object, exit 0). `payload` is a string holding this JSON object:
#   { "outcome": "idle" | "new-activity" | "terminal-state",
#     "cursor": { "completed": ["check-a","check-b"], "digest": "<sha>" },
#     "payload": "{\"result\":\"success\"|\"failure\"|null,\"pr\":464,\"repo\":\"...\",
#                  \"passed\":29,\"failed\":1,\"pending\":0,\"skipped\":1,
#                  \"failing\":[\"python-lint\"],\"merge_state\":\"CLEAN\"}" }
#   (shown unescaped for readability; on the wire it is one escaped string)
#
# stdin `config.pr` must be a bare integer. Anything else (for example a step's whole
# prose message from `{{<step>.output}}`) exits 2, which the handler treats as a rejected
# input: the node fails at once instead of idling until the loop budget runs out.
#
#   - terminal-state + payload.result == "success" -> downstream merge step proceeds.
#   - terminal-state + payload.result == "failure" -> downstream respond step reads
#     payload.failing and branches to fix.
#   - new-activity -> a check completed since last poll (completed-set grew) but others
#     remain; loop continues cheaply.
#   - idle -> nothing changed / still pending / within grace window with too few checks.
#   The loop stop condition is `<watchId>.terminal`, which fires on the first terminal-state.
#
# -----------------------------------------------------------------------------
# Wiring it into a run_workflow `workflowPrompt` brief (paste verbatim)
# -----------------------------------------------------------------------------
# For the CI-wait step, do NOT use a `github-pr` watch handler -- the target repos run
# CI only as GitHub Actions check runs, and the `github-pr` handler keys terminal
# detection on the REST combined commit status, which stays `pending` forever when
# there are no legacy commit statuses. Instead emit a `watch` node with
# handler: "command" whose `command` is the single static line
# `bash "$HOME"/Projects/fsxn-cyber-resilience-patterns/scripts/ci-watch/pr-checks-watch.sh`
# (run_workflow's command watch needs the ABSOLUTE resolved path at use time; the
# orchestrator supplies it in the per-run workflowPrompt brief, which is ephemeral and
# not committed, so no home-directory path is tracked in this repo).
# (absolute path; no args, no `{{...}}` in the command). Put the PR number and repo in
# the watch `config` as template-resolved keys:
# `{"pr": {{pr_number}}, "repo": "{{repo}}", "min_checks": 1, "grace_seconds": 180}`.
# The script reads that config from stdin and prints `{outcome, cursor, payload}`. Use
# the loop stop condition `"<watchId>.terminal"`. After the watch, branch on
# `{{<watchId>.output}}`: `payload.result == "success"` -> merge step;
# `payload.result == "failure"` -> respond/fix step that reads `payload.failing`.
#
# Because the `command` watch runs ONE static line and template-resolves every OTHER
# config key, the PR/repo MUST travel through `config` (stdin), never through the
# command string. That is why this script takes zero args.
# -----------------------------------------------------------------------------
set -uo pipefail

# The handler requires "payload" to be a STRING, so every object payload built below is
# encoded to a JSON string here, in one place. If jq itself fails, print the input as is:
# the handler then fails the node loudly rather than the script guessing.
emit() {
  local out
  out="$(jq -c 'if (.payload | type) == "object" then .payload |= tojson else . end' <<<"$1" 2>/dev/null)" || out="$1"
  printf '%s\n' "$out"
  exit 0
}
# Fail safe: any unexpected error returns a valid idle object so the loop keeps polling.
trap 'emit "{\"outcome\":\"idle\",\"cursor\":null,\"payload\":{\"result\":null,\"error\":\"script_error\"}}"' ERR

IN="$(cat)"
PR="$(jq -r '.config.pr'   <<<"$IN")"
REPO="$(jq -r '.config.repo' <<<"$IN")"
MIN_CHECKS="$(jq -r '.config.min_checks   // 1'   <<<"$IN")"
# GRACE is reserved. The intended grace window ("zero checks AND head commit younger
# than grace_seconds -> idle") was not wired in: the zero-checks guard below keys on
# min_checks only, and commit-age lookup is deliberately out of scope here. Kept so the
# accepted config key is documented and read; mark unused for shellcheck until enforced.
# shellcheck disable=SC2034
GRACE="$(jq -r '.config.grace_seconds // 180'     <<<"$IN")"
PREV_COMPLETED="$(jq -c '.cursor.completed // []' <<<"$IN")"
REQUIRE="$(jq -c '.config.require_names // []'     <<<"$IN")"

# Bad input is a configuration error, not a transient one. Exit 2 makes the handler fail
# the watch node without a retry; idling here would hide a wrong config for hours.
if [[ ! "$PR" =~ ^[0-9]+$ || -z "$REPO" || "$REPO" == "null" ]]; then
  printf 'pr-checks-watch: config.pr must be a bare integer and config.repo must be set (pr=%s)\n' \
    "$(printf '%s' "$PR" | tr '\n' ' ' | cut -c1-80)" >&2
  exit 2
fi

# --- read check runs via gh (check-run conclusions, NOT combined status) ---
# GH_PAGER='' and 2>/dev/null strip the interactive spinner; --jq guarantees JSON-only stdout.
# `gh pr checks` exits non-zero for the NORMAL fail (1) and pending (8) cases, so we must
# capture GH_RC without letting those documented exits trip the ERR trap -- otherwise the
# trap would emit idle on a genuine check failure, reproducing the very bug this replaces.
# GH_RC is only a cheap corroboration; the authoritative decision is the BUCKET counts
# parsed below. Only GH_RC > 1 (a real gh/transport error) short-circuits to idle.
GH_RC=0
CHECKS="$(GH_PAGER='' gh pr checks "$PR" --repo "$REPO" \
            --json name,state,bucket --jq '.' 2>/dev/null)" || GH_RC=$?
# gh exit: 0 pass, 8 pending, 1 fail, >1 real error. On a real error, stay idle.
if [[ $GH_RC -ne 0 && $GH_RC -ne 8 && $GH_RC -ne 1 ]]; then
  emit '{"outcome":"idle","cursor":null,"payload":{"result":null,"error":"gh_error"}}'
fi
[[ -z "$CHECKS" || "$CHECKS" == "null" ]] && CHECKS='[]'

# Optional allowlist of required check names (default: evaluate all).
if [[ "$REQUIRE" != "[]" ]]; then
  CHECKS="$(jq -c --argjson keep "$REQUIRE" '[ .[] | select(.name as $n | $keep|index($n)) ]' <<<"$CHECKS")"
fi

TOTAL=$(jq 'length' <<<"$CHECKS")
PASS=$(jq '[.[]|select(.bucket=="pass")]|length'               <<<"$CHECKS")
SKIP=$(jq '[.[]|select(.bucket=="skipping")]|length'           <<<"$CHECKS")
FAIL=$(jq '[.[]|select(.bucket=="fail" or .bucket=="cancel")]|length' <<<"$CHECKS")
PEND=$(jq '[.[]|select(.bucket=="pending")]|length'            <<<"$CHECKS")
FAILING=$(jq -c '[.[]|select(.bucket=="fail" or .bucket=="cancel")|.name]' <<<"$CHECKS")

# mergeStateStatus for the payload only (never a terminal gate).
MSS="$(GH_PAGER='' gh pr view "$PR" --repo "$REPO" --json mergeStateStatus \
         --jq '.mergeStateStatus' 2>/dev/null)"; [[ -z "$MSS" ]] && MSS="UNKNOWN"

# Completed set + digest for the cursor (cheap repeated polls / new-activity detection).
COMPLETED=$(jq -c '[.[]|select(.bucket!="pending")|.name]|sort' <<<"$CHECKS")
DIGEST=$(jq -c '[.[]|{name,bucket}]|sort_by(.name)' <<<"$CHECKS" | shasum -a 256 | cut -d" " -f1)
NEW_CURSOR=$(jq -cn --argjson c "$COMPLETED" --arg d "$DIGEST" '{completed:$c,digest:$d}')

# Grace window: too few checks yet AND head commit young → idle, do not call it terminal.
if [[ "$TOTAL" -lt "$MIN_CHECKS" ]]; then
  emit "$(jq -cn --argjson cur "$NEW_CURSOR" '{outcome:"idle",cursor:$cur,payload:{result:null,reason:"awaiting_checks"}}')"
fi

PAYLOAD=$(jq -cn --arg pr "$PR" --arg repo "$REPO" --arg mss "$MSS" \
  --argjson pass "$PASS" --argjson fail "$FAIL" --argjson pend "$PEND" \
  --argjson skip "$SKIP" --argjson failing "$FAILING" \
  '{pr:($pr|tonumber),repo:$repo,passed:$pass,failed:$fail,pending:$pend,skipped:$skip,failing:$failing,merge_state:$mss}')

if [[ "$PEND" -gt 0 ]]; then
  # Still running. new-activity if a check completed since last poll, else idle.
  if [[ "$COMPLETED" != "$PREV_COMPLETED" ]]; then OUT="new-activity"; else OUT="idle"; fi
  emit "$(jq -cn --arg o "$OUT" --argjson cur "$NEW_CURSOR" --argjson p "$PAYLOAD" \
            '{outcome:$o,cursor:$cur,payload:($p+{result:null})}')"
fi

# No pending checks → terminal. Any fail/cancel → failure, else success.
if [[ "$FAIL" -gt 0 ]]; then RESULT="failure"; else RESULT="success"; fi
emit "$(jq -cn --argjson cur "$NEW_CURSOR" --argjson p "$PAYLOAD" --arg r "$RESULT" \
          '{outcome:"terminal-state",cursor:$cur,payload:($p+{result:$r})}')"
