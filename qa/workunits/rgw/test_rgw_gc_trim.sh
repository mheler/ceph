#!/usr/bin/env bash
#
# gc keeps trimming a shard whose processing outlasts rgw_gc_processor_max_time,
# with two processors at once and after a processor is killed under its lease.
# the job runs with one gc shard and no gc threads, and this script sets 16KiB
# stripes, so every deleted 1MiB object leaves an entry on gc.0 with 63 tail objects

set -ex

nobjs=300
tails_per_obj=63
data_pool=default.rgw.buckets.data
gc_pool=default.rgw.log

endpoint=${RGW_ENDPOINT:-$(cat "${TESTDIR}/url_file")}
export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-default}
export AWS_ACCESS_KEY_ID=GCTRIMTESTACCESSKEY1
export AWS_SECRET_ACCESS_KEY=gctrimtestsecretkey000000000000000000001

tmpdir=$(mktemp -d)

cleanup() {
  ceph config rm client rgw_obj_stripe_size
  ceph config rm client rgw_max_chunk_size
  rm -rf "$tmpdir"
}
trap cleanup EXIT

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

s3() {
  aws --endpoint-url "$endpoint" s3 "$@"
}

run_gc() {
  radosgw-admin gc process --include-all "$@"
}

gc_count() {
  radosgw-admin gc list --include-all |
    python3 -c "import json, sys; print(len(json.load(sys.stdin)))"
}

gc_locked() {
  rados -p "$gc_pool" -N gc lock info gc.0 gc_process |
    python3 -c "import json, sys; sys.exit(0 if json.load(sys.stdin)['lockers'] else 1)"
}

bucket_marker() {
  radosgw-admin bucket stats --bucket="$1" |
    python3 -c "import json, sys; print(json.load(sys.stdin)['marker'])"
}

# tail objects in the data pool of the bucket with marker $1
tail_count() {
  rados -p "$data_pool" ls >"$tmpdir/rados-ls" || return
  grep -c "^${1}__shadow_" "$tmpdir/rados-ls" || [ $? -eq 1 ]
}

# upload and delete the objects, leaving one gc entry per object; sets marker
fill_gc() {
  local tails queued
  s3 mb "s3://$1"
  marker=$(bucket_marker "$1")
  s3 cp --recursive --quiet "$tmpdir/objs" "s3://$1"
  tails=$(tail_count "$marker")
  [ "$tails" -ge $((tails_per_obj * nobjs)) ] ||
    fail "$nobjs objects have $tails tail objects, stripe config not applied"
  s3 rm --recursive --quiet "s3://$1"
  queued=$(gc_count)
  [ "$queued" -ge "$nobjs" ] || fail "deleting $nobjs objects queued $queued gc entries"
}

# gc is empty and none of the bucket's tail objects are left
check_drained() {
  local left tails
  left=$(gc_count)
  [ "$left" -eq 0 ] || fail "$left gc entries left"
  tails=$(tail_count "$marker")
  [ "$tails" -eq 0 ] || fail "$tails tail objects of $1 left in $data_pool"
  s3 rb "s3://$1"
}

radosgw-admin user create --uid gc-trim-tester --display-name 'gc trim tester' \
  --access-key "$AWS_ACCESS_KEY_ID" --secret "$AWS_SECRET_ACCESS_KEY" >/dev/null

# radosgw reads both per request; the head holds one chunk, the rest is striped
ceph config set client rgw_obj_stripe_size 16384
ceph config set client rgw_max_chunk_size 16384

mkdir "$tmpdir/objs"
head -c $((nobjs * 1024 * 1024)) /dev/urandom | split -b 1M -a 3 - "$tmpdir/objs/obj-"

####################################
# each run past the deadline trims what it finished

bucket=gc-trim-deadline
fill_gc $bucket

prev=$(gc_count)
runs=0
while [ "$prev" -gt 0 ]; do
  run_gc --rgw-gc-processor-max-time=3 --rgw-gc-max-concurrent-io=1
  runs=$((runs + 1))
  left=$(gc_count)
  [ "$left" -lt "$prev" ] || fail "gc run $runs trimmed nothing, $left entries left"
  [ "$left" -gt 0 ] || [ "$runs" -gt 1 ] || fail "the first gc run drained gc.0, raise nobjs"
  prev=$left
done
check_drained $bucket

####################################
# two processors at once

bucket=gc-trim-concurrent
fill_gc $bucket

prev=$(gc_count)
radosgw-admin gc process --include-all --rgw-gc-processor-max-time=3 &
pid1=$!
radosgw-admin gc process --include-all --rgw-gc-processor-max-time=3 &
pid2=$!
wait $pid1
wait $pid2
left=$(gc_count)
[ "$left" -lt "$prev" ] || fail "concurrent gc runs trimmed nothing, $left entries left"
run_gc
check_drained $bucket

####################################
# a processor killed under its lease

bucket=gc-trim-crash
fill_gc $bucket

radosgw-admin gc process --include-all --rgw-gc-processor-max-time=5 \
  --rgw-gc-max-concurrent-io=1 &
pid=$!
for i in $(seq 50); do
  gc_locked && break
  sleep 0.2
done
kill -KILL $pid || true
rc=0
wait $pid || rc=$?
[ "$rc" -eq 137 ] || fail "gc process exited with $rc before it was killed"
gc_locked || fail "gc.0 was not locked when gc process was killed, raise nobjs"
sleep 6 # past the 5s lease
run_gc
check_drained $bucket

echo OK.
