// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab ft=cpp

#include "rgw_lc_delete_throttle.h"
#include "rgw_perf_counters.h"

#include <algorithm>
#include <chrono>
#include <cmath>

LCDeleteThrottle::LCDeleteThrottle(uint32_t max_wp_worker)
  : window(std::max(4u, max_wp_worker / 2)),
    p50_idx((window - 1) / 2),
    p95_idx(static_cast<uint32_t>(std::ceil(0.95 * window)) - 1),
    samples(window, 0),
    scratch(window)
{}

uint64_t LCDeleteThrottle::mono_now_us()
{
  return std::chrono::duration_cast<std::chrono::microseconds>(
    ceph::mono_clock::now().time_since_epoch()).count();
}

void LCDeleteThrottle::record(uint64_t latency_us, uint32_t max_sleep_ms,
                              uint64_t ceiling_us)
{
  std::lock_guard l(mutex);

  /*
   * Check staleness: if last record is older than STALENESS_US,
   * zero sleep and reset sample_count to start a fresh window.
   * This prevents a stale cached sleep from the previous run
   * being reused.
   */
  uint64_t now = mono_now_us();
  uint64_t prev = last_record_time.load(std::memory_order_relaxed);
  if (prev > 0 && (now - prev) > STALENESS_US) {
    sleep_us.store(0, std::memory_order_relaxed);
    sample_count = 0;
  }

  samples[write_pos] = latency_us;
  if (++write_pos >= window) write_pos = 0;
  sample_count++;
  last_record_time.store(now, std::memory_order_relaxed);

  if (sample_count >= window) {
    sample_count = 0;
    recompute(max_sleep_ms, ceiling_us);
  }
}

void LCDeleteThrottle::recompute(uint32_t max_sleep_ms, uint64_t ceiling_us)
{
  // copy into pre-allocated scratch for in-place nth_element
  std::copy(samples.begin(), samples.end(), scratch.begin());

  std::nth_element(scratch.begin(), scratch.begin() + p50_idx, scratch.end());
  uint64_t p50 = scratch[p50_idx];

  std::nth_element(scratch.begin() + p50_idx, scratch.begin() + p95_idx,
                   scratch.end());
  uint64_t p95 = scratch[p95_idx];

  uint64_t new_sleep = 0;

  if (p50 == 0) {
    // degenerate case
    new_sleep = 0;
  } else if (ceiling_us > 0 && p50 > ceiling_us) {
    // absolute ceiling breached
    new_sleep = static_cast<uint64_t>(max_sleep_ms) * 1000;
  } else {
    double ratio = static_cast<double>(p95) / p50;
    if (ratio < RATIO_LOW) {
      new_sleep = 0;
    } else {
      double scale = std::clamp(
        (ratio - RATIO_LOW) / (RATIO_HIGH - RATIO_LOW), 0.0, 1.0);
      new_sleep = static_cast<uint64_t>(scale * max_sleep_ms * 1000);
    }
  }

  sleep_us.store(new_sleep, std::memory_order_relaxed);
  if (perfcounter) {
    perfcounter->set(l_rgw_lc_delete_throttle_sleep_us, new_sleep);
  }
}

uint64_t LCDeleteThrottle::get_sleep() const
{
  uint64_t last = last_record_time.load(std::memory_order_relaxed);
  if (last == 0) {
    return 0;
  }
  uint64_t now = mono_now_us();
  if ((now - last) > STALENESS_US) {
    return 0;
  }
  return sleep_us.load(std::memory_order_relaxed);
}
