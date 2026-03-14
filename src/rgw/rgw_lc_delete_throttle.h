// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab ft=cpp

#pragma once

#include <atomic>
#include <cstdint>
#include <vector>

#include "common/ceph_mutex.h"
#include "common/ceph_time.h"

struct LCDeleteThrottle {
  static constexpr double RATIO_LOW = 2.0;
  static constexpr double RATIO_HIGH = 10.0;
  static constexpr uint64_t STALENESS_US = 60'000'000; // 60 seconds

  const uint32_t window; // max(4, max_wp_worker / 2)
  const uint32_t p50_idx;
  const uint32_t p95_idx;

  ceph::mutex mutex = ceph::make_mutex("LCDeleteThrottle");
  std::vector<uint64_t> samples;     // ring buffer, window elements (us)
  std::vector<uint64_t> scratch;     // reused by recompute()
  uint32_t write_pos{0};             // next write slot
  uint32_t sample_count{0};          // samples written since last recompute

  std::atomic<uint64_t> sleep_us{0}; // cached sleep in us, read lock-free
  std::atomic<uint64_t> last_record_time{0}; // monotonic timestamp (us)

  explicit LCDeleteThrottle(uint32_t max_wp_worker);

  void record(uint64_t latency_us, uint32_t max_sleep_ms,
              uint64_t ceiling_us);

  uint64_t get_sleep() const;

private:
  void recompute(uint32_t max_sleep_ms, uint64_t ceiling_us);

  static uint64_t mono_now_us();
};
