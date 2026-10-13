// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab ft=cpp

/*
 * Ceph - scalable distributed file system
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation. See file COPYING.
 *
 */

#pragma once

#include <cerrno>
#include <cstddef>
#include <deque>
#include <string>
#include <utility>
#include <vector>

#include "include/ceph_assert.h"

namespace rgw {

// strand-owned; one instance per shard phase (omap or queue)
class gc_trim_tracker {
  struct entry {
    std::string tag;
    size_t pending; // objects not yet reported
    bool ok = true;
    bool taken = false;

    bool done_ok() const { return pending == 0 && ok; }
  };
  std::deque<entry> entries; // entries[i] is position base + i
  size_t base = 0;
  size_t inflight = 0;
  bool any_failed = false;

 public:
  // nobjs == 0 finishes immediately
  size_t admit(size_t nobjs, std::string tag) {
    entries.push_back({std::move(tag), nobjs});
    if (nobjs > 0) {
      ++inflight;
    }
    return base + entries.size() - 1;
  }

  // -ENOENT is success
  void object_done(size_t pos, int r) {
    ceph_assert(pos >= base && pos - base < entries.size());
    auto& e = entries[pos - base];
    ceph_assert(e.pending > 0);
    if (r != 0 && r != -ENOENT) {
      e.ok = false;
    }
    if (--e.pending == 0) {
      --inflight;
      if (!e.ok) {
        any_failed = true;
      }
    }
  }

  // contiguous all-ok entries from the front, not yet trimmed
  size_t untrimmed() const {
    size_t n = 0;
    for (const auto& e : entries) {
      if (!e.done_ok()) {
        break;
      }
      ++n;
    }
    return n;
  }

  void trimmed(size_t n) {
    ceph_assert(n <= untrimmed());
    entries.erase(entries.begin(), entries.begin() + n);
    base += n;
  }

  // all-ok entries in any order, once each
  std::vector<std::string> take_done_tags() {
    std::vector<std::string> tags;
    for (auto& e : entries) {
      if (e.done_ok() && !e.taken) {
        tags.push_back(std::move(e.tag));
        e.taken = true;
      }
    }
    // drop finished entries from the front; omap mode never uses untrimmed()
    while (!entries.empty() && entries.front().pending == 0 &&
           (entries.front().taken || !entries.front().ok)) {
      entries.pop_front();
      ++base;
    }
    return tags;
  }

  // some finished entry had an object fail
  bool failed() const { return any_failed; }

  // admitted entries not finished
  size_t in_flight() const { return inflight; }
};

} // namespace rgw
