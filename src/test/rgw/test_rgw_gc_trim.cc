// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab

/*
 * Ceph - scalable distributed file system
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 */

#include "rgw/driver/rados/rgw_gc_trim.h"

#include <algorithm>
#include <cerrno>
#include <string>
#include <vector>

#include <gtest/gtest.h>

using rgw::gc_trim_tracker;
using tags_t = std::vector<std::string>;

static void admit_n(gc_trim_tracker& t, size_t n)
{
  for (size_t i = 0; i < n; ++i) {
    t.admit(1, "t" + std::to_string(i));
  }
}

static tags_t sorted(tags_t tags)
{
  std::sort(tags.begin(), tags.end());
  return tags;
}

TEST(gc_trim_tracker, empty)
{
  gc_trim_tracker t;
  EXPECT_EQ(0u, t.untrimmed());
  EXPECT_EQ(0u, t.in_flight());
  EXPECT_FALSE(t.failed());
  EXPECT_TRUE(t.take_done_tags().empty());
}

TEST(gc_trim_tracker, in_order)
{
  gc_trim_tracker t;
  admit_n(t, 5);
  EXPECT_EQ(5u, t.in_flight());
  for (size_t i = 0; i < 5; ++i) {
    t.object_done(i, 0);
  }
  EXPECT_EQ(5u, t.untrimmed());
  EXPECT_EQ(0u, t.in_flight());
  EXPECT_FALSE(t.failed());
}

TEST(gc_trim_tracker, out_of_order)
{
  gc_trim_tracker t;
  admit_n(t, 3);
  t.object_done(2, 0);
  EXPECT_EQ(0u, t.untrimmed());
  t.object_done(1, 0);
  EXPECT_EQ(0u, t.untrimmed());
  t.object_done(0, 0);
  EXPECT_EQ(3u, t.untrimmed());
}

TEST(gc_trim_tracker, gap_blocks)
{
  gc_trim_tracker t;
  admit_n(t, 3);
  t.object_done(0, 0);
  t.object_done(2, 0);
  EXPECT_EQ(1u, t.untrimmed());
  EXPECT_EQ(1u, t.in_flight());
  t.object_done(1, 0);
  EXPECT_EQ(3u, t.untrimmed());
}

TEST(gc_trim_tracker, multi_object_entry_last)
{
  gc_trim_tracker t;
  EXPECT_EQ(0u, t.admit(3, "a"));
  EXPECT_EQ(1u, t.admit(1, "b"));
  EXPECT_EQ(2u, t.admit(1, "c"));
  t.object_done(1, 0);
  t.object_done(2, 0);
  t.object_done(0, 0);
  t.object_done(0, 0);
  EXPECT_EQ(0u, t.untrimmed());
  EXPECT_EQ(1u, t.in_flight());
  t.object_done(0, 0);
  EXPECT_EQ(3u, t.untrimmed());
  EXPECT_EQ(0u, t.in_flight());
}

TEST(gc_trim_tracker, enoent_mixed)
{
  gc_trim_tracker t;
  t.admit(3, "a");
  t.object_done(0, 0);
  t.object_done(0, -ENOENT);
  t.object_done(0, 0);
  EXPECT_EQ(1u, t.untrimmed());
  EXPECT_FALSE(t.failed());
  EXPECT_EQ(tags_t{"a"}, t.take_done_tags());
}

TEST(gc_trim_tracker, failure_blocks)
{
  gc_trim_tracker t;
  admit_n(t, 3);
  t.object_done(0, 0);
  t.object_done(1, -EIO);
  t.object_done(2, 0);
  EXPECT_EQ(1u, t.untrimmed());
  EXPECT_TRUE(t.failed());
  EXPECT_EQ(0u, t.in_flight());
  EXPECT_EQ((tags_t{"t0", "t2"}), sorted(t.take_done_tags()));
  EXPECT_TRUE(t.take_done_tags().empty());
}

TEST(gc_trim_tracker, failed_on_last_object)
{
  gc_trim_tracker t;
  t.admit(3, "a");
  t.object_done(0, -EIO);
  EXPECT_FALSE(t.failed());
  t.object_done(0, 0);
  EXPECT_FALSE(t.failed());
  EXPECT_EQ(1u, t.in_flight());
  t.object_done(0, 0);
  EXPECT_TRUE(t.failed());
  EXPECT_EQ(0u, t.in_flight());
  EXPECT_EQ(0u, t.untrimmed());
  EXPECT_TRUE(t.take_done_tags().empty());
}

TEST(gc_trim_tracker, empty_chain)
{
  gc_trim_tracker t;
  EXPECT_EQ(0u, t.admit(0, "a"));
  EXPECT_EQ(0u, t.in_flight());
  EXPECT_EQ(1u, t.untrimmed());
  EXPECT_EQ(tags_t{"a"}, t.take_done_tags());
}

TEST(gc_trim_tracker, trim_rebase)
{
  gc_trim_tracker t;
  admit_n(t, 5);
  t.object_done(0, 0);
  t.object_done(1, 0);
  t.object_done(2, 0);
  EXPECT_EQ(3u, t.untrimmed());
  t.trimmed(3);
  EXPECT_EQ(0u, t.untrimmed());
  t.object_done(4, 0);
  EXPECT_EQ(0u, t.untrimmed());
  t.object_done(3, 0);
  EXPECT_EQ(2u, t.untrimmed());
  EXPECT_EQ(5u, t.admit(1, "t5"));
  t.object_done(5, 0);
  EXPECT_EQ(3u, t.untrimmed());
}

TEST(gc_trim_tracker, deadline_prefix)
{
  gc_trim_tracker t;
  admit_n(t, 4);
  t.object_done(0, 0);
  t.object_done(1, 0);
  EXPECT_EQ(2u, t.untrimmed());
  EXPECT_EQ(2u, t.in_flight());
  t.trimmed(2);
  EXPECT_EQ(0u, t.untrimmed());
  EXPECT_EQ(2u, t.in_flight());
}

TEST(gc_trim_tracker, done_tags_once)
{
  gc_trim_tracker t;
  admit_n(t, 3);
  t.object_done(1, 0);
  EXPECT_EQ(tags_t{"t1"}, t.take_done_tags());
  EXPECT_TRUE(t.take_done_tags().empty());
  t.object_done(0, 0);
  EXPECT_EQ(tags_t{"t0"}, t.take_done_tags());
  t.object_done(2, 0);
  EXPECT_EQ(tags_t{"t2"}, t.take_done_tags());
  EXPECT_TRUE(t.take_done_tags().empty());
}

TEST(gc_trim_tracker, failed_front_compacts)
{
  gc_trim_tracker t;
  EXPECT_EQ(0u, t.admit(1, "bad"));
  EXPECT_EQ(1u, t.admit(2, "slow"));
  t.object_done(0, -EIO);
  EXPECT_TRUE(t.failed());
  for (size_t i = 2; i < 6; ++i) {
    const std::string tag = "t" + std::to_string(i);
    EXPECT_EQ(i, t.admit(1, tag));
    t.object_done(i, 0);
    EXPECT_EQ(tags_t{tag}, t.take_done_tags());
  }
  t.object_done(1, 0);
  t.object_done(1, 0);
  EXPECT_EQ(tags_t{"slow"}, t.take_done_tags());
  EXPECT_EQ(6u, t.admit(1, "t6"));
  t.object_done(6, 0);
  EXPECT_EQ(tags_t{"t6"}, t.take_done_tags());
  EXPECT_EQ(0u, t.in_flight());
}

TEST(gc_trim_tracker, overtrim_asserts)
{
  gc_trim_tracker t;
  admit_n(t, 2);
  t.object_done(0, 0);
  ASSERT_EQ(1u, t.untrimmed());
  EXPECT_DEATH(t.trimmed(2), "FAILED ceph_assert");
}
