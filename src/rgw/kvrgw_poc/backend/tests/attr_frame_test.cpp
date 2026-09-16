// -*- mode:C++; tab-width:8; c-basic-offset:2;
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#include "attr_frame.hpp"

#include <cassert>
#include <iostream>
#include <string>
#include <vector>

namespace {

std::vector<uint8_t> encode_ok(std::span<const kvrgw::AttrPair> attrs)
{
  std::vector<uint8_t> out;
  assert(kvrgw::encode_attr_frame(attrs, out));
  return out;
}

void test_roundtrip_large_value()
{
  const std::string manifest(1 << 20, 'm');
  const std::string small("small");
  const kvrgw::AttrPair attrs[] = {{"a.compression", small},
                                   {"a.manifest", manifest}};
  const auto frame = encode_ok(attrs);
  assert(frame.size() == 2 + (2 + 13 + 4 + 5) + (2 + 10 + 4 + manifest.size()));

  size_t size = 0;
  assert(kvrgw::encoded_attr_frame_size(frame, size));
  assert(size == frame.size());

  std::vector<kvrgw::AttrPair> decoded;
  assert(kvrgw::decode_attr_frame(frame, decoded));
  assert(decoded.size() == 2);
  assert(decoded[0].first == "a.compression");
  assert(decoded[0].second == small);
  assert(decoded[1].first == "a.manifest");
  assert(decoded[1].second == manifest);
}

void test_value_over_64k()
{
  const std::string big(70000, 'v');
  const kvrgw::AttrPair attrs[] = {{"k", big}};
  const auto frame = encode_ok(attrs);
  std::vector<kvrgw::AttrPair> decoded;
  assert(kvrgw::decode_attr_frame(frame, decoded));
  assert(decoded[0].second.size() == 70000);
}

void test_empty_frame()
{
  const auto frame = encode_ok({});
  assert(frame.size() == 2);
  std::vector<kvrgw::AttrPair> decoded;
  assert(kvrgw::decode_attr_frame(frame, decoded));
  assert(decoded.empty());
}

void test_rejects_unsorted_and_duplicate_keys()
{
  std::vector<uint8_t> out;
  const kvrgw::AttrPair unsorted[] = {{"b", "1"}, {"a", "2"}};
  assert(!kvrgw::encode_attr_frame(unsorted, out));
  const kvrgw::AttrPair duplicate[] = {{"a", "1"}, {"a", "2"}};
  assert(!kvrgw::encode_attr_frame(duplicate, out));
  const kvrgw::AttrPair empty_key[] = {{"", "1"}};
  assert(!kvrgw::encode_attr_frame(empty_key, out));

  // Same rules on decode: hand-build a frame with keys out of order.
  const kvrgw::AttrPair sorted[] = {{"a", "1"}, {"b", "2"}};
  auto frame = encode_ok(sorted);
  frame[4] = 'b';
  std::vector<kvrgw::AttrPair> decoded;
  assert(!kvrgw::decode_attr_frame(frame, decoded));
  assert(decoded.empty());
}

void test_rejects_truncated_and_trailing_bytes()
{
  const kvrgw::AttrPair attrs[] = {{"key", std::string(100, 'x')}};
  const auto frame = encode_ok(attrs);
  std::vector<kvrgw::AttrPair> decoded;
  for (size_t cut = 0; cut < frame.size(); ++cut) {
    std::span<const uint8_t> truncated(frame.data(), cut);
    assert(!kvrgw::decode_attr_frame(truncated, decoded));
  }
  auto trailing = frame;
  trailing.push_back(0);
  assert(!kvrgw::decode_attr_frame(trailing, decoded));
  size_t size = 0;
  assert(kvrgw::encoded_attr_frame_size(trailing, size));
  assert(size == frame.size());
}

} // namespace

int main()
{
  test_roundtrip_large_value();
  test_value_over_64k();
  test_empty_frame();
  test_rejects_unsorted_and_duplicate_keys();
  test_rejects_truncated_and_trailing_bytes();
  std::cout << "attr_frame_test passed\n";
  return 0;
}
