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

#include "id_tag.hpp"

#include <algorithm>
#include <limits>

namespace kvrgw {

namespace {

constexpr size_t kCountBytes = sizeof(uint16_t);
constexpr size_t kKeyLenBytes = sizeof(uint16_t);
constexpr size_t kValLenBytes = sizeof(uint32_t);

// Walks the frame once. Returns false on any structural problem.
bool walk_attr_frame(std::span<const uint8_t> input, size_t &out_size,
                     std::vector<AttrPair> *out)
{
  if (input.size() < kCountBytes) {
    return false;
  }
  const uint16_t count = read_be_field<uint16_t>(input.data());
  size_t off = kCountBytes;
  std::string_view prev_key;
  for (uint16_t i = 0; i < count; ++i) {
    if (input.size() - off < kKeyLenBytes) {
      return false;
    }
    const uint16_t key_len = read_be_field<uint16_t>(input.data() + off);
    off += kKeyLenBytes;
    if (!key_len || key_len > kMaxAttrKeyLen || input.size() - off < key_len) {
      return false;
    }
    const std::string_view key(
        reinterpret_cast<const char *>(input.data() + off), key_len);
    off += key_len;
    if (i > 0 && !(prev_key < key)) {
      return false;
    }
    prev_key = key;
    if (input.size() - off < kValLenBytes) {
      return false;
    }
    const uint32_t val_len = read_be_field<uint32_t>(input.data() + off);
    off += kValLenBytes;
    if (input.size() - off < val_len) {
      return false;
    }
    if (out) {
      out->emplace_back(
          key, std::string_view(
                   reinterpret_cast<const char *>(input.data() + off), val_len));
    }
    off += val_len;
  }
  out_size = off;
  return true;
}

} // namespace

bool encode_attr_frame(std::span<const AttrPair> attrs,
                       std::vector<uint8_t> &out)
{
  if (attrs.size() > std::numeric_limits<uint16_t>::max()) {
    return false;
  }
  size_t total = kCountBytes;
  for (size_t i = 0; i < attrs.size(); ++i) {
    const auto &[key, value] = attrs[i];
    if (key.empty() || key.size() > kMaxAttrKeyLen ||
        value.size() > std::numeric_limits<uint32_t>::max()) {
      return false;
    }
    if (i > 0 && !(attrs[i - 1].first < key)) {
      return false;
    }
    total += kKeyLenBytes + key.size() + kValLenBytes + value.size();
  }

  out.resize(total);
  uint8_t *p = out.data();
  write_be_field<uint16_t>(p, static_cast<uint16_t>(attrs.size()));
  p += kCountBytes;
  for (const auto &[key, value] : attrs) {
    write_be_field<uint16_t>(p, static_cast<uint16_t>(key.size()));
    p += kKeyLenBytes;
    std::copy(key.begin(), key.end(), reinterpret_cast<char *>(p));
    p += key.size();
    write_be_field<uint32_t>(p, static_cast<uint32_t>(value.size()));
    p += kValLenBytes;
    std::copy(value.begin(), value.end(), reinterpret_cast<char *>(p));
    p += value.size();
  }
  return true;
}

bool decode_attr_frame(std::span<const uint8_t> frame,
                       std::vector<AttrPair> &out)
{
  out.clear();
  size_t size = 0;
  if (!walk_attr_frame(frame, size, &out)) {
    out.clear();
    return false;
  }
  return size == frame.size();
}

bool encoded_attr_frame_size(std::span<const uint8_t> input, size_t &out_size)
{
  return walk_attr_frame(input, out_size, nullptr);
}

} // namespace kvrgw
