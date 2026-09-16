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

#include "extended_attrs.hpp"

#include "id_tag.hpp"
#include "keys.hpp"
#include "kv_store.hpp"

#include <algorithm>
#include <limits>
#include <string>

namespace kvrgw {

namespace {

constexpr size_t kChunk0HeaderBytes = 1 + sizeof(uint32_t);
constexpr size_t kChunk0FrameBytes = kExtendedChunkBytes - kChunk0HeaderBytes;

static_assert(kMaxExtendedAttrBytes / kExtendedChunkBytes + 2 <=
              std::numeric_limits<uint16_t>::max());
static_assert(sizeof(ChildValueHeader) + kExtendedChunkBytes < 10000);

std::string_view as_view(std::span<const uint8_t> bytes)
{
  return {reinterpret_cast<const char *>(bytes.data()), bytes.size()};
}

} // namespace

KvrgwErrorCode put_extended_attrs(KvTransaction &tr, bucket_id_t bucket_id,
                                  std::string_view ref_tag,
                                  std::span<const uint8_t> frame)
{
  if (frame.size() > kMaxExtendedAttrBytes) {
    return KVRGW_ERR_VALUE_TOO_LARGE;
  }
  const ChildValueHeader ch{};

  std::string first;
  first.reserve(kExtendedChunkBytes);
  first.push_back(static_cast<char>(kExtendedFormatV1));
  uint8_t len_be[sizeof(uint32_t)];
  write_be_field<uint32_t>(len_be, static_cast<uint32_t>(frame.size()));
  first.append(reinterpret_cast<const char *>(len_be), sizeof(len_be));
  const size_t n0 = std::min(frame.size(), kChunk0FrameBytes);
  first.append(as_view(frame.first(n0)));

  uint16_t index = 0;
  tr.kv_put(make_ce_key(bucket_id, ref_tag, index++).view(),
            make_child_value(ch, first));

  for (size_t off = n0; off < frame.size();) {
    const size_t n = std::min(frame.size() - off, kExtendedChunkBytes);
    tr.kv_put(make_ce_key(bucket_id, ref_tag, index++).view(),
              make_child_value(ch, as_view(frame.subspan(off, n))));
    off += n;
  }
  return KVRGW_ERR_OK;
}

std::expected<std::optional<std::vector<uint8_t>>, fdb_error_t>
read_extended_attrs(KvTransaction &tr, bucket_id_t bucket_id,
                    std::string_view ref_tag)
{
  const auto prefix = make_ce_prefix(bucket_id, ref_tag);
  // Bound on the next child type so every 2-byte index sorts inside.
  auto end = make_c_prefix(bucket_id, ref_tag);
  end.append_byte(static_cast<uint8_t>(kChildTypeExtended) + 1);
  auto rows = tr.kv_range_scan(prefix.view(), end.view(), 0);
  if (!rows) {
    return std::unexpected(rows.error());
  }
  if (rows->empty()) {
    return std::nullopt;
  }

  std::vector<uint8_t> frame;
  uint32_t total = 0;
  for (size_t i = 0; i < rows->size(); ++i) {
    const auto &row = (*rows)[i];
    if (row.key.size() != prefix.size() + sizeof(uint16_t) ||
        read_be_field<uint16_t>(
            reinterpret_cast<const uint8_t *>(row.key.data()) +
            prefix.size()) != i) {
      return std::nullopt;
    }
    std::string_view payload = child_value_payload(row.value);
    if (payload.empty()) {
      return std::nullopt;
    }
    if (i == 0) {
      if (payload.size() < kChunk0HeaderBytes ||
          static_cast<uint8_t>(payload[0]) != kExtendedFormatV1) {
        return std::nullopt;
      }
      total = read_be_field<uint32_t>(
          reinterpret_cast<const uint8_t *>(payload.data()) + 1);
      if (total > kMaxExtendedAttrBytes) {
        return std::nullopt;
      }
      frame.reserve(total);
      payload.remove_prefix(kChunk0HeaderBytes);
    }
    if (frame.size() + payload.size() > total) {
      return std::nullopt;
    }
    frame.insert(frame.end(), payload.begin(), payload.end());
  }
  if (frame.size() != total) {
    return std::nullopt;
  }
  return frame;
}

KvrgwErrorCode place_attr_frame(ObjectValue &value, KvTransaction &tr,
                                bucket_id_t bucket_id, std::string_view ref_tag)
{
  value.hdr.flags &=
      ~(ObjectValue::kFlagInlineAttrs | ObjectValue::kFlagExtendedAttrs);
  if (value.attr_frame.empty()) {
    return KVRGW_ERR_OK;
  }
  value.hdr.flags |= ObjectValue::kFlagInlineAttrs;
  OValueBuf probe;
  if (write_object_value(probe, value)) {
    return KVRGW_ERR_OK;
  }
  value.hdr.flags &= ~ObjectValue::kFlagInlineAttrs;
  value.hdr.flags |= ObjectValue::kFlagExtendedAttrs;
  return put_extended_attrs(tr, bucket_id, ref_tag, value.attr_frame);
}

} // namespace kvrgw
