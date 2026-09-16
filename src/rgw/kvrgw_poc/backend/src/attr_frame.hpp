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

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace kvrgw {

/*
 * Internal object attributes (manifest, compression table, encryption
 * metadata). Values may be hundreds of KB, so lengths are 32-bit; the
 * user metadata codec in id_meta.hpp caps values at 2 KB and is not
 * reused here.
 *
 * Wire layout, all integers big-endian:
 *   u16 count
 *   count times: u16 key_len, key bytes, u32 val_len, value bytes
 * Keys are sorted ascending and unique.
 */

using AttrPair = std::pair<std::string_view, std::string_view>;

inline constexpr size_t kMaxAttrKeyLen = 256;

bool encode_attr_frame(std::span<const AttrPair> attrs,
                       std::vector<uint8_t>& out);
bool decode_attr_frame(std::span<const uint8_t> frame,
                       std::vector<AttrPair>& out);
bool encoded_attr_frame_size(std::span<const uint8_t> input,
                             size_t& out_size);

}  // namespace kvrgw
