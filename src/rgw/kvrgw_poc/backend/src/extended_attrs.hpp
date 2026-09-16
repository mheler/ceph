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

#include "error_codes.hpp"
#include "fdb.hpp"
#include "object_value.hpp"
#include "typed_ids.hpp"

#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace kvrgw {

class KvTransaction;

/*
 * An attr frame that does not fit in the O: record is stored as a run of
 * child keys C:<ref_tag>E<index>, index counting up from 0. Each value is
 * a ChildValueHeader followed by at most kExtendedChunkBytes of payload.
 * The payload of chunk 0 starts with a format byte and the u32 frame
 * length so a reader can prove it reassembled the whole frame.
 *
 * Writes go into the caller's transaction, so the chunks commit together
 * with the O: record that points at them. Cleanup rides the existing
 * C:<ref_tag> prefix clear.
 */

KvrgwErrorCode put_extended_attrs(KvTransaction& tr, bucket_id_t bucket_id,
                                  std::string_view ref_tag,
                                  std::span<const uint8_t> frame);

// nullopt means the chunks are missing or inconsistent.
std::expected<std::optional<std::vector<uint8_t>>, fdb_error_t>
read_extended_attrs(KvTransaction& tr, bucket_id_t bucket_id,
                    std::string_view ref_tag);

// Decides where value.attr_frame lives and sets the flag bits: inline
// when the whole record fits, otherwise chunked under ref_tag via tr.
KvrgwErrorCode place_attr_frame(ObjectValue& value, KvTransaction& tr,
                                bucket_id_t bucket_id,
                                std::string_view ref_tag);

}  // namespace kvrgw
