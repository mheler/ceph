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

// Live FDB test for extended attrs. Needs a reachable cluster, like
// kv_range_test. Runs the service in perf mode so no data files are
// written; objects that must land on the storage tier carry one byte.

#include "attr_frame.hpp"
#include "extended_attrs.hpp"
#include "gc_config_state.hpp"
#include "gc_policy.hpp"
#include "gc_worker.hpp"
#include "keys.hpp"
#include "kvrgw_runtime.hpp"
#include "service_impl.hpp"

#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>
#include <optional>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

namespace {

using kvrgw::KvRgwServiceImpl;

constexpr kvrgw::tenant_id_t kTenant = kvrgw::kDefaultTenantId;
constexpr size_t kChunk0Frame = kvrgw::kExtendedChunkBytes - 5;

std::vector<uint8_t> encode(std::span<const kvrgw::AttrPair> attrs)
{
  std::vector<uint8_t> frame;
  assert(kvrgw::encode_attr_frame(attrs, frame));
  return frame;
}

// The 10,000-part scenario: manifest rules, compression blocks, GCM salts.
std::vector<uint8_t> multipart_frame()
{
  const std::string manifest(10000 * 46, 'm');
  const std::string compression(20000 * 30, 'c');
  const std::string salts(10000 * 24, 's');
  const kvrgw::AttrPair attrs[] = {{"compression", compression},
                                   {"crypt.part-numbers", salts},
                                   {"manifest", manifest}};
  return encode(attrs);
}

// One attr whose value is n bytes; the frame is n + 9 bytes.
std::vector<uint8_t> frame_of(size_t n)
{
  const std::string v(n, 'v');
  const kvrgw::AttrPair attrs[] = {{"a", v}};
  return encode(attrs);
}

size_t expected_chunks(size_t frame_bytes)
{
  if (frame_bytes <= kChunk0Frame) {
    return 1;
  }
  const size_t rest = frame_bytes - kChunk0Frame;
  return 1 + (rest + kvrgw::kExtendedChunkBytes - 1) / kvrgw::kExtendedChunkBytes;
}

struct Put {
  KvRgwServiceImpl::PutObjectResult res;
  kvrgw::RefTag ref_tag{};
};

Put put(KvRgwServiceImpl &svc, const std::string &bucket,
        const std::string &key, std::string_view data,
        std::vector<uint8_t> frame)
{
  KvRgwServiceImpl::PutObjectRequest req;
  req.tenant_id = kTenant;
  req.bucket_name = bucket;
  req.object_name = key;
  req.ref_tag = svc.ref_tags().next();
  std::memcpy(req.value.hdr.ref_tag, req.ref_tag.data(), kvrgw::kRefTagSize);
  req.value.hdr.size = data.size();
  req.value.hdr.last_modified_sec = static_cast<uint32_t>(std::time(nullptr));
  req.value.content_type = "application/octet-stream";
  req.value.attr_frame = std::move(frame);
  req.estimated_size = data.size();
  req.cond = nullptr;
  Put out;
  out.ref_tag = req.ref_tag;
  out.res = svc.put_object_route(
      req, reinterpret_cast<const uint8_t *>(data.data()), data.size());
  return out;
}

std::string_view ref_view(const uint8_t *ref_tag)
{
  return {reinterpret_cast<const char *>(ref_tag), kvrgw::kRefTagSize};
}

size_t child_count(kvrgw::KvStore &store, kvrgw::bucket_id_t bucket_id,
                   std::string_view ref_tag)
{
  const auto prefix = kvrgw::make_ce_prefix(bucket_id, ref_tag);
  std::string end(kvrgw::make_c_prefix(bucket_id, ref_tag).view());
  end.push_back(static_cast<char>(kvrgw::kChildTypeExtended + 1));
  auto rows = store.range_scan(prefix.view(), end, 0);
  assert(rows);
  return rows->size();
}

kvrgw::ObjectValue head(KvRgwServiceImpl &svc, const std::string &bucket,
                        const std::string &key)
{
  kvrgw::ObjectValue value;
  std::string detail;
  const auto ec =
      svc.head_object(kTenant, bucket, key, std::nullopt, &value, &detail);
  assert(ec == kvrgw::KVRGW_ERR_OK);
  return value;
}

kvrgw::KvrgwErrorCode get(KvRgwServiceImpl &svc, const std::string &bucket,
                          const std::string &key,
                          std::optional<kvrgw::version_id_t> vid,
                          KvRgwServiceImpl::GetObjectResult *out)
{
  return svc.get_object(kTenant, bucket, key, vid, nullptr, out);
}

void del(KvRgwServiceImpl &svc, const std::string &bucket,
         const std::string &key)
{
  KvRgwServiceImpl::DeleteResult dr;
  const auto ec = svc.delete_object(kTenant, bucket, key, nullptr, &dr);
  assert(ec == kvrgw::KVRGW_ERR_OK);
}

// Runs a gc worker until pred() holds or 20 s pass.
template <typename Pred>
void run_gc_until(kvrgw::KvRgwRuntime &rt, Pred pred)
{
  kvrgw::GcPolicy policy;
  policy.interval_sec = 1;
  kvrgw::GcConfigState config(policy);
  std::atomic<bool> stop{false};
  kvrgw::GcWorker worker(rt.store(), *rt.perf_data_store(), config, stop);
  std::thread runner([&] { worker.run(); });
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(20);
  while (!pred() && std::chrono::steady_clock::now() < deadline) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  stop = true;
  runner.join();
  assert(pred());
}

void txn_del(kvrgw::KvStore &store, std::string_view key)
{
  auto tr = store.begin_transaction();
  assert(tr);
  (*tr)->kv_del(key);
  assert((*tr)->commit());
}

void test_reproducer(KvRgwServiceImpl &svc, kvrgw::KvStore &store,
                     const std::string &bucket, kvrgw::bucket_id_t bucket_id)
{
  const auto frame = multipart_frame();
  assert(frame.size() > 1000000);
  const auto p = put(svc, bucket, "mp", "", frame);
  assert(p.res.error_code == kvrgw::KVRGW_ERR_OK);

  KvRgwServiceImpl::GetObjectResult got;
  assert(get(svc, bucket, "mp", std::nullopt, &got) == kvrgw::KVRGW_ERR_OK);
  assert(got.value.has_extended_attrs());
  assert(!got.value.has_inline_attrs());
  assert(got.value.attr_frame == frame);
  assert(child_count(store, bucket_id, ref_view(got.value.hdr.ref_tag)) ==
         expected_chunks(frame.size()));

  // HEAD never touches the frame.
  const auto h = head(svc, bucket, "mp");
  assert(h.has_extended_attrs());
  assert(h.attr_frame.empty());
  std::cout << "  reproducer: " << frame.size() << " byte frame in "
            << expected_chunks(frame.size()) << " chunks\n";
}

void test_placement_boundaries(KvRgwServiceImpl &svc, kvrgw::KvStore &store,
                               const std::string &bucket,
                               kvrgw::bucket_id_t bucket_id)
{
  struct Case {
    size_t value_bytes;
    bool inline_expected;
  };
  const Case cases[] = {
      {0, true},
      {100, true},
      {kChunk0Frame - 9, false},      // frame exactly fills chunk 0
      {kChunk0Frame - 8, false},      // one byte spills into chunk 1
      {kChunk0Frame + 8192 - 9, false},  // exactly two chunks
      {kChunk0Frame + 8192 - 8, false},  // three chunks
  };
  for (const auto &c : cases) {
    const std::string key = "sz-" + std::to_string(c.value_bytes);
    const auto frame = frame_of(c.value_bytes);
    assert(put(svc, bucket, key, "", frame).res.error_code ==
           kvrgw::KVRGW_ERR_OK);
    KvRgwServiceImpl::GetObjectResult got;
    assert(get(svc, bucket, key, std::nullopt, &got) == kvrgw::KVRGW_ERR_OK);
    assert(got.value.attr_frame == frame);
    const auto n = child_count(store, bucket_id, ref_view(got.value.hdr.ref_tag));
    if (c.inline_expected) {
      assert(got.value.has_inline_attrs());
      assert(n == 0);
    }
    else {
      assert(got.value.has_extended_attrs());
      assert(n == expected_chunks(frame.size()));
    }
    del(svc, bucket, key);
    assert(child_count(store, bucket_id, ref_view(got.value.hdr.ref_tag)) == 0);
  }
  std::cout << "  placement boundaries and delete passed\n";
}

void test_overwrite_gc(kvrgw::KvRgwRuntime &rt, const std::string &bucket,
                       kvrgw::bucket_id_t bucket_id)
{
  auto &svc = rt.service();
  auto &store = rt.store();
  // One byte of data puts the object on the storage tier, so the old
  // record is deferred to the gc worker instead of being freed inline.
  assert(put(svc, bucket, "ow", "x", frame_of(20000)).res.error_code ==
         kvrgw::KVRGW_ERR_OK);
  const auto first = head(svc, bucket, "ow");
  assert(first.has_extended_attrs());
  const std::string ref1(ref_view(first.hdr.ref_tag));
  assert(child_count(store, bucket_id, ref1) == expected_chunks(20009));

  assert(put(svc, bucket, "ow", "x", frame_of(30000)).res.error_code ==
         kvrgw::KVRGW_ERR_OK);
  const auto second = head(svc, bucket, "ow");
  const std::string ref2(ref_view(second.hdr.ref_tag));
  assert(ref1 != ref2);

  run_gc_until(rt, [&] { return child_count(store, bucket_id, ref1) == 0; });
  assert(child_count(store, bucket_id, ref2) == expected_chunks(30009));
  del(svc, bucket, "ow");
  run_gc_until(rt, [&] { return child_count(store, bucket_id, ref2) == 0; });
  std::cout << "  overwrite via gc passed\n";
}

void test_delete_by_version_id(kvrgw::KvRgwRuntime &rt,
                               const std::string &bucket,
                               kvrgw::bucket_id_t bucket_id)
{
  auto &svc = rt.service();
  auto &store = rt.store();
  assert(svc.put_bucket_versioning(kTenant, bucket,
                                   kvrgw::VERSIONING_ENABLED) ==
         kvrgw::KVRGW_ERR_OK);

  const auto f1 = frame_of(20000);
  const auto f2 = frame_of(30000);
  assert(put(svc, bucket, "ver", "", f1).res.error_code == kvrgw::KVRGW_ERR_OK);
  const auto v1 = head(svc, bucket, "ver");
  assert(put(svc, bucket, "ver", "", f2).res.error_code == kvrgw::KVRGW_ERR_OK);
  const auto v2 = head(svc, bucket, "ver");
  const std::string ref1(ref_view(v1.hdr.ref_tag));
  const std::string ref2(ref_view(v2.hdr.ref_tag));
  assert(v1.hdr.version_id != v2.hdr.version_id);

  // The displaced version keeps its chunks until it is deleted.
  assert(child_count(store, bucket_id, ref1) == expected_chunks(f1.size()));
  KvRgwServiceImpl::GetObjectResult old;
  assert(get(svc, bucket, "ver", v1.hdr.version_id, &old) ==
         kvrgw::KVRGW_ERR_OK);
  assert(old.value.attr_frame == f1);

  assert(svc.delete_object_version(kTenant, bucket, "ver", v1.hdr.version_id,
                                   nullptr) == kvrgw::KVRGW_ERR_OK);
  run_gc_until(rt, [&] { return child_count(store, bucket_id, ref1) == 0; });
  assert(child_count(store, bucket_id, ref2) == expected_chunks(f2.size()));

  KvRgwServiceImpl::GetObjectResult cur;
  assert(get(svc, bucket, "ver", std::nullopt, &cur) == kvrgw::KVRGW_ERR_OK);
  assert(cur.value.attr_frame == f2);

  assert(svc.delete_object_version(kTenant, bucket, "ver", v2.hdr.version_id,
                                   nullptr) == kvrgw::KVRGW_ERR_OK);
  assert(child_count(store, bucket_id, ref2) == 0);
  assert(svc.put_bucket_versioning(kTenant, bucket,
                                   kvrgw::VERSIONING_DISABLED) ==
         kvrgw::KVRGW_ERR_OK);
  std::cout << "  delete by version id passed\n";
}

void test_copy(KvRgwServiceImpl &svc, kvrgw::KvStore &store,
               const std::string &bucket, kvrgw::bucket_id_t bucket_id)
{
  const auto frame = multipart_frame();
  assert(put(svc, bucket, "src", "", frame).res.error_code ==
         kvrgw::KVRGW_ERR_OK);

  KvRgwServiceImpl::CopyObjectRequest req;
  req.tenant_id = kTenant;
  req.src_bucket_name = bucket;
  req.src_key = "src";
  req.dst_bucket_name = bucket;
  req.dst_key = "dst";
  req.content_type = "application/octet-stream";
  KvRgwServiceImpl::CopyObjectResult res;
  assert(svc.copy_object(req, &res) == kvrgw::KVRGW_ERR_OK);

  KvRgwServiceImpl::GetObjectResult got;
  assert(get(svc, bucket, "dst", std::nullopt, &got) == kvrgw::KVRGW_ERR_OK);
  assert(got.value.attr_frame == frame);
  const std::string dst_ref(ref_view(got.value.hdr.ref_tag));
  assert(child_count(store, bucket_id, dst_ref) == expected_chunks(frame.size()));

  del(svc, bucket, "src");
  KvRgwServiceImpl::GetObjectResult again;
  assert(get(svc, bucket, "dst", std::nullopt, &again) == kvrgw::KVRGW_ERR_OK);
  assert(again.value.attr_frame == frame);
  del(svc, bucket, "dst");
  assert(child_count(store, bucket_id, dst_ref) == 0);
  std::cout << "  copy passed\n";
}

void test_corruption(KvRgwServiceImpl &svc, kvrgw::KvStore &store,
                     const std::string &bucket, kvrgw::bucket_id_t bucket_id)
{
  // A missing middle chunk. The chunks commit with the record, so a torn
  // set is reported as corruption rather than a missing object.
  assert(put(svc, bucket, "torn", "", frame_of(20000)).res.error_code ==
         kvrgw::KVRGW_ERR_OK);
  const auto torn = head(svc, bucket, "torn");
  const std::string torn_ref(ref_view(torn.hdr.ref_tag));
  assert(child_count(store, bucket_id, torn_ref) == 3);
  txn_del(store, kvrgw::make_ce_key(bucket_id, torn_ref, 1).view());
  KvRgwServiceImpl::GetObjectResult got;
  assert(get(svc, bucket, "torn", std::nullopt, &got) ==
         kvrgw::KVRGW_ERR_CORRUPT_VALUE);

  // A total length that does not match the chunks.
  assert(put(svc, bucket, "short", "", frame_of(20000)).res.error_code ==
         kvrgw::KVRGW_ERR_OK);
  const auto shrt = head(svc, bucket, "short");
  const std::string short_ref(ref_view(shrt.hdr.ref_tag));
  const auto chunk0_key = kvrgw::make_ce_key(bucket_id, short_ref, 0);
  auto chunk0 = store.get(chunk0_key.view());
  assert(chunk0 && *chunk0);
  std::string edited = **chunk0;
  // ChildValueHeader (8) + format byte, then the u32 length: bump it.
  edited[8 + 4] = static_cast<char>(edited[8 + 4] + 1);
  auto tr = store.begin_transaction();
  assert(tr);
  (*tr)->kv_put(chunk0_key.view(), edited);
  assert((*tr)->commit());
  assert(get(svc, bucket, "short", std::nullopt, &got) ==
         kvrgw::KVRGW_ERR_CORRUPT_VALUE);

  del(svc, bucket, "torn");
  del(svc, bucket, "short");
  assert(child_count(store, bucket_id, torn_ref) == 0);
  assert(child_count(store, bucket_id, short_ref) == 0);
  std::cout << "  corruption detection passed\n";
}

void test_cap(KvRgwServiceImpl &svc, kvrgw::KvStore &store,
              const std::string &bucket, kvrgw::bucket_id_t bucket_id)
{
  const auto p =
      put(svc, bucket, "cap", "", frame_of(kvrgw::kMaxExtendedAttrBytes + 1));
  assert(p.res.error_code == kvrgw::KVRGW_ERR_VALUE_TOO_LARGE);
  kvrgw::ObjectValue value;
  std::string detail;
  assert(svc.head_object(kTenant, bucket, "cap", std::nullopt, &value,
                         &detail) == kvrgw::KVRGW_ERR_NO_SUCH_KEY);
  assert(child_count(store, bucket_id, kvrgw::ref_tag_view(p.ref_tag)) == 0);
  std::cout << "  frame cap passed\n";
}

} // namespace

int main()
{
  const std::string run_tag = std::to_string(static_cast<long long>(getpid()));
  const std::string sock = "/tmp/kvrgw-extended-attrs-" + run_tag + ".sock";
  setenv("KVRGW_ADMIN_SOCKET", sock.c_str(), 1);
  setenv("KVRGW_CONFIG_FILE", "/nonexistent/kvrgw.yaml", 1);

  kvrgw::KvRgwRuntime rt;
  kvrgw::KvRgwStartOptions opts;
  opts.perf_mode = true;
  opts.data_root = "/tmp/kvrgw-extended-attrs-" + run_tag;
  if (!rt.start(opts)) {
    std::cerr << "extended_attrs_test: runtime start failed\n";
    return 1;
  }

  auto &svc = rt.service();
  auto &store = rt.store();
  const std::string bucket = "xattrs-" + run_tag;
  assert(svc.create_bucket(kTenant, bucket) == kvrgw::KVRGW_ERR_OK);
  const kvrgw::bucket_id_t bucket_id = svc.resolve_bucket_id(kTenant, bucket);
  assert(bucket_id != 0);

  test_reproducer(svc, store, bucket, bucket_id);
  test_placement_boundaries(svc, store, bucket, bucket_id);
  test_overwrite_gc(rt, bucket, bucket_id);
  test_delete_by_version_id(rt, bucket, bucket_id);
  test_copy(svc, store, bucket, bucket_id);
  test_corruption(svc, store, bucket, bucket_id);
  test_cap(svc, store, bucket, bucket_id);

  del(svc, bucket, "mp");
  (void)svc.delete_bucket(kTenant, bucket);
  rt.stop();
  std::cout << "extended_attrs_test passed\n";
  return 0;
}
