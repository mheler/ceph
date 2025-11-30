// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab ft=cpp

#pragma once

#include <map>
#include <optional>
#include <atomic>
#include "rgw_common.h"
#include "rgw_zone_types.h"
#include "common/Thread.h"
#include "common/ceph_mutex.h"

#define RGW_CLOUD_DELETE_HASH_PRIME 7877

namespace rgw::sal {
class Driver;
}

namespace rgw::cloud_delete {

// Persisted entry stored in the cloud-delete FIFO queue for async remote deletion
struct CloudDeleteEntry {
  rgw_bucket src_bucket;
  rgw_obj_key src_key;
  std::string src_version_id;
  std::string target_bucket_name;
  RGWZoneGroupPlacementTierS3 placement;
  uint32_t retry_count{0};
  ceph::real_time enqueue_time;
  ceph::real_time next_retry_time;  // Don't process before this time (exponential backoff)

  void encode(ceph::buffer::list& bl) const {
    ENCODE_START(1, 1, bl);
    encode(src_bucket, bl);
    encode(src_key, bl);
    encode(src_version_id, bl);
    encode(target_bucket_name, bl);
    encode(placement, bl);
    encode(retry_count, bl);
    encode(enqueue_time, bl);
    encode(next_retry_time, bl);
    ENCODE_FINISH(bl);
  }

  void decode(ceph::buffer::list::const_iterator& bl) {
    DECODE_START(1, bl);
    decode(src_bucket, bl);
    decode(src_key, bl);
    decode(src_version_id, bl);
    decode(target_bucket_name, bl);
    decode(placement, bl);
    decode(retry_count, bl);
    decode(enqueue_time, bl);
    decode(next_retry_time, bl);
    DECODE_FINISH(bl);
  }
};
WRITE_CLASS_ENCODER(CloudDeleteEntry)

class CloudDelete : public DoutPrefixProvider {
  CephContext *cct;
  rgw::sal::Driver* driver;
  std::unique_ptr<rgw::sal::CloudDelete> sal_cloud_delete;
  int max_objs{0};
  std::vector<std::string> obj_names;
  std::atomic<bool> down_flag{false};

  class Worker : public Thread {
    CloudDelete *parent;
    ceph::mutex lock = ceph::make_mutex("CloudDelete::Worker");
    ceph::condition_variable cond;
  public:
    explicit Worker(CloudDelete *p) : parent(p) {}
    void *entry() override;
    void wake();
  };

  std::unique_ptr<Worker> worker;

public:
  ~CloudDelete() {
    stop_processor();
  }

  CloudDelete() : cct(nullptr), driver(nullptr), max_objs(0) {}

  int initialize(CephContext *_cct, rgw::sal::Driver* _driver);
  int enqueue(const DoutPrefixProvider* dpp, optional_yield y,
              const CloudDeleteEntry& entry);
  void start_processor();
  void stop_processor();

  CephContext *get_cct() const override { return cct; }
  unsigned get_subsys() const override;
  std::ostream& gen_prefix(std::ostream& out) const override;

  int process(optional_yield y);
};

struct CloudDeleteContext {
  std::optional<rgw::sal::Attrs> attrs;
  std::optional<obj_version> check_objv;  // version to check during delete
};

std::unique_ptr<CloudDelete> make_cloud_delete();

CloudDeleteContext prepare_cloud_delete_context(
    const DoutPrefixProvider* dpp,
    rgw::sal::Driver* driver,
    rgw::sal::Object* obj,
    bool is_versioned_delete_marker_creation,
    optional_yield y,
    const rgw::sal::Attrs* preloaded_attrs = nullptr);

int maybe_enqueue_cloud_delete(const DoutPrefixProvider* dpp,
                               rgw::sal::Driver* driver,
                               const std::map<std::string, ceph::buffer::list>& attrs,
                               const rgw_bucket& bucket,
                               const rgw_obj_key& obj_key,
                               const std::string& version_id,
                               bool is_current,
                               optional_yield y);

int try_enqueue_after_delete(const DoutPrefixProvider* dpp,
                             rgw::sal::Driver* driver,
                             const CloudDeleteContext& cloud_ctx,
                             const rgw_bucket& bucket,
                             const rgw_obj_key& obj_key,
                             const std::string& version_id,
                             bool is_current,
                             optional_yield y);

} // namespace rgw::cloud_delete
