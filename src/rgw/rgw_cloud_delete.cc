// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab ft=cpp

#include "rgw_cloud_delete.h"

#include "common/dout.h"
#include "common/ceph_context.h"
#include "common/errno.h"
#include "rgw_perf_counters.h"
#include "rgw_sal.h"
#include "rgw_sal_rados.h"
#include "rgw_rest_conn.h"
#include "driver/rados/rgw_lc_tier.h"
#include "rgw_http_errors.h"
#include "include/random.h"
#include <fmt/core.h>
#include <chrono>

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rgw

namespace rgw::cloud_delete {

namespace {

constexpr uint32_t max_retry_count = 5;

bool is_terminal_success(int ret) { return ret == 0 || ret == -ENOENT; }

bool is_permanent_failure(int ret) {
  // Don't retry authentication/authorization failures or bad requests
  return ret == -EACCES || ret == -EPERM || ret == -EINVAL;
}

bool is_retryable(int ret) {
  if (is_terminal_success(ret) || is_permanent_failure(ret)) {
    return false;
  }
  // Retry all transient network and server errors:
  // -EBUSY:         HTTP 503 Service Unavailable
  // -EIO:           Network/connection failures
  // -ECONNRESET:    Connection reset by peer
  // -EHOSTUNREACH:  Host unreachable
  // -ENETUNREACH:   Network unreachable
  // -ECONNREFUSED:  Connection refused
  // -ETIMEDOUT:     Timeout
  // -EAGAIN:        Try again
  // -ERR_INTERNAL_ERROR: HTTP 500/502/504 and other server errors
  return ret == -EBUSY ||
         ret == -EIO ||
         ret == -ECONNRESET ||
         ret == -EHOSTUNREACH ||
         ret == -ENETUNREACH ||
         ret == -ECONNREFUSED ||
         ret == -ETIMEDOUT ||
         ret == -EAGAIN ||
         ret == -ERR_INTERNAL_ERROR;
}

/** Delete cloud object by trying both head and versioned naming schemes. */
int handle_entry(const DoutPrefixProvider *dpp, rgw::sal::Driver* driver,
                 const CloudDeleteEntry& entry) {
  auto* store = dynamic_cast<rgw::sal::RadosStore*>(driver);
  if (!store) return -EINVAL;

  const rgw::sal::ZoneGroup& zg = store->get_zone()->get_zonegroup();
  S3RESTConn conn(store->ctx(), "cloudid", {entry.placement.endpoint},
                  entry.placement.key, zg.get_id(),
                  entry.placement.region, entry.placement.host_style);

  auto try_delete = [&](const std::string& name) {
    bufferlist out_bl, bl;
    std::string resource = entry.target_bucket_name + "/" + name;
    return conn.send_resource(dpp, "DELETE", resource, nullptr, nullptr,
                             out_bl, &bl, nullptr, null_yield);
  };

  rgw_obj_key versioned_key = entry.src_key;
  if (versioned_key.instance.empty() && !entry.src_version_id.empty()) {
    versioned_key.set_instance(entry.src_version_id);
  }
  std::string versioned_name = make_target_obj_name(entry.src_bucket.name, versioned_key,
                                                     entry.placement.target_by_bucket, false);
  rgw_obj_key head_key = entry.src_key;
  head_key.instance.clear();
  std::string head_name = make_target_obj_name(entry.src_bucket.name, head_key,
                                                entry.placement.target_by_bucket, true);

  int ret = try_delete(versioned_name);
  if (ret == -ENOENT && head_name != versioned_name) {
    ret = try_delete(head_name);
  }
  return ret;
}

} // anonymous namespace

// CloudDelete wrapper implementation

int CloudDelete::initialize(CephContext *_cct, rgw::sal::Driver* _driver) {
  cct = _cct;
  driver = _driver;

  max_objs = cct->_conf->rgw_cloud_delete_max_objs;
  if (max_objs > RGW_CLOUD_DELETE_HASH_PRIME) {
    max_objs = RGW_CLOUD_DELETE_HASH_PRIME;
  }

  obj_names.clear();
  for (int i = 0; i < max_objs; i++) {
    obj_names.push_back(fmt::format("delete.{}", i));
  }

  // Get SAL implementation from driver
  sal_cloud_delete = driver->get_cloud_delete();
  if (!sal_cloud_delete) {
    ldpp_dout(this, -1) << __PRETTY_FUNCTION__ << ": failed to create SAL cloud delete" << dendl;
    return -EINVAL;
  }

  // Initialize SAL layer
  int ret = sal_cloud_delete->initialize(this, null_yield, max_objs, obj_names);
  if (ret < 0) {
    ldpp_dout(this, -1) << __PRETTY_FUNCTION__ << ": failed to initialize SAL: " << ret << dendl;
    return ret;
  }

  return 0;
}

int CloudDelete::enqueue(const DoutPrefixProvider* dpp, optional_yield y,
                         const CloudDeleteEntry& entry) {
  if (!sal_cloud_delete) return -EINVAL;

  int ret = sal_cloud_delete->enqueue(dpp, y, entry);
  if (ret < 0) return ret;

  if (::perfcounter) ::perfcounter->inc(l_rgw_cloud_delete_queued);

  // Worker may be reset during shutdown; best-effort wake is fine.
  if (auto w = worker.get(); w && w->is_started()) w->wake();

  return 0;
}

void CloudDelete::start_processor() {
  down_flag.store(false, std::memory_order_release);
  if (!worker) {
    worker = std::make_unique<Worker>(this);
  }
  if (!worker->is_started()) {
    worker->create("rgw_cloud_del");
  }
}

void CloudDelete::stop_processor() {
  down_flag.store(true, std::memory_order_release);
  if (worker) {
    if (worker->is_started()) {
      worker->wake();
      worker->join();
    }
    worker.reset();
  }
}

unsigned CloudDelete::get_subsys() const {
  return dout_subsys;
}

std::ostream& CloudDelete::gen_prefix(std::ostream& out) const {
  return out << "cloud_delete: ";
}

// Worker thread implementation

void CloudDelete::Worker::wake() {
  std::lock_guard l{lock};
  cond.notify_one();
}

void *CloudDelete::Worker::entry() {
  while (true) {
    if (int ret = parent->process(null_yield); ret < 0) {
      ldpp_dout(parent, 5) << "cloud delete worker process failed with " << ret << dendl;
    }
    if (parent->down_flag.load(std::memory_order_acquire)) break;
    std::unique_lock l{lock};
    cond.wait_for(l, std::chrono::seconds(parent->cct->_conf->rgw_cloud_delete_interval));
  }
  return nullptr;
}

// Processing logic

int CloudDelete::process(optional_yield y) {
  if (!sal_cloud_delete) return -EINVAL;

  int start = ceph::util::generate_random_number(0, max_objs ? max_objs - 1 : 0);
  for (int i = 0; i < max_objs; i++) {
    int index = (i + start) % max_objs;

    std::string marker;
    bool truncated = false;
    do {
      std::vector<CloudDeleteEntry> entries;
      std::string out_marker;
      truncated = false;

      // Delegate to SAL layer for FIFO operations
      int ret = sal_cloud_delete->list_entries(this, y, index, marker, &out_marker,
                                                64, entries, &truncated);
      if (ret < 0) return ret;
      if (entries.empty()) break;

      marker = out_marker;

      for (auto& e : entries) {
        // Check if we should process this entry yet (exponential backoff)
        ceph::real_time now = ceph::real_clock::now();
        if (e.next_retry_time > now) {
          // Not ready yet, re-enqueue without incrementing retry count
          if (int rret = sal_cloud_delete->enqueue(this, y, e); rret < 0) return rret;
          continue;
        }

        int dret = handle_entry(this, driver, e);
        if (is_terminal_success(dret)) {
          if (::perfcounter) ::perfcounter->inc(l_rgw_cloud_delete_success);
          continue;
        }
        if (is_retryable(dret) && e.retry_count + 1 < max_retry_count) {
          e.retry_count++;
          // Calculate exponential backoff: base_delay * 2^retry_count
          // Base delay = 60 seconds, max ~32 minutes (2^5 * 60s = 1920s)
          uint32_t backoff_secs = 60 * (1 << e.retry_count);
          e.next_retry_time = now + std::chrono::seconds(backoff_secs);

          ldpp_dout(this, 10) << "Cloud delete retry " << e.retry_count
                              << " for " << e.src_bucket.name << "/" << e.src_key.name
                              << " backoff=" << backoff_secs << "s"
                              << " error=" << dret << dendl;

          // Re-enqueue through SAL layer
          if (int rret = sal_cloud_delete->enqueue(this, y, e); rret < 0) return rret;
          if (::perfcounter) ::perfcounter->inc(l_rgw_cloud_delete_retry);
          continue;
        }
        // Permanent failure or max retries exceeded
        ldpp_dout(this, 1) << "WARNING: Cloud delete permanently failed"
                           << " (error=" << dret
                           << ", retries=" << e.retry_count
                           << ") - remote object may be orphaned" << dendl;
        ldpp_dout(this, 10) << "Failed cloud delete details: "
                            << "bucket=" << e.src_bucket.name
                            << " key=" << e.src_key.name
                            << " version=" << e.src_version_id << dendl;
        if (::perfcounter) ::perfcounter->inc(l_rgw_cloud_delete_fail);
      }

      if (!marker.empty()) {
        // Trim through SAL layer
        int trim_ret = sal_cloud_delete->trim_entries(this, y, index, marker);
        if (trim_ret < 0) {
          ldpp_dout(this, 1) << "WARNING: trim failed for index " << index
                             << ": " << trim_ret << dendl;
        }
      }
    } while (truncated && !down_flag.load(std::memory_order_acquire));

    if (down_flag.load(std::memory_order_acquire)) {
      return 0;
    }
  }
  return 0;
}

std::unique_ptr<CloudDelete> make_cloud_delete() {
  return std::make_unique<CloudDelete>();
}

} // namespace rgw::cloud_delete
