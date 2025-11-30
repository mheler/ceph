// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab ft=cpp

#include "rgw_cloud_delete.h"

#include "common/ceph_time.h"
#include "rgw_obj_manifest.h"
#include "rgw_sal.h"
#include "driver/rados/rgw_sal_rados.h"
#include "rgw_zone.h"
#include "rgw_http_errors.h"
#include "driver/rados/rgw_lc_tier.h"

#define dout_subsys ceph_subsys_rgw

namespace rgw::cloud_delete {

/** Prepare cloud delete context by reading object attrs before deletion. */
CloudDeleteContext prepare_cloud_delete_context(
    const DoutPrefixProvider* dpp,
    rgw::sal::Driver* driver,
    rgw::sal::Object* obj,
    bool is_versioned_delete_marker_creation,
    optional_yield y,
    const rgw::sal::Attrs* preloaded_attrs)
{
  if (!driver || !driver->get_rgwcloud_delete() || is_versioned_delete_marker_creation) return {};

  const rgw::sal::Attrs* attrs = preloaded_attrs;
  if (!attrs) {
    if (obj->get_obj_attrs(y, dpp) < 0) return {};
    attrs = &obj->get_attrs();
  }

  CloudDeleteContext ctx;
  ctx.attrs = *attrs;
#ifdef WITH_RADOS
  if (auto ro = dynamic_cast<rgw::sal::RadosObject*>(obj)) {
    if (auto* v = ro->get_state().objv_tracker.version_for_check()) {
      ctx.check_objv = *v;  // copy the version for conditional delete
    }
  }
#endif

  return ctx;
}

/** Enqueue cloud delete if object was cloud-tiered and delete_with_head_object enabled. */
int maybe_enqueue_cloud_delete(const DoutPrefixProvider* dpp,
                               rgw::sal::Driver* driver,
                               const std::map<std::string, ceph::buffer::list>& attrs,
                               const rgw_bucket& bucket,
                               const rgw_obj_key& obj_key,
                               const std::string& version_id,
                               bool is_current,
                               optional_yield y)
{
  auto* queue = driver ? driver->get_rgwcloud_delete() : nullptr;
  if (!queue) return 0;
  auto attr_iter = attrs.find(RGW_ATTR_MANIFEST);
  if (attr_iter == attrs.end()) return 0;
  RGWObjManifest manifest;
  try {
    auto bliter = attr_iter->second.cbegin();
    decode(manifest, bliter);
  } catch (const buffer::error&) {
    return 0;
  }
  if (!manifest.is_tier_type_s3()) return 0;
  RGWObjTier tier_config;
  manifest.get_tier_config(&tier_config);
  auto& s3 = tier_config.tier_placement.t.s3;
  bool allow_delete = s3.delete_with_head_object;
  auto* zone = driver->get_zone();
  if (!allow_delete) {
    rgw_placement_rule rule = manifest.get_head_placement_rule();
    rule.storage_class = tier_config.tier_placement.storage_class;
    std::unique_ptr<rgw::sal::PlacementTier> live_tier;
    int r = zone->get_zonegroup().get_placement_tier(rule, &live_tier);
    if (r >= 0 && live_tier && live_tier->is_tier_type_s3()) {
      allow_delete = live_tier->delete_with_head_object();
    }
  }
  if (!allow_delete) return 0;
  auto& zg = zone->get_zonegroup();
  std::string target_bucket = s3.make_target_bucket_name(
      zg.get_name(),
      tier_config.tier_placement.storage_class,
      bucket.name,
      bucket.tenant);
  rgw::cloud_delete::CloudDeleteEntry entry;
  entry.src_bucket = bucket;
  entry.src_key = obj_key;
  entry.src_version_id = version_id;
  entry.target_bucket_name = target_bucket;
  entry.placement = s3;
  entry.enqueue_time = ceph::real_clock::now();
  entry.next_retry_time = entry.enqueue_time;  // Process immediately on first attempt
  int ret = queue->enqueue(dpp, y, entry);
  if (ret < 0) {
    ldpp_dout(dpp, 1) << __func__ << ": WARNING: failed to enqueue cloud delete: "
                      << ret << " (bucket=" << bucket.name
                      << ", key=" << obj_key.name << ") - remote object may be orphaned" << dendl;
  }
  return ret;
}

int try_enqueue_after_delete(const DoutPrefixProvider* dpp,
                             rgw::sal::Driver* driver,
                             const CloudDeleteContext& cloud_ctx,
                             const rgw_bucket& bucket,
                             const rgw_obj_key& obj_key,
                             const std::string& version_id,
                             bool is_current,
                             optional_yield y) {
  if (!cloud_ctx.attrs.has_value()) return 0;
  return maybe_enqueue_cloud_delete(dpp, driver, *cloud_ctx.attrs,
                                    bucket, obj_key, version_id,
                                    is_current, y);
}

} // namespace rgw::cloud_delete
