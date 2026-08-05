// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab ft=cpp

/**
 * SSE-S3 Key Provider client: the only translation unit that pulls in the
 * gRPC headers, which must not spread into the rest of RGW.
 */

#include "rgw_keyprovider.h"

#include <chrono>
#include <errno.h>
#include <memory>
#include <set>
#include <shared_mutex>
#include <string>
#include <vector>

#include <boost/asio/defer.hpp>
#include <fmt/format.h>
#include <grpc/grpc.h>
#include <grpcpp/channel.h>
#include <grpcpp/client_context.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/support/channel_arguments.h>

#include "common/async/waiter.h"
#include "common/async/yield_waiter.h"
#include "common/ceph_crypto.h"
#include "common/ceph_mutex.h"
#include "common/config_obs.h"
#include "common/dout.h"
#include "common/perf_counters.h"
#include "rgw/rgw_asio_thread.h"
#include "rgw/rgw_common.h"
#include "rgw/rgw_perf_counters.h"

#include "keyprovider/v1/keyprovider.grpc.pb.h"
#include "keyprovider/v1/keyprovider.pb.h"

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rgw

namespace rgw::keyprovider {

/// AES-256. The Key Provider must return DEKs of exactly this size.
static constexpr size_t DEK_SIZE = 32;

/**
 * The gRPC client, one per process, built lazily by get_client().
 *
 * Locking: stub_ is guarded by m_channel_. RPCs take a shared lock just long
 * enough to copy the stub pointer; channel swaps take a unique lock and
 * rebuild the stub. The stub owns the channel, so an in-flight RPC keeps the
 * old one alive and a URI swap never disturbs running calls.
 *
 * The channel is plaintext by design: the provider runs co-located with RGW,
 * and securing the provider-to-key-manager hop is the provider's concern.
 *
 * Neither DEKs nor E-DEKs are ever logged: logs carry bucket name/ID, E-DEK
 * length and gRPC status only.
 */
class KeyProviderClientImpl final : public md_config_obs_t {
  CephContext* cct_ = nullptr;
  std::shared_mutex m_channel_;
  using stub_ptr_t = std::shared_ptr<::keyprovider::v1::KeyProviderService::Stub>;
  // Built once per channel, shared by every concurrent RPC: stubs are
  // thread-safe, and constructing one calls Channel::RegisterMethod() for
  // each method on the service.
  stub_ptr_t stub_;

public:
  /// A dead provider does not fail construction: gRPC connects lazily, and
  /// the first RPC reports it as UNAVAILABLE.
  explicit KeyProviderClientImpl(CephContext* cct);

  // Unhook before any member handle_conf_change() touches is destroyed.
  // remove_observer() blocks until in-flight callbacks finish. The ref taken
  // in the constructor keeps cct_ alive until here; release it last.
  ~KeyProviderClientImpl()
  {
    cct_->_conf.remove_observer(this);
    cct_->put();
  }

  KeyProviderClientImpl(const KeyProviderClientImpl&) = delete;
  KeyProviderClientImpl& operator=(const KeyProviderClientImpl&) = delete;
  KeyProviderClientImpl(KeyProviderClientImpl&&) = delete;
  KeyProviderClientImpl& operator=(KeyProviderClientImpl&&) = delete;

  int create_dek(const DoutPrefixProvider* dpp,
      const std::string& bucket_name, const std::string& bucket_id,
      std::string& dek_out, std::string& e_dek_out, optional_yield y);

  int decrypt_dek(const DoutPrefixProvider* dpp,
      const std::string& bucket_name, const std::string& bucket_id,
      const std::string& e_dek, std::string& dek_out, optional_yield y);

  std::vector<std::string> get_tracked_keys() const noexcept override;
  void handle_conf_change(const ConfigProxy& conf,
      const std::set<std::string>& changed) override;

private:
  /// Point the client at the configured URI, building a new insecure channel.
  void set_channel(CephContext* const cct);

  /// No vtable args: their lifetime would have to outlive the channel.
  static ::grpc::ChannelArguments get_default_channel_args();

  /// Copy the shared stub under a shared lock; the copy keeps both the stub
  /// and its channel alive for the call. Never null: the constructor builds
  /// the stub before the client is published.
  stub_ptr_t safe_get_client();

  /// Apply rgw_crypt_sse_s3_keyprovider_timeout_ms, so a hung provider cannot
  /// hang the S3 operation.
  void prepare_call_context(::grpc::ClientContext& context);

  static int transform_status(const ::grpc::Status& status);

  void account_rpc(bool create, int r, ceph::timespan lat);

  /**
   * Start a unary RPC via \p invoke and wait for it. With a coroutine in \p y
   * the frontend thread is released for the round trip; without one there is
   * nothing to suspend, so the caller blocks and reports it through
   * maybe_warn_about_blocking().
   */
  template <typename Invoke>
  ::grpc::Status await_rpc(const DoutPrefixProvider* dpp, optional_yield y,
      Invoke&& invoke);

  /**
   * Shared body of create_dek() and decrypt_dek(). \p on_ok runs after the
   * DEK is validated and moved into \p dek_out, for response handling beyond
   * the DEK. \p dek_out is zeroized and cleared on any failure, so callers
   * only scrub it on the success path.
   */
  template <typename Resp, typename Invoke, typename OnOk>
  int do_rpc(const DoutPrefixProvider* dpp, optional_yield y,
      const char* rpc, bool create, const std::string& bucket_name,
      const std::string& bucket_id, Resp& resp, std::string& dek_out,
      Invoke&& invoke, OnOk&& on_ok);

}; // class KeyProviderClientImpl

KeyProviderClientImpl::KeyProviderClientImpl(CephContext* cct)
    : cct_(cct)
{
  ceph_assert(cct != nullptr);
  cct_->get();
  set_channel(cct);
  cct_->_conf.add_observer(this);
  ldout(cct, 1) << fmt::format(FMT_STRING("KeyProvider: client initialised (timeout={}ms)"),
      cct->_conf->rgw_crypt_sse_s3_keyprovider_timeout_ms)
                << dendl;
}

std::vector<std::string> KeyProviderClientImpl::get_tracked_keys() const noexcept
{
  return { std::string { "rgw_crypt_sse_s3_keyprovider_uri" } };
}

void KeyProviderClientImpl::handle_conf_change(const ConfigProxy&,
    const std::set<std::string>&)
{
  set_channel(cct_);
}

void KeyProviderClientImpl::set_channel(CephContext* const cct)
{
  auto new_uri = std::string(cct->_conf->rgw_crypt_sse_s3_keyprovider_uri);

  std::unique_lock g(m_channel_);
  // Plaintext is intentional: the hop never leaves the host. A bad URI yields
  // a lame channel rather than a null one, so there is nothing to check here.
  auto new_channel = ::grpc::CreateCustomChannel(new_uri,
      ::grpc::InsecureChannelCredentials(), get_default_channel_args());
  ldout(cct, 1) << fmt::format(FMT_STRING("KeyProvider: gRPC channel set to '{}'"), new_uri) << dendl;
  // The stub owns new_channel from here on.
  stub_ = ::keyprovider::v1::KeyProviderService::NewStub(new_channel);
}

::grpc::ChannelArguments KeyProviderClientImpl::get_default_channel_args()
{
  // Tighter than gRPC's defaults (20s min connect timeout, 2min max backoff):
  // the provider is co-located, so reconnect quickly after a restart.
  ::grpc::ChannelArguments args;
  args.SetInt(GRPC_ARG_INITIAL_RECONNECT_BACKOFF_MS, 1000);
  args.SetInt(GRPC_ARG_MIN_RECONNECT_BACKOFF_MS, 1000);
  args.SetInt(GRPC_ARG_MAX_RECONNECT_BACKOFF_MS, 10000);
  return args;
}

KeyProviderClientImpl::stub_ptr_t KeyProviderClientImpl::safe_get_client()
{
  std::shared_lock g(m_channel_);
  return stub_;
}

void KeyProviderClientImpl::prepare_call_context(::grpc::ClientContext& context)
{
  auto timeout_ms = cct_->_conf->rgw_crypt_sse_s3_keyprovider_timeout_ms;
  context.set_deadline(std::chrono::system_clock::now() + std::chrono::milliseconds(timeout_ms));
}

int KeyProviderClientImpl::transform_status(const ::grpc::Status& status)
{
  switch (status.error_code()) {
  case ::grpc::StatusCode::OK:
    return 0;
  case ::grpc::StatusCode::DEADLINE_EXCEEDED:
    return -ETIMEDOUT;
  case ::grpc::StatusCode::UNAVAILABLE:
    return -ERR_SERVICE_UNAVAILABLE;
  case ::grpc::StatusCode::INVALID_ARGUMENT:
    return -EINVAL;
  default:
    return -ERR_INTERNAL_ERROR;
  }
}

void KeyProviderClientImpl::account_rpc(bool create, int r, ceph::timespan lat)
{
  if (!perfcounter) {
    return;
  }
  perfcounter->tinc(create ? l_rgw_keyprovider_create_lat : l_rgw_keyprovider_decrypt_lat, lat);
  if (r == 0) {
    perfcounter->inc(create ? l_rgw_keyprovider_create_ok : l_rgw_keyprovider_decrypt_ok);
  } else {
    perfcounter->inc(create ? l_rgw_keyprovider_create_fail : l_rgw_keyprovider_decrypt_fail);
    if (r == -ERR_SERVICE_UNAVAILABLE) {
      perfcounter->inc(l_rgw_keyprovider_unavailable);
    }
  }
}

template <typename Invoke>
::grpc::Status KeyProviderClientImpl::await_rpc(const DoutPrefixProvider* dpp,
    optional_yield y, Invoke&& invoke)
{
  if (y) {
    // TODO: if a request coroutine is ever cancelled mid-RPC, do_rpc()'s frame
    // (context, request, response) unwinds while the gRPC EventEngine still
    // holds pointers into it -- call context.TryCancel() and drain the
    // completion before unwinding. No frontend binds cancellation slots to
    // request coroutines today.
    auto& yield = y.get_yield_context();
    ceph::async::yield_waiter<::grpc::Status> w;
    // Start from the coroutine's executor, not inline: gRPC completes on an
    // EventEngine thread, so a fast failure could otherwise reach complete()
    // before async_wait() below registers the handler.
    boost::asio::defer(yield.get_executor(), [&w, &invoke]() {
      invoke([&w](::grpc::Status st) {
        w.complete(boost::system::error_code {}, std::move(st));
      });
    });
    return w.async_wait(yield);
  }
  // Nothing to suspend, so this parks the calling thread for the round trip;
  // make that visible to rgw_asio_assert_yielding.
  maybe_warn_about_blocking(dpp);
  // Not waiter<::grpc::Status>: that specialization move-assigns into
  // uninitialised storage, which is UB for a type with non-trivial members,
  // and grpc::Status owns two std::strings. The waiter's mutex orders the
  // write to status against the read after wait().
  ::grpc::Status status;
  ceph::async::waiter<> w;
  invoke([&w, &status](::grpc::Status st) {
    status = std::move(st);
    w();
  });
  w.wait();
  return status;
}

template <typename Resp, typename Invoke, typename OnOk>
int KeyProviderClientImpl::do_rpc(const DoutPrefixProvider* dpp,
    optional_yield y, const char* rpc, bool create,
    const std::string& bucket_name, const std::string& bucket_id,
    Resp& resp, std::string& dek_out, Invoke&& invoke, OnOk&& on_ok)
{
  auto client = safe_get_client();

  ::grpc::ClientContext context;
  prepare_call_context(context);

  auto t0 = ceph::mono_clock::now();
  auto status = await_rpc(dpp, y, [&](auto&& done) {
    invoke(*client, &context, std::move(done));
  });
  auto lat = std::chrono::duration_cast<ceph::timespan>(ceph::mono_clock::now() - t0);

  int r = transform_status(status);
  if (r == 0) {
    if (resp.dek().size() != DEK_SIZE) {
      // The invalid DEK is wiped by the unconditional scrub below.
      ldpp_dout(dpp, 1) << fmt::format(FMT_STRING("KeyProvider: response DEK has invalid length {} (want {})"),
          resp.dek().size(), DEK_SIZE)
                        << dendl;
      r = -EINVAL;
    } else {
      dek_out = std::move(*resp.mutable_dek());
    }
  }
  if (r == 0) {
    r = on_ok(resp);
  }
  if (r < 0) {
    // Never hand a partial or stale key back on an error return.
    ::ceph::crypto::zeroize_for_security(dek_out.data(), dek_out.length());
    dek_out.clear();
  }
  // Unconditional: no key material may survive in the response.
  ::ceph::crypto::zeroize_for_security(resp.mutable_dek()->data(),
      resp.mutable_dek()->length());
  resp.mutable_dek()->clear();

  account_rpc(create, r, lat);

  if (r < 0) {
    ldpp_dout(dpp, 1) << fmt::format(FMT_STRING("KeyProvider: {} failed (bucket_name={}, bucket_id={}): r={} gRPC status {}: {}"),
        rpc, bucket_name, bucket_id, r, static_cast<int>(status.error_code()),
        status.error_message())
                      << dendl;
  } else {
    ldpp_dout(dpp, 20) << fmt::format(FMT_STRING("KeyProvider: {} ok (bucket_name={}, lat={}ms)"),
        rpc, bucket_name,
        std::chrono::duration_cast<std::chrono::milliseconds>(lat).count())
                       << dendl;
  }
  return r;
}

int KeyProviderClientImpl::create_dek(const DoutPrefixProvider* dpp,
    const std::string& bucket_name, const std::string& bucket_id,
    std::string& dek_out, std::string& e_dek_out, optional_yield y)
{
  ldpp_dout(dpp, 20) << fmt::format(FMT_STRING("KeyProvider: create_dek(bucket_name={}, bucket_id={})"),
      bucket_name, bucket_id)
                     << dendl;
  ::keyprovider::v1::CreateRequest req;
  req.set_bucket_name(bucket_name);
  req.set_bucket_id(bucket_id);
  ::keyprovider::v1::CreateResponse resp;

  return do_rpc(dpp, y, "Create", true, bucket_name, bucket_id, resp, dek_out,
      [&](::keyprovider::v1::KeyProviderService::Stub& stub,
          ::grpc::ClientContext* ctx, auto&& done) {
        stub.async()->Create(ctx, &req, &resp, std::move(done));
      },
      [&](::keyprovider::v1::CreateResponse& resp) -> int {
        if (resp.e_dek().empty()) {
          ldpp_dout(dpp, 1) << "KeyProvider: Create returned an empty E-DEK" << dendl;
          return -ERR_INTERNAL_ERROR;
        }
        e_dek_out = std::move(*resp.mutable_e_dek());
        return 0;
      });
}

int KeyProviderClientImpl::decrypt_dek(const DoutPrefixProvider* dpp,
    const std::string& bucket_name, const std::string& bucket_id,
    const std::string& e_dek, std::string& dek_out, optional_yield y)
{
  ldpp_dout(dpp, 20) << fmt::format(FMT_STRING("KeyProvider: decrypt_dek(bucket_name={}, bucket_id={}, e_dek_len={})"),
      bucket_name, bucket_id, e_dek.size())
                     << dendl;
  if (e_dek.empty()) {
    ldpp_dout(dpp, 1) << "KeyProvider: empty E-DEK" << dendl;
    return -EINVAL;
  }
  ::keyprovider::v1::DecryptRequest req;
  req.set_bucket_name(bucket_name);
  req.set_bucket_id(bucket_id);
  req.set_e_dek(e_dek);
  ::keyprovider::v1::DecryptResponse resp;

  return do_rpc(dpp, y, "Decrypt", false, bucket_name, bucket_id, resp, dek_out,
      [&](::keyprovider::v1::KeyProviderService::Stub& stub,
          ::grpc::ClientContext* ctx, auto&& done) {
        stub.async()->Decrypt(ctx, &req, &resp, std::move(done));
      },
      [](::keyprovider::v1::DecryptResponse&) -> int { return 0; });
}

// One client per process, created on first use, so the backend is reachable
// from every code path -- request handling, lifecycle transition and
// reencrypt -- without threading a handle through req_state.
static std::shared_ptr<KeyProviderClientImpl> g_client;
static ceph::mutex g_client_lock = ceph::make_mutex("keyprovider_client");

/// Returns false if rgw_crypt_sse_s3_backend is 'keyprovider' but the provider
/// configuration is incomplete; the daemon should then exit.
static bool validate_configuration(CephContext* cct)
{
  if (cct->_conf->rgw_crypt_sse_s3_keyprovider_uri.empty()) {
    lderr(cct) << "KeyProvider: FATAL: SSE-S3 backend is 'keyprovider', but rgw_crypt_sse_s3_keyprovider_uri is not set" << dendl;
    return false;
  }
  if (cct->_conf->rgw_crypt_sse_s3_keyprovider_timeout_ms == 0) {
    lderr(cct) << "KeyProvider: FATAL: SSE-S3 backend is 'keyprovider', but rgw_crypt_sse_s3_keyprovider_timeout_ms must be greater than zero" << dendl;
    return false;
  }
  return true;
}

/**
 * Get-or-create the client; nullptr if the configuration is invalid. The
 * returned reference keeps the client alive if cleanup() runs while an RPC
 * has its coroutine suspended.
 */
static std::shared_ptr<KeyProviderClientImpl> get_client(CephContext* cct)
{
  std::lock_guard l { g_client_lock };
  if (!g_client) {
    if (!validate_configuration(cct)) {
      return nullptr;
    }
    g_client = std::make_shared<KeyProviderClientImpl>(cct);
  }
  return g_client;
}

int init(CephContext* cct)
{
  return get_client(cct) ? 0 : -EINVAL;
}

int create_dek(const DoutPrefixProvider* dpp, const std::string& bucket_name,
    const std::string& bucket_id, std::string& dek_out,
    std::string& e_dek_out, optional_yield y)
{
  auto client = get_client(dpp->get_cct());
  if (!client) {
    ldpp_dout(dpp, 0) << "ERROR: KeyProvider: SSE-S3 keyprovider backend unavailable" << dendl;
    return -EIO;
  }
  return client->create_dek(dpp, bucket_name, bucket_id, dek_out, e_dek_out, y);
}

int decrypt_dek(const DoutPrefixProvider* dpp, const std::string& bucket_name,
    const std::string& bucket_id, const std::string& e_dek,
    std::string& dek_out, optional_yield y)
{
  auto client = get_client(dpp->get_cct());
  if (!client) {
    ldpp_dout(dpp, 0) << "ERROR: KeyProvider: SSE-S3 keyprovider backend unavailable" << dendl;
    return -EIO;
  }
  return client->decrypt_dek(dpp, bucket_name, bucket_id, e_dek, dek_out, y);
}

void cleanup()
{
  std::lock_guard l { g_client_lock };
  g_client.reset();
}

} // namespace rgw::keyprovider
