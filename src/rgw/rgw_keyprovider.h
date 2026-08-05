// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab ft=cpp

/**
 * SSE-S3 'keyprovider' backend: public interface, free of gRPC headers.
 * The client behind it lives entirely in rgw_keyprovider_impl.cc.
 */

#pragma once

#include <string>

#include "common/async/yield_context.h"
#include "common/dout.h"

namespace rgw::keyprovider {

/**
 * Build the process-wide client eagerly and validate its configuration;
 * returns a negative error if it is incomplete, so a misconfigured gateway
 * can refuse to start. Without this call the client is still built lazily
 * on first use (radosgw-admin has no init path).
 */
int init(CephContext* cct);

/**
 * \p bucket_id is the bucket marker, used by the key manager as the KEK
 * derivation salt. \p bucket_name is for the provider's audit log only and
 * may be empty on paths with no request context.
 *
 * On success \p dek_out holds the plaintext 32-byte DEK; the caller owns
 * scrubbing it with ::ceph::crypto::zeroize_for_security(). It is wiped and
 * cleared on every failure. Returns 0 or a negative RGW error.
 *
 * Safe to call from any number of frontend threads. There is deliberately no
 * DEK cache: every encrypted write costs one Create and every encrypted read
 * one Decrypt. Caching belongs in the provider.
 */
int create_dek(const DoutPrefixProvider* dpp, const std::string& bucket_name,
    const std::string& bucket_id, std::string& dek_out,
    std::string& e_dek_out, optional_yield y);

/// \p bucket_id must come from the object's metadata, not the request
/// bucket: the two differ for a replicated object.
int decrypt_dek(const DoutPrefixProvider* dpp, const std::string& bucket_name,
    const std::string& bucket_id, const std::string& e_dek,
    std::string& dek_out, optional_yield y);

/// Drop the process-wide client; any in-flight RPC holds its own reference.
void cleanup();

} // namespace rgw::keyprovider
