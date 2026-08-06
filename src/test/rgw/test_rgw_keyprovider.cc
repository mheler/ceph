// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab

/*
 * Ceph - scalable distributed file system
 *
 * Copyright contributors to the Ceph project
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation. See file COPYING.
 *
 */

/*
 * Drives the SSE-S3 keyprovider client through its public interface --
 * rgw::keyprovider::{init, create_dek, decrypt_dek, cleanup} -- against a
 * fake KeyProviderService on a real gRPC socket. The fake is the sync
 * Service API; it is wire-compatible with the client's async stubs.
 */

#include <atomic>
#include <chrono>
#include <functional>
#include <string>
#include <thread>

#include <boost/asio/io_context.hpp>
#include <boost/asio/spawn.hpp>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>

#include "common/ceph_argparse.h"
#include "common/dout.h"
#include "global/global_init.h"
#include "rgw_common.h"
#include "rgw_keyprovider.h"

#include "keyprovider/v1/keyprovider.grpc.pb.h"

#define dout_subsys ceph_subsys_rgw

using namespace keyprovider::v1;

static const std::string DEK32(32, 'k');

struct FakeProvider final : KeyProviderService::Service {
  std::function<::grpc::Status(const CreateRequest&, CreateResponse*)> on_create;
  std::function<::grpc::Status(const DecryptRequest&, DecryptResponse*)> on_decrypt;
  std::atomic<int> calls = 0;

  ::grpc::Status Create(::grpc::ServerContext*, const CreateRequest* req,
      CreateResponse* resp) override
  {
    ++calls;
    return on_create(*req, resp);
  }

  ::grpc::Status Decrypt(::grpc::ServerContext*, const DecryptRequest* req,
      DecryptResponse* resp) override
  {
    ++calls;
    return on_decrypt(*req, resp);
  }
};

class TestKeyProviderClient : public ::testing::Test {
 protected:
  FakeProvider svc;
  std::unique_ptr<::grpc::Server> server;
  int port = 0;
  const NoDoutPrefix dpp { g_ceph_context, dout_subsys };

  static void set_conf(const char* name, const std::string& value)
  {
    ASSERT_EQ(0, g_ceph_context->_conf.set_val(name, value));
    g_ceph_context->_conf.apply_changes(nullptr);
  }

  static std::string uri_of(int port)
  {
    return "ipv4:127.0.0.1:" + std::to_string(port);
  }

  std::unique_ptr<::grpc::Server> start_server(FakeProvider& provider, int* port)
  {
    ::grpc::ServerBuilder b;
    b.AddListeningPort("127.0.0.1:0", ::grpc::InsecureServerCredentials(), port);
    b.RegisterService(&provider);
    return b.BuildAndStart();
  }

  void SetUp() override
  {
    server = start_server(svc, &port);
    ASSERT_TRUE(server);
    set_conf("rgw_crypt_sse_s3_keyprovider_uri", uri_of(port));
    set_conf("rgw_crypt_sse_s3_keyprovider_timeout_ms", "5000");
  }

  void TearDown() override
  {
    rgw::keyprovider::cleanup();
    if (server) {
      server->Shutdown();
    }
  }
};

TEST_F(TestKeyProviderClient, round_trip)
{
  svc.on_create = [] (const CreateRequest& req, CreateResponse* resp) {
    EXPECT_EQ("testbucket", req.bucket_name());
    EXPECT_EQ("marker123", req.bucket_id());
    resp->set_dek(DEK32);
    resp->set_e_dek("wrapped");
    return ::grpc::Status::OK;
  };
  svc.on_decrypt = [] (const DecryptRequest& req, DecryptResponse* resp) {
    EXPECT_EQ("marker123", req.bucket_id());
    EXPECT_EQ("wrapped", req.e_dek());
    resp->set_dek(DEK32);
    return ::grpc::Status::OK;
  };

  std::string dek, e_dek;
  ASSERT_EQ(0, rgw::keyprovider::create_dek(&dpp, "testbucket", "marker123", dek, e_dek,
      null_yield));
  EXPECT_EQ(DEK32, dek);
  EXPECT_EQ("wrapped", e_dek);

  std::string dek2;
  ASSERT_EQ(0, rgw::keyprovider::decrypt_dek(&dpp, "testbucket", "marker123", e_dek,
      dek2, null_yield));
  EXPECT_EQ(DEK32, dek2);
  EXPECT_EQ(2, svc.calls);
}

TEST_F(TestKeyProviderClient, create_rejects_bad_dek_length)
{
  for (const size_t len : {size_t(0), size_t(16), size_t(33)}) {
    svc.on_create = [len] (const CreateRequest&, CreateResponse* resp) {
      resp->set_dek(std::string(len, 'k'));
      resp->set_e_dek("wrapped");
      return ::grpc::Status::OK;
    };
    std::string dek, e_dek;
    EXPECT_EQ(-EINVAL, rgw::keyprovider::create_dek(&dpp, "b", "id", dek, e_dek,
        null_yield));
    // fails closed: no partial key reaches the caller
    EXPECT_TRUE(dek.empty());
  }
}

TEST_F(TestKeyProviderClient, decrypt_rejects_bad_dek_length)
{
  svc.on_decrypt = [] (const DecryptRequest&, DecryptResponse* resp) {
    resp->set_dek(std::string(16, 'k'));
    return ::grpc::Status::OK;
  };
  std::string dek;
  EXPECT_EQ(-EINVAL, rgw::keyprovider::decrypt_dek(&dpp, "b", "id", "wrapped", dek,
      null_yield));
  EXPECT_TRUE(dek.empty());
}

TEST_F(TestKeyProviderClient, create_rejects_empty_edek)
{
  svc.on_create = [] (const CreateRequest&, CreateResponse* resp) {
    resp->set_dek(DEK32);
    // no e_dek: nothing to store as object metadata, so the DEK is unusable
    return ::grpc::Status::OK;
  };
  std::string dek, e_dek;
  EXPECT_EQ(-ERR_INTERNAL_ERROR, rgw::keyprovider::create_dek(&dpp, "b", "id", dek,
      e_dek, null_yield));
  // the DEK was valid and adopted before the e_dek check; it must not survive
  EXPECT_TRUE(dek.empty());
}

TEST_F(TestKeyProviderClient, decrypt_rejects_empty_edek_argument)
{
  std::string dek;
  EXPECT_EQ(-EINVAL, rgw::keyprovider::decrypt_dek(&dpp, "b", "id", "", dek,
      null_yield));
  EXPECT_EQ(0, svc.calls); // rejected before any RPC
}

TEST_F(TestKeyProviderClient, provider_unavailable)
{
  server->Shutdown();
  server.reset();
  std::string dek, e_dek;
  EXPECT_EQ(-ERR_SERVICE_UNAVAILABLE, rgw::keyprovider::create_dek(&dpp, "b", "id", dek,
      e_dek, null_yield));
  EXPECT_TRUE(dek.empty());
}

TEST_F(TestKeyProviderClient, call_deadline)
{
  svc.on_create = [] (const CreateRequest&, CreateResponse* resp) {
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    resp->set_dek(DEK32);
    resp->set_e_dek("wrapped");
    return ::grpc::Status::OK;
  };
  set_conf("rgw_crypt_sse_s3_keyprovider_timeout_ms", "50");
  std::string dek, e_dek;
  EXPECT_EQ(-ETIMEDOUT, rgw::keyprovider::create_dek(&dpp, "b", "id", dek, e_dek,
      null_yield));
  EXPECT_TRUE(dek.empty());
}

TEST_F(TestKeyProviderClient, uri_change_repoints_channel)
{
  auto ok_create = [] (const CreateRequest&, CreateResponse* resp) {
    resp->set_dek(DEK32);
    resp->set_e_dek("wrapped");
    return ::grpc::Status::OK;
  };
  svc.on_create = ok_create;
  std::string dek, e_dek;
  ASSERT_EQ(0, rgw::keyprovider::create_dek(&dpp, "b", "id", dek, e_dek, null_yield));

  FakeProvider svc2;
  svc2.on_create = ok_create;
  int port2 = 0;
  auto server2 = start_server(svc2, &port2);
  ASSERT_TRUE(server2);
  // apply_changes() fires the config observer, which swaps the channel
  set_conf("rgw_crypt_sse_s3_keyprovider_uri", uri_of(port2));

  ASSERT_EQ(0, rgw::keyprovider::create_dek(&dpp, "b", "id", dek, e_dek, null_yield));
  EXPECT_EQ(1, svc.calls);
  EXPECT_EQ(1, svc2.calls);
  server2->Shutdown();
}

TEST_F(TestKeyProviderClient, unset_uri_fails_init)
{
  set_conf("rgw_crypt_sse_s3_keyprovider_uri", "");
  EXPECT_EQ(-EINVAL, rgw::keyprovider::init(g_ceph_context));
}

TEST_F(TestKeyProviderClient, yield_round_trip)
{
  svc.on_create = [] (const CreateRequest&, CreateResponse* resp) {
    resp->set_dek(DEK32);
    resp->set_e_dek("wrapped");
    return ::grpc::Status::OK;
  };

  boost::asio::io_context ioc;
  int r = -1;
  std::string dek, e_dek;
  boost::asio::spawn(ioc, [&] (boost::asio::yield_context y) {
      r = rgw::keyprovider::create_dek(&dpp, "b", "id", dek, e_dek, y);
    }, [] (std::exception_ptr eptr) {
      if (eptr) std::rethrow_exception(eptr);
    });
  ioc.run();
  EXPECT_EQ(0, r);
  EXPECT_EQ(DEK32, dek);
}

TEST_F(TestKeyProviderClient, yield_deadline)
{
  svc.on_create = [] (const CreateRequest&, CreateResponse* resp) {
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    resp->set_dek(DEK32);
    resp->set_e_dek("wrapped");
    return ::grpc::Status::OK;
  };
  set_conf("rgw_crypt_sse_s3_keyprovider_timeout_ms", "50");

  boost::asio::io_context ioc;
  int r = 0;
  std::string dek, e_dek;
  boost::asio::spawn(ioc, [&] (boost::asio::yield_context y) {
      r = rgw::keyprovider::create_dek(&dpp, "b", "id", dek, e_dek, y);
    }, [] (std::exception_ptr eptr) {
      if (eptr) std::rethrow_exception(eptr);
    });
  ioc.run();
  EXPECT_EQ(-ETIMEDOUT, r);
  EXPECT_TRUE(dek.empty());
}

int main(int argc, char **argv) {
  auto args = argv_to_vec(argc, argv);
  auto cct = global_init(NULL, args, CEPH_ENTITY_TYPE_CLIENT,
			 CODE_ENVIRONMENT_UTILITY,
			 CINIT_FLAG_NO_DEFAULT_CONFIG_FILE);
  common_init_finish(g_ceph_context);

  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
