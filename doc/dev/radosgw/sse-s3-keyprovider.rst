===================================
 SSE-S3 Key Provider backend (RGW)
===================================

This document describes the internals of RGW's SSE-S3 ``keyprovider``
backend for Ceph developers: the service topology, the version layers that
let the format evolve, the write and read flows, the per-object metadata,
the decrypt dispatch logic, the failure modes and observability, and the
evolution contract that keeps old objects readable.

For the operator-facing overview (configuration options, behaviour notes)
see :doc:`/radosgw/encryption` under "SSE-S3 with the Key Provider service".

.. contents::
   :depth: 2

------------------
Problem and design
------------------

SSE-S3 makes server-side encryption invisible to the S3 client: the gateway
transparently encrypts on write and decrypts on read, managing keys itself.
RGW has historically implemented SSE-S3 with a Vault backend that keeps a
per-bucket key in Vault. The ``keyprovider`` backend is an alternative
SSE-S3 key source selected with ``rgw_crypt_sse_s3_backend = keyprovider``.

The design goal is to keep essentially all key management *out* of RGW. RGW
never sees a master secret, never sees a key-encryption key (KEK), never
derives or wraps anything, and persists no key material other than one
opaque blob per object. It asks a co-located service for a fresh data
encryption key (DEK) on write, and asks the same service to unwrap the
stored blob back into a DEK on read.

Topology
========

Three processes are involved::

   S3 client
       |  (HTTP, object bytes)
       v
   +-------+   gRPC (plaintext,     +--------------+  gRPC/mTLS   +-------------+
   |  RGW  |-- localhost, per-op) ->| Key Provider |------------->| Key Manager |
   +-------+   Create / Decrypt     +--------------+  Get/GetLatest +-------------+
       |                                   |                            |
   encrypts object                  wraps/unwraps DEK             derives per-bucket
   with the DEK                     with a per-bucket KEK         KEK from rotating
   (AES-256)                        (E-DEK format)                master secrets

* **RGW** performs the actual bulk encryption of object data with the DEK
  (AES-256-CBC, or AES-256-GCM when ``rgw_crypt_sse_algorithm`` selects it --
  the existing SSE-S3 cipher path). It talks only to the Key Provider.
* **Key Provider** (``keyprovider.v1.KeyProviderService``) generates DEKs,
  wraps them into an *encrypted DEK* (E-DEK) under a per-bucket KEK, and
  unwraps E-DEKs. It is expected to run local to the gateway; the channel is
  plaintext by design.
* **Key Manager** (``keymanager.v1.KeyManagerService``) derives the
  per-bucket KEK from rotating master secrets. **RGW never talks to the Key
  Manager**; it sits entirely behind the Key Provider, and RGW cannot parse
  anything the Key Provider produces.

The per-bucket KEK is derived using the Ceph *bucket ID* (the bucket marker)
as the derivation salt. This matters for copied objects: see
`Copied objects`_.

-----------------------
The four version layers
-----------------------

Four independent version/identity layers let the format evolve without
breaking already-written objects. Keeping them separate is deliberate — the
two that RGW owns are the only ones RGW is allowed to interpret.

1. **RPC / proto package version** — the gRPC contract, ``keyprovider.v1``
   (``src/rgw/protos/keyprovider/v1/keyprovider.proto``). A backwards
   incompatible change to the service surface would be a new package
   (``keyprovider.v2``), a new generated stub, and a new backend wiring in
   RGW. This is the RPC boundary RGW compiles against.

2. **E-DEK wire format** — the layout of the wrapped-DEK blob the Key
   Provider returns (for example ``ak:<ver>:<index>:<base64(nonce||
   ciphertext)>``; it carries its own ``<ver>`` field). This format is
   **keyprovider-internal and completely opaque to RGW**. RGW stores it
   verbatim and hands it back verbatim on decrypt. RGW must never parse,
   validate the shape of, or depend on the contents of the E-DEK. New E-DEK
   versions require no RGW change.

3. **Per-object cipher** — ``RGW_ATTR_CRYPT_MODE`` (``user.rgw.crypt.mode``),
   either ``AES256`` (AES-256-CBC) or ``AES256-GCM`` (AES-256-GCM), according
   to ``rgw_crypt_sse_algorithm`` at write time. This is *RGW-owned* and
   selects the bulk data cipher. Both values are shared with the Vault SSE-S3
   backend; which backend serves a given gateway is purely a matter of the
   ``rgw_crypt_sse_s3_backend`` configuration, as for the other SSE-S3
   backends.

4. **Routing attributes** — ``RGW_ATTR_CRYPT_KEYID``
   (``user.rgw.crypt.keyid``, the ID of the bucket the object was encrypted
   in) and ``RGW_ATTR_CRYPT_DATAKEY`` (``user.rgw.crypt.datakey``, the stored
   E-DEK). The attribute schema is *RGW-owned*: RGW writes and reads these to
   route a decrypt to the right backend and bucket identity, while the E-DEK
   *value* inside stays layer 2 — opaque.

The split between layer 2 (Key-Provider-owned, opaque) and layers 3-4
(RGW-owned, interpreted) is the core of the evolution contract described in
`Versioning and evolution contract`_.

--------------
The write flow
--------------

On an encrypted object write (``rgw_s3_prepare_encrypt()`` in
``src/rgw/rgw_crypt.cc``), when ``rgw_crypt_sse_s3_backend`` is
``keyprovider``:

1. RGW stamps ``RGW_ATTR_CRYPT_KEYID`` = the bucket marker (the bucket ID
   used as the KEK derivation salt) before fetching the key, set by
   ``rgw_s3_prepare_encrypt()``.

   ``RGW_ATTR_CRYPT_MODE`` is *not* stamped here. It is written further down
   ``rgw_s3_prepare_encrypt()``, after the DEK has been fetched and its
   length validated, because the cipher choice is independent of the key
   source.

2. ``make_actual_key_from_sse_s3()`` dispatches on the configured backend to
   ``make_actual_key_from_keyprovider()`` (``src/rgw/rgw_kms.cc``), which
   reads the bucket ID back out of ``RGW_ATTR_CRYPT_KEYID`` and calls
   ``rgw::keyprovider::create_dek()`` with it and the bucket name (audit
   only). The Key Provider returns a fresh 32-byte DEK and the opaque E-DEK.

3. RGW stores the E-DEK verbatim in ``RGW_ATTR_CRYPT_DATAKEY``
   (``user.rgw.crypt.datakey``) and uses the DEK as the AES-256 key for the
   object body. The DEK is scrubbed once the cipher is keyed, the same way
   the Vault SSE-S3 path scrubs it (see `Key hygiene`_).

Unlike the Vault backend there is no per-bucket key setup, key selector, or
crypto context on this path — the DEK is per object and fetched fresh.

--------------
The read flow
--------------

On decrypt (``rgw_s3_prepare_decrypt()`` in ``src/rgw/rgw_crypt.cc``), for an
object whose ``RGW_ATTR_CRYPT_MODE`` is ``AES256`` or ``AES256-GCM``:

1. RGW dispatches on the configured backend (see `Decrypt dispatch`_): under
   ``rgw_crypt_sse_s3_backend = keyprovider`` the read routes to
   ``reconstitute_actual_key_from_keyprovider()``.

2. That function reads the E-DEK from ``RGW_ATTR_CRYPT_DATAKEY`` and the
   bucket ID from ``RGW_ATTR_CRYPT_KEYID`` — **both from the object's own
   metadata, never from the request** — and calls
   ``rgw::keyprovider::decrypt_dek()``.

3. The Key Provider unwraps the E-DEK back into the 32-byte DEK, which RGW
   uses to key the bulk cipher and stream the decrypted body, then scrubs
   (see `Key hygiene`_).

There is deliberately no DEK cache in RGW: every encrypted read costs one
Decrypt RPC, and every multipart part upload costs one Decrypt (the part
re-reads the upload's crypt attributes). Caching, if ever needed, belongs in
the Key Provider, which is local and fast.

----------------------------
Per-object attributes stored
----------------------------

A ``keyprovider``-encrypted object carries these ``user.rgw.crypt.*`` xattrs:

.. list-table::
   :header-rows: 1
   :widths: 30 20 50

   * - Attribute
     - Value
     - Meaning
   * - ``RGW_ATTR_CRYPT_MODE``
     - ``AES256`` or ``AES256-GCM``
     - SSE-S3 bulk cipher selector (AES-256-CBC or AES-256-GCM), chosen by
       ``rgw_crypt_sse_algorithm`` at write time. Shared with Vault.
   * - ``RGW_ATTR_CRYPT_KEYID``
     - bucket marker
     - The bucket ID the object was *encrypted in*, i.e. the KEK derivation
       salt. Travels with the object.
   * - ``RGW_ATTR_CRYPT_DATAKEY``
     - E-DEK
     - The wrapped DEK, stored verbatim and opaque to RGW. Sent back on
       Decrypt.

For multipart objects the usual SSE-S3 ``RGW_ATTR_CRYPT_PARTS`` part-length
attribute applies as for any SSE-S3 object; it is not specific to this
backend.

----------------
Decrypt dispatch
----------------

``reconstitute_actual_key_from_sse_s3()`` (``src/rgw/rgw_kms.cc``) routes on
the **configured backend**::

   if backend == "vault":
       reconstitute_actual_key_from_vault(...)
   if backend == "keyprovider":
       reconstitute_actual_key_from_keyprovider(...)
   else:
       -EINVAL   # enum-validated; unreachable in practice

The Key Provider client itself is process-wide and created lazily on first
use, so every code path — request handling, lifecycle transition, reencrypt —
reaches the same client without threading a handle through ``req_state``.

Consequences:

* Decryption never falls through to another backend: a wrapped key is only
  ever handed to the backend the configuration names, and if that backend
  cannot unwrap it the read fails with that backend's error.
* The operator-facing consequences — switching ``rgw_crypt_sse_s3_backend``
  on a cluster that already holds SSE-S3 objects is unsupported, and a
  multisite peer zone can serve these objects only with the same backend and
  master secrets — are covered in :doc:`/radosgw/encryption`.

Copied objects
==============

The KEK is derived per *bucket*, salted with the bucket ID, so decryption
must use the identity of the bucket the object was *encrypted in*. Because
``reconstitute_actual_key_from_keyprovider()`` reads the bucket ID from
``RGW_ATTR_CRYPT_KEYID`` on the object rather than from the request's bucket,
an object whose crypt attributes were carried over from another bucket still
decrypts correctly.

Which paths actually depend on this:

* **Multisite replication** copies the ``user.rgw.crypt.*`` attributes
  verbatim, so the source bucket's ID travels with the object. This is the
  case the object-sourced bucket ID exists for.
* **Same-zone ``CopyObject``** does not depend on it.
  ``RGWCopyObjDPF::get_encrypt_crypt()`` (``src/rgw/rgw_op.cc``) erases the
  whole ``user.rgw.crypt.`` range from the destination and re-encrypts, so
  the copy gets a fresh DEK wrapped under the *destination* bucket's KEK.

------------------------------------------
Failure modes and perf counters
------------------------------------------

Failure modes
=============

Every RPC has a per-call deadline (``rgw_crypt_sse_s3_keyprovider_timeout_ms``,
default 5000 ms): a hung Key Provider fails the S3 operation rather than
hanging it. gRPC statuses are mapped to RGW errors in
``KeyProviderClientImpl::transform_status()``:

.. list-table::
   :header-rows: 1
   :widths: 30 35 35

   * - gRPC status
     - RGW result code
     - Meaning
   * - ``OK``
     - 0
     - success
   * - ``DEADLINE_EXCEEDED``
     - ``-ETIMEDOUT``
     - service too slow
   * - ``UNAVAILABLE``
     - ``-ERR_SERVICE_UNAVAILABLE``
     - service down (surfaces as HTTP 503)
   * - ``INVALID_ARGUMENT``
     - ``-EINVAL``
     - bad / corrupt E-DEK, etc.
   * - anything else
     - ``-ERR_INTERNAL_ERROR``
     - unexpected

If the Key Provider is down, writes to buckets with default encryption and
reads of ``keyprovider`` objects fail with HTTP 503 (``UNAVAILABLE`` ->
``-ERR_SERVICE_UNAVAILABLE``). If it is merely slow enough to blow the
deadline, the failure is HTTP 408 ``RequestTimeout`` (``DEADLINE_EXCEEDED``
-> ``-ETIMEDOUT``), which S3 clients treat differently for retry purposes.
Unencrypted buckets are unaffected.

.. note::

   Both RPCs use the gRPC callback API and are driven through
   ``KeyProviderClientImpl::await_rpc()``. When the enclosing request carries a
   coroutine (``optional_yield``), the frontend thread is released for the
   duration of the round trip via ``ceph::async::yield_waiter``, matching how
   the Vault path behaves. Only when there is no yield context — no coroutine
   to suspend — does the calling thread wait, and that case is reported through
   ``maybe_warn_about_blocking()`` so it shows up under
   ``rgw_asio_assert_yielding``. This matters because the frontend pool is
   ``rgw_thread_pool_size`` threads (default 128): a blocking key fetch would
   throttle overall request concurrency, not just encrypted operations.

Perf counters
=============

Registered in ``src/rgw/rgw_perf_counters.cc`` (``rgw`` section, visible via
``ceph daemon <rgw.asok> perf dump``):

* ``keyprovider_create_ok`` / ``keyprovider_create_fail`` /
  ``keyprovider_create_lat``
* ``keyprovider_decrypt_ok`` / ``keyprovider_decrypt_fail`` /
  ``keyprovider_decrypt_lat``
* ``keyprovider_unavailable`` — incremented specifically when a failure
  indicates the service is down; the key SLO alarm signal.

Accounting is done once per RPC in ``KeyProviderClientImpl::account_rpc()``.

Key hygiene
===========

Plaintext DEKs never appear in logs or results.

Key material follows the convention the rest of RGW's crypt code already
uses: it travels in a plain ``std::string&`` out-parameter and is scrubbed
with ``::ceph::crypto::zeroize_for_security()`` on every exit path. There is
no bespoke holder type. ``create_dek()`` / ``decrypt_dek()`` write straight
into the ``actual_key`` that ``rgw_kms.h`` declares, exactly as the Vault
engines do, and ``rgw_crypt.cc`` scrubs it after keying the cipher on the
same lines that already handle the Vault and SSE-KMS keys.

The client adds two guarantees on top so callers do not have to unwind key
state themselves:

* ``dek_out`` is zeroized and cleared on **every** failure -- transport
  error, wrong DEK length, or a rejected response -- so an error return never
  leaves a partial or stale key in the caller's buffer.
* The gRPC response's own ``dek`` field is zeroized unconditionally before
  the response leaves scope, whatever the outcome.

Log lines carry the bucket name/ID, the E-DEK length, and the gRPC status
only.

-----------------------------------
Versioning and evolution contract
-----------------------------------

The layering exists so the scheme can evolve while every previously written
object stays readable. The contract:

* **The E-DEK stays opaque.** RGW stores and returns it verbatim. A new
  E-DEK wire format (layer 2) is entirely a Key Provider concern and needs
  **no** RGW change. Never add code to RGW that parses the E-DEK.

* **A new key backend gets a new backend value.** If a future backend is
  added, it introduces a new ``rgw_crypt_sse_s3_backend`` enum value and a
  new dispatch branch in ``rgw_kms.cc``, exactly as ``keyprovider`` was
  added alongside ``vault``. Existing backends keep their branches, so a
  gateway configured for them keeps decrypting its objects.

* **A new RPC contract is a new proto package.** A breaking change to the
  service surface (layer 1) becomes ``keyprovider.v2`` with its own generated
  stub, wired as a new code path; the ``v1`` client stays for objects already
  in the field until they are all re-encrypted or the service drops it.

* **An unserviceable backend fails closed.** A wrapped key is only ever
  handed to the backend the configuration names; if that backend is
  unavailable the read fails rather than guessing another key source.

The one hard rule that ties this together: RGW may interpret only the layers
it owns (the cipher mode and routing attributes). Everything the Key
Provider produces is opaque.

----------------
Pointers to code
----------------

* ``src/rgw/rgw_keyprovider.h`` — public interface: the free
  ``rgw::keyprovider::{init, create_dek, decrypt_dek, cleanup}`` functions.
  Deliberately free of gRPC headers.
* ``src/rgw/rgw_keyprovider_impl.cc`` — ``KeyProviderClientImpl``: the
  gRPC channel management, config observer, the Create/Decrypt RPCs with
  per-call deadline, ``transform_status()`` error mapping and perf
  accounting, plus config validation and the process-wide client storage.
  This is the only place the gRPC headers are pulled in.
* ``src/rgw/rgw_kms.{h,cc}`` — the seam between RGW's SSE-S3 code and the
  client: ``make_actual_key_from_keyprovider()`` (write) and
  ``reconstitute_actual_key_from_keyprovider()`` (read).
* ``src/rgw/rgw_crypt.cc`` — ``rgw_s3_prepare_encrypt()`` /
  ``rgw_s3_prepare_decrypt()``: attribute stamping; the backend dispatch
  itself lives in ``rgw_kms.cc``.
* ``src/rgw/rgw_common.h`` — the ``RGW_ATTR_CRYPT_*`` attribute definitions.
* ``src/rgw/protos/keyprovider/v1/keyprovider.proto`` — the RPC contract.
