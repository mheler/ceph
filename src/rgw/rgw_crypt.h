// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab ft=cpp

/**
 * Crypto filters for Put/Post/Get operations.
 */

#pragma once

#include <string_view>

#include <rgw/rgw_op.h>
#include <rgw/rgw_rest.h>
#include <rgw/rgw_rest_s3.h>
#include "rgw_putobj.h"
#include "common/async/yield_context.h"

/**
 * \brief Interface for block encryption methods
 *
 * Encrypts and decrypts data.
 * Operations are performed in context of larger stream being divided into blocks.
 * Each block can be processed independently, but only as a whole.
 * Part block cannot be properly processed.
 * Each request must start on block-aligned offset.
 * Each request should have length that is multiply of block size.
 * Request with unaligned length is only acceptable for last part of stream.
 */
class BlockCrypt {
public:
  BlockCrypt(){};
  virtual ~BlockCrypt(){};

  /**
    * Determines size of encryption block.
    * This is usually multiply of key size.
    * It determines size of chunks that should be passed to \ref encrypt and \ref decrypt.
    */
  virtual size_t get_block_size() = 0;

  /**
   * Returns size of encrypted block (ciphertext + metadata like auth tags).
   * For most ciphers this equals get_block_size(), but for AEAD modes like GCM
   * it includes the authentication tag.
   */
  virtual size_t get_encrypted_block_size() {
    return get_block_size();
  }

  /**
   * Encrypts data.
   * Argument \ref stream_offset shows where in generalized stream chunk is located.
   * Input for encryption is \ref input buffer, with relevant data in range <in_ofs, in_ofs+size).
   * \ref input and \output may not be the same buffer.
   *
   * \params
   * input - source buffer of data
   * in_ofs - offset of chunk inside input
   * size - size of chunk, must be chunk-aligned unless last part is processed
   * output - destination buffer to encrypt to
   * stream_offset - location of <in_ofs,in_ofs+size) chunk in data stream, must be chunk-aligned
   * \return true iff successfully encrypted
   */
  virtual bool encrypt(bufferlist& input,
                       off_t in_ofs,
                       size_t size,
                       bufferlist& output,
                       off_t stream_offset,
                       optional_yield y) = 0;

  /**
   * Decrypts data.
   * Argument \ref stream_offset shows where in generalized stream chunk is located.
   * Input for decryption is \ref input buffer, with relevant data in range <in_ofs, in_ofs+size).
   * \ref input and \output may not be the same buffer.
   *
   * \params
   * input - source buffer of data
   * in_ofs - offset of chunk inside input
   * size - size of chunk, must be chunk-aligned unless last part is processed
   * output - destination buffer to encrypt to
   * stream_offset - location of <in_ofs,in_ofs+size) chunk in data stream, must be chunk-aligned
   * \return true iff successfully encrypted
   */
  virtual bool decrypt(bufferlist& input,
                       off_t in_ofs,
                       size_t size,
                       bufferlist& output,
                       off_t stream_offset,
                       optional_yield y) = 0;

  /**
   * Set the part number for multipart object decryption.
   * For GCM, this affects IV derivation to ensure unique IVs across parts.
   * Default implementation does nothing (CBC doesn't need this).
   */
  virtual void set_part_number(uint32_t part_number) {}
};

static const size_t AES_256_KEYSIZE = 256 / 8;
static const size_t AES_256_GCM_NONCE_SIZE = 96 / 8;  // 12 bytes, GCM standard

bool AES_256_ECB_encrypt(const DoutPrefixProvider* dpp,
                         CephContext* cct,
                         const uint8_t* key,
                         size_t key_size,
                         const uint8_t* data_in,
                         uint8_t* data_out,
                         size_t data_size);

/**
 * Create an AES-256-GCM BlockCrypt instance.
 *
 * For encryption: Pass nonce=nullptr to generate a random nonce.
 *                 After creation, call AES_256_GCM_get_nonce() to retrieve it for storage.
 *
 * For decryption: Pass the stored nonce from RGW_ATTR_CRYPT_NONCE.
 */
std::unique_ptr<BlockCrypt> AES_256_GCM_create(const DoutPrefixProvider* dpp,
                                                CephContext* cct,
                                                const uint8_t* key,
                                                size_t key_len,
                                                const uint8_t* nonce = nullptr,
                                                size_t nonce_len = 0,
                                                uint32_t part_number = 0);

/**
 * Retrieve the nonce from a BlockCrypt instance for storage in RGW_ATTR_CRYPT_NONCE.
 * Returns empty string if the BlockCrypt is not an AES_256_GCM instance.
 */
std::string AES_256_GCM_get_nonce(BlockCrypt* block_crypt);

class RGWGetObj_BlockDecrypt : public RGWGetObj_Filter {
  const DoutPrefixProvider *dpp;
  CephContext* cct;
  std::unique_ptr<BlockCrypt> crypt; /**< already configured stateless BlockCrypt
                                          for operations when enough data is accumulated */
  off_t enc_begin_skip; /**< amount of data to skip from beginning of received data */
  off_t ofs; /**< plaintext stream offset of data we expect to show up next through \ref handle_data */
  off_t enc_ofs; /**< encrypted stream offset, for comparing against parts_len which contains encrypted sizes */
  off_t end; /**< stream offset of last byte that is requested */
  bufferlist cache; /**< stores extra data that could not (yet) be processed by BlockCrypt */
  size_t block_size; /**< snapshot of \ref BlockCrypt.get_block_size() (plaintext block size) */
  size_t encrypted_block_size; /**< snapshot of \ref BlockCrypt.get_encrypted_block_size() (includes auth tag for GCM) */
  optional_yield y;
  std::vector<size_t> parts_len; /**< size of parts of multipart object, parsed from manifest */
  uint32_t current_part_num = 0; /**< current part number (1-based, 0 means single-part object) */

  int process(bufferlist& cipher, size_t part_ofs, size_t size);

  /**
   * Convert a logical (plaintext) offset to encrypted (storage) offset.
   * For GCM: accounts for 16-byte auth tag per chunk.
   */
  off_t logical_to_encrypted_offset(off_t logical_ofs) const {
    if (block_size == encrypted_block_size) {
      return logical_ofs; // CBC or other length-preserving cipher
    }
    // GCM: each plaintext chunk becomes larger encrypted chunk
    off_t chunk_idx = logical_ofs / block_size;
    off_t offset_in_chunk = logical_ofs % block_size;
    return chunk_idx * encrypted_block_size + offset_in_chunk;
  }

  /**
   * Convert an encrypted (storage) offset to logical (plaintext) offset.
   */
  off_t encrypted_to_logical_offset(off_t encrypted_ofs) const {
    if (block_size == encrypted_block_size) {
      return encrypted_ofs;
    }
    off_t chunk_idx = encrypted_ofs / encrypted_block_size;
    off_t offset_in_chunk = encrypted_ofs % encrypted_block_size;
    // If offset is in the tag area, clamp to end of plaintext chunk
    if (offset_in_chunk >= (off_t)block_size) {
      offset_in_chunk = block_size - 1;
    }
    return chunk_idx * block_size + offset_in_chunk;
  }

  /**
   * Convert an encrypted size to plaintext size.
   * For GCM: removes the 16-byte auth tag overhead per chunk.
   * This handles partial final chunks correctly.
   */
  size_t encrypted_to_plaintext_size(size_t encrypted_size) const {
    if (block_size == encrypted_block_size) {
      return encrypted_size;  // CBC - no conversion needed
    }
    // GCM: each encrypted_block_size bytes = block_size plaintext bytes
    size_t num_complete_chunks = encrypted_size / encrypted_block_size;
    size_t remaining = encrypted_size % encrypted_block_size;
    size_t tag_size = encrypted_block_size - block_size;  // 16 bytes for GCM

    // Partial chunk: must have at least (tag_size + 1) bytes to contain any ciphertext
    size_t last_chunk_plain = 0;
    if (remaining > 0) {
      if (remaining <= tag_size) {
        // Malformed: partial chunk has no ciphertext, only tag bytes
        ldpp_dout(dpp, 1) << "WARNING: encrypted_to_plaintext_size: "
            << "partial chunk size " << remaining
            << " is <= tag_size " << tag_size
            << " - data may be corrupted" << dendl;
      } else {
        last_chunk_plain = remaining - tag_size;
      }
    }
    return num_complete_chunks * block_size + last_chunk_plain;
  }

public:
  RGWGetObj_BlockDecrypt(const DoutPrefixProvider *dpp,
                         CephContext* cct,
                         RGWGetObj_Filter* next,
                         std::unique_ptr<BlockCrypt> crypt,
                         std::vector<size_t> parts_len,
                         optional_yield y);
  virtual ~RGWGetObj_BlockDecrypt();

  virtual int fixup_range(off_t& bl_ofs,
                          off_t& bl_end) override;
  virtual int handle_data(bufferlist& bl,
                          off_t bl_ofs,
                          off_t bl_len) override;
  virtual int flush() override;

  static int read_manifest_parts(const DoutPrefixProvider *dpp,
                                 const bufferlist& manifest_bl,
                                 std::vector<size_t>& parts_len);

  /**
   * Returns true if this cipher expands the data size (e.g., GCM adds auth tags).
   * Used to determine if obj_size needs adjustment for Content-Length.
   */
  bool has_size_expansion() const {
    return block_size != encrypted_block_size;
  }

  /**
   * Calculate the plaintext size from encrypted size.
   * For GCM: removes the 16-byte auth tag overhead per chunk.
   * Public wrapper for use by callers that need to adjust Content-Length.
   */
  uint64_t get_plaintext_size(uint64_t encrypted_size) const {
    return encrypted_to_plaintext_size(encrypted_size);
  }
}; /* RGWGetObj_BlockDecrypt */


class RGWPutObj_BlockEncrypt : public rgw::putobj::Pipe
{
  const DoutPrefixProvider *dpp;
  CephContext* cct;
  std::unique_ptr<BlockCrypt> crypt; /**< already configured stateless BlockCrypt
                                          for operations when enough data is accumulated */
  bufferlist cache; /**< stores extra data that could not (yet) be processed by BlockCrypt */
  const size_t block_size; /**< snapshot of \ref BlockCrypt.get_block_size() (plaintext block size) */
  uint64_t encrypted_offset = 0; /**< tracks write position in encrypted stream (differs from plaintext for GCM) */
  optional_yield y;
public:
  RGWPutObj_BlockEncrypt(const DoutPrefixProvider *dpp,
                         CephContext* cct,
                         rgw::sal::DataProcessor *next,
                         std::unique_ptr<BlockCrypt> crypt,
                         optional_yield y);

  int process(bufferlist&& data, uint64_t logical_offset) override;
}; /* RGWPutObj_BlockEncrypt */


int rgw_s3_prepare_encrypt(req_state* s, optional_yield y,
                           std::map<std::string, ceph::bufferlist>& attrs,
                           std::unique_ptr<BlockCrypt>* block_crypt,
                           std::map<std::string,
                                    std::string>& crypt_http_responses,
                           uint32_t part_number = 0);

int rgw_s3_prepare_decrypt(req_state* s, optional_yield y,
                           std::map<std::string, ceph::bufferlist>& attrs,
                           std::unique_ptr<BlockCrypt>* block_crypt,
                           std::map<std::string, std::string>* crypt_http_responses,
                           bool copy_source,
                           uint32_t part_number = 0);

static inline void set_attr(std::map<std::string, bufferlist>& attrs,
                            const char* key,
                            std::string_view value)
{
  bufferlist bl;
  bl.append(value.data(), value.size());
  attrs[key] = std::move(bl);
}

static inline std::string get_str_attribute(const std::map<std::string, bufferlist>& attrs,
                                            const char *name)
{
  auto iter = attrs.find(name);
  if (iter == attrs.end()) {
    return {};
  }
  return iter->second.to_str();
}

int rgw_remove_sse_s3_bucket_key(req_state *s, optional_yield y);
