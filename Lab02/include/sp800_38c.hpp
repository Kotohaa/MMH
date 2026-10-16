#pragma once

#include "common.hpp"

namespace lab {

// Returns nonce || ciphertext || authentication tag by default.
Bytes ccm_encrypt(const AES& aes, const Bytes& plaintext, const Bytes& nonce,
                  const Bytes& aad = {}, std::size_t tag_length = 16,
                  bool prepend_nonce = true);

// With has_nonce=true, input is nonce || ciphertext || authentication tag and
// nonce_length identifies the prepended nonce length. Otherwise input is
// ciphertext || authentication tag and nonce is used explicitly.
Bytes ccm_decrypt(const AES& aes, const Bytes& ciphertext_and_tag,
                  const Bytes& nonce, const Bytes& aad = {},
                  std::size_t tag_length = 16, bool has_nonce = false,
                  std::size_t nonce_length = 13);

}
