#ifndef MODES_SP800_38C_CPP
#define MODES_SP800_38C_CPP

#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <stdexcept>
#include <random>
#include <iomanip>
#include <sstream>
#include <algorithm>

#include "AES.cpp"

using namespace std;

typedef vector<uint8_t> ByteArray;

class ModesSP800_38C {
private:
    ByteArray key;
    AES aes;
    bool verbose;

public:
    static const size_t BLOCK_SIZE = 16;

    ModesSP800_38C(const ByteArray& k, bool verb = false)
        : key(k), aes(k), verbose(verb) {
        if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
            throw invalid_argument("Do dai key AES khong hop le!");
        }
    }

    ModesSP800_38C(const string& k_str, bool verb = false)
        : ModesSP800_38C(utf8_to_bytes(k_str), verb) {}

    static AES::Block to_aes_block(const ByteArray& b) {
        AES::Block block{};
        for (size_t i = 0; i < 16 && i < b.size(); ++i) {
            block[i] = b[i];
        }
        return block;
    }

    static ByteArray from_aes_block(const AES::Block& block) {
        return ByteArray(block.begin(), block.end());
    }

    static ByteArray utf8_to_bytes(const string& str) {
        return ByteArray(str.begin(), str.end());
    }

    static string bytes_to_hex(const ByteArray& data) {
        stringstream ss;
        ss << hex << setfill('0');
        for (uint8_t b : data) {
            ss << setw(2) << static_cast<int>(b);
        }
        return ss.str();
    }

    static ByteArray xor_bytes(const ByteArray& a, const ByteArray& b) {
        if (a.size() != b.size()) throw invalid_argument("XOR size mismatch");
        ByteArray res(a.size());
        for (size_t i = 0; i < a.size(); ++i) res[i] = a[i] ^ b[i];
        return res;
    }

    static ByteArray generate_random_bytes(size_t length) {
        ByteArray out(length);
        random_device rd;
        mt19937 gen(rd());
        uniform_int_distribution<int> dis(0, 255);
        for (size_t i = 0; i < length; ++i) out[i] = static_cast<uint8_t>(dis(gen));
        return out;
    }

private:
    static void validate_ccm_params(size_t nonce_len, size_t tag_len, uint64_t payload_len) {
        if (tag_len < 4 || tag_len > 16 || tag_len % 2 != 0) throw invalid_argument("Invalid CCM tag length");
        if (nonce_len < 7 || nonce_len > 13) throw invalid_argument("Invalid CCM nonce length");
    }

    static ByteArray format_b0_and_aad(const ByteArray& nonce, const ByteArray& aad, size_t payload_len, size_t tag_len) {
        size_t n = nonce.size();
        size_t q = 15 - n;
        ByteArray b0(16, 0);
        uint8_t flags = 0;
        if (!aad.empty()) flags |= (1 << 6);
        flags |= static_cast<uint8_t>(((tag_len - 2) / 2) << 3);
        flags |= static_cast<uint8_t>((q - 1) & 0x07);

        b0[0] = flags;
        for (size_t i = 0; i < n; ++i) b0[1 + i] = nonce[i];
        uint64_t Q = static_cast<uint64_t>(payload_len);
        for (size_t i = 0; i < q; ++i) {
            b0[15 - i] = static_cast<uint8_t>(Q & 0xFF);
            Q >>= 8;
        }

        ByteArray formatted = b0;
        if (!aad.empty()) {
            uint64_t a = static_cast<uint64_t>(aad.size());
            ByteArray aad_block;
            if (a < 0xFF00ULL) {
                aad_block.push_back(static_cast<uint8_t>((a >> 8) & 0xFF));
                aad_block.push_back(static_cast<uint8_t>(a & 0xFF));
            }
            aad_block.insert(aad_block.end(), aad.begin(), aad.end());
            if (aad_block.size() % BLOCK_SIZE != 0) {
                aad_block.insert(aad_block.end(), BLOCK_SIZE - (aad_block.size() % BLOCK_SIZE), 0x00);
            }
            formatted.insert(formatted.end(), aad_block.begin(), aad_block.end());
        }
        return formatted;
    }

    static ByteArray format_counter_block(const ByteArray& nonce, uint64_t counter_index) {
        size_t n = nonce.size();
        size_t q = 15 - n;
        ByteArray ctr(16, 0);
        ctr[0] = static_cast<uint8_t>((q - 1) & 0x07);
        for (size_t i = 0; i < n; ++i) ctr[1 + i] = nonce[i];
        uint64_t idx = counter_index;
        for (size_t j = 0; j < q; ++j) {
            ctr[15 - j] = static_cast<uint8_t>(idx & 0xFF);
            idx >>= 8;
        }
        return ctr;
    }

    ByteArray compute_cbc_mac(const ByteArray& nonce, const ByteArray& aad, const ByteArray& plaintext, size_t tag_len) {
        ByteArray b_stream = format_b0_and_aad(nonce, aad, plaintext.size(), tag_len);
        b_stream.insert(b_stream.end(), plaintext.begin(), plaintext.end());
        if (plaintext.size() % BLOCK_SIZE != 0) {
            b_stream.insert(b_stream.end(), BLOCK_SIZE - (plaintext.size() % BLOCK_SIZE), 0x00);
        }

        ByteArray y(BLOCK_SIZE, 0);
        for (size_t i = 0; i < b_stream.size(); i += BLOCK_SIZE) {
            ByteArray block(b_stream.begin() + i, b_stream.begin() + i + BLOCK_SIZE);
            AES::Block enc_b = aes.encrypt(to_aes_block(xor_bytes(block, y)));
            y = from_aes_block(enc_b);
        }
        return ByteArray(y.begin(), y.begin() + tag_len);
    }

    static bool constant_time_compare(const ByteArray& a, const ByteArray& b) {
        if (a.size() != b.size()) return false;
        uint8_t diff = 0;
        for (size_t i = 0; i < a.size(); ++i) diff |= (a[i] ^ b[i]);
        return diff == 0;
    }

public:
    ByteArray ccm_encrypt(const ByteArray& plaintext, const ByteArray& associated_data = {}, const ByteArray& nonce = {}, size_t tag_length = 16, bool prepend_nonce = true) {
        ByteArray nonce_bytes = nonce.empty() ? generate_random_bytes(13) : nonce;
        validate_ccm_params(nonce_bytes.size(), tag_length, plaintext.size());

        ByteArray T = compute_cbc_mac(nonce_bytes, associated_data, plaintext, tag_length);
        AES::Block s0_b = aes.encrypt(to_aes_block(format_counter_block(nonce_bytes, 0)));
        ByteArray s0 = from_aes_block(s0_b);
        ByteArray U = xor_bytes(T, ByteArray(s0.begin(), s0.begin() + tag_length));

        ByteArray ciphertext;
        uint64_t counter_idx = 1;
        for (size_t i = 0; i < plaintext.size(); i += BLOCK_SIZE) {
            size_t chunk_len = min(BLOCK_SIZE, plaintext.size() - i);
            ByteArray block(plaintext.begin() + i, plaintext.begin() + i + chunk_len);

            AES::Block si_b = aes.encrypt(to_aes_block(format_counter_block(nonce_bytes, counter_idx++)));
            ByteArray s_i = from_aes_block(si_b);
            ByteArray enc_chunk = xor_bytes(block, ByteArray(s_i.begin(), s_i.begin() + chunk_len));
            ciphertext.insert(ciphertext.end(), enc_chunk.begin(), enc_chunk.end());
        }

        ByteArray out;
        if (prepend_nonce) out.insert(out.end(), nonce_bytes.begin(), nonce_bytes.end());
        out.insert(out.end(), ciphertext.begin(), ciphertext.end());
        out.insert(out.end(), U.begin(), U.end());
        return out;
    }

    ByteArray ccm_decrypt(const ByteArray& ciphertext_and_tag, const ByteArray& associated_data = {}, const ByteArray& nonce = {}, bool has_nonce = true, size_t nonce_length = 13, size_t tag_length = 16) {
        ByteArray nonce_bytes, data;
        if (has_nonce) {
            nonce_bytes.assign(ciphertext_and_tag.begin(), ciphertext_and_tag.begin() + nonce_length);
            data.assign(ciphertext_and_tag.begin() + nonce_length, ciphertext_and_tag.end());
        } else {
            nonce_bytes = nonce;
            data = ciphertext_and_tag;
        }

        size_t payload_len = data.size() - tag_length;
        ByteArray ciphertext(data.begin(), data.begin() + payload_len);
        ByteArray U(data.begin() + payload_len, data.end());

        ByteArray plaintext;
        uint64_t counter_idx = 1;
        for (size_t i = 0; i < ciphertext.size(); i += BLOCK_SIZE) {
            size_t chunk_len = min(BLOCK_SIZE, ciphertext.size() - i);
            ByteArray block(ciphertext.begin() + i, ciphertext.begin() + i + chunk_len);

            AES::Block si_b = aes.encrypt(to_aes_block(format_counter_block(nonce_bytes, counter_idx++)));
            ByteArray s_i = from_aes_block(si_b);
            ByteArray dec_chunk = xor_bytes(block, ByteArray(s_i.begin(), s_i.begin() + chunk_len));
            plaintext.insert(plaintext.end(), dec_chunk.begin(), dec_chunk.end());
        }

        AES::Block s0_b = aes.encrypt(to_aes_block(format_counter_block(nonce_bytes, 0)));
        ByteArray s0 = from_aes_block(s0_b);
        ByteArray received_T = xor_bytes(U, ByteArray(s0.begin(), s0.begin() + tag_length));
        ByteArray expected_T = compute_cbc_mac(nonce_bytes, associated_data, plaintext, tag_length);

        if (!constant_time_compare(received_T, expected_T)) {
            throw runtime_error("Xac thuc AES-CCM that bai (InvalidTag)!");
        }
        return plaintext;
    }
};

using modes_38c = ModesSP800_38C;

#endif