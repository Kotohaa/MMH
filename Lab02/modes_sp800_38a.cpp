#ifndef MODES_SP800_38A_CPP
#define MODES_SP800_38A_CPP

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

class ModesSP800_38A {
private:
    ByteArray key;
    AES aes;
    bool verbose;
    ByteArray last_iv;

public:
    static const size_t BLOCK_SIZE = 16;

    ModesSP800_38A(const ByteArray& k, bool verb = false) 
        : key(k), aes(k), verbose(verb) {
        if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
            throw invalid_argument("Do dai key AES khong hop le! Chi ho tro 16, 24 hoac 32 bytes.");
        }
    }

    ModesSP800_38A(const string& k_str, bool verb = false)
        : ModesSP800_38A(utf8_to_bytes(k_str), verb) {}

    ByteArray get_last_iv() const {
        return last_iv;
    }

    // --- CÁC HÀM CHUYỂN ĐỔI KIỂU GIỮA VECTOR VÀ ARRAY CỦA AES ---
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
        if (str.size() >= 2 && str[0] == '0' && str[1] == 'b') {
            return binary_to_bytes(str.substr(2));
        }
        return ByteArray(str.begin(), str.end());
    }

    static string bytes_to_utf8(const ByteArray& data) {
        return string(data.begin(), data.end());
    }

    static string bytes_to_hex(const ByteArray& data) {
        stringstream ss;
        ss << hex << setfill('0');
        for (uint8_t b : data) {
            ss << setw(2) << static_cast<int>(b);
        }
        return ss.str();
    }

    static ByteArray binary_to_bytes(string binary_str) {
        if (binary_str.size() >= 2 && binary_str[0] == '0' && binary_str[1] == 'b') {
            binary_str = binary_str.substr(2);
        }
        size_t pad_len = 8 - (binary_str.size() % 8);
        if (pad_len == 0) pad_len = 8;
        string padded = binary_str + "1" + string(pad_len - 1, '0');

        ByteArray result;
        for (size_t i = 0; i < padded.size(); i += 8) {
            uint8_t byte_val = 0;
            for (size_t j = 0; j < 8; ++j) {
                byte_val = (byte_val << 1) | (padded[i + j] - '0');
            }
            result.push_back(byte_val);
        }
        return result;
    }

    static ByteArray xor_bytes(const ByteArray& a, const ByteArray& b) {
        if (a.size() != b.size()) {
            throw invalid_argument("Hai mang byte dem XOR phai co cung do dai!");
        }
        ByteArray res(a.size());
        for (size_t i = 0; i < a.size(); ++i) {
            res[i] = a[i] ^ b[i];
        }
        return res;
    }

    static void require_block_multiple(const ByteArray& data, const string& name) {
        if (data.empty() || data.size() % BLOCK_SIZE != 0) {
            throw invalid_argument(name + " phai co do dai khac 0 va la boi so cua 16 bytes.");
        }
    }

    static ByteArray require_exact_block(const ByteArray& data, const string& name) {
        if (data.size() != BLOCK_SIZE) {
            throw invalid_argument(name + " phai co do dai chinh xac la 16 bytes.");
        }
        return data;
    }

    static ByteArray generate_random_bytes(size_t length) {
        ByteArray out(length);
        random_device rd;
        mt19937 gen(rd());
        uniform_int_distribution<int> dis(0, 255);
        for (size_t i = 0; i < length; ++i) {
            out[i] = static_cast<uint8_t>(dis(gen));
        }
        return out;
    }

    ByteArray fresh_iv(const ByteArray& iv = {}, const string& name = "iv") {
        ByteArray val = iv.empty() ? generate_random_bytes(BLOCK_SIZE) : iv;
        require_exact_block(val, name);
        last_iv = val;
        return val;
    }

    static ByteArray pkcs7_padding(const ByteArray& data) {
        size_t padding_len = BLOCK_SIZE - (data.size() % BLOCK_SIZE);
        ByteArray padded = data;
        padded.insert(padded.end(), padding_len, static_cast<uint8_t>(padding_len));
        return padded;
    }

    static ByteArray pkcs7_unpadding(const ByteArray& data) {
        if (data.empty() || data.size() % BLOCK_SIZE != 0) {
            throw invalid_argument("Du lieu PKCS#7 phai khac rong va chia het cho 16 bytes.");
        }
        uint8_t padding_len = data.back();
        if (padding_len < 1 || padding_len > BLOCK_SIZE) {
            throw invalid_argument("Do dai PKCS#7 padding khong hop le!");
        }
        for (size_t i = data.size() - padding_len; i < data.size(); ++i) {
            if (data[i] != padding_len) {
                throw invalid_argument("Gia tri byte trong PKCS#7 padding bi sai!");
            }
        }
        return ByteArray(data.begin(), data.end() - padding_len);
    }

    // --- ECB ---
    ByteArray ecb_encrypt(const ByteArray& plaintext, bool pad = true) {
        ByteArray data = plaintext;
        if (pad) data = pkcs7_padding(data);
        else require_block_multiple(data, "plaintext");

        ByteArray out;
        out.reserve(data.size());
        for (size_t i = 0; i < data.size(); i += BLOCK_SIZE) {
            ByteArray block(data.begin() + i, data.begin() + i + BLOCK_SIZE);
            AES::Block enc_b = aes.encrypt(to_aes_block(block));
            ByteArray enc_block = from_aes_block(enc_b);
            out.insert(out.end(), enc_block.begin(), enc_block.end());
        }
        return out;
    }

    ByteArray ecb_decrypt(const ByteArray& ciphertext, bool unpad = true) {
        require_block_multiple(ciphertext, "ciphertext");
        ByteArray plaintext;
        plaintext.reserve(ciphertext.size());
        for (size_t i = 0; i < ciphertext.size(); i += BLOCK_SIZE) {
            ByteArray block(ciphertext.begin() + i, ciphertext.begin() + i + BLOCK_SIZE);
            AES::Block dec_b = aes.decrypt(to_aes_block(block));
            ByteArray dec_block = from_aes_block(dec_b);
            plaintext.insert(plaintext.end(), dec_block.begin(), dec_block.end());
        }
        if (unpad) plaintext = pkcs7_unpadding(plaintext);
        return plaintext;
    }

    // --- CBC ---
    ByteArray cbc_encrypt(const ByteArray& plaintext, const ByteArray& iv = {}, bool prepend_iv = true, bool pad = true) {
        ByteArray iv_bytes = fresh_iv(iv);
        ByteArray data = plaintext;
        if (pad) data = pkcs7_padding(data);
        else require_block_multiple(data, "plaintext");

        ByteArray out;
        if (prepend_iv) out.insert(out.end(), iv_bytes.begin(), iv_bytes.end());

        ByteArray previous = iv_bytes;
        for (size_t i = 0; i < data.size(); i += BLOCK_SIZE) {
            ByteArray block(data.begin() + i, data.begin() + i + BLOCK_SIZE);
            AES::Block enc_b = aes.encrypt(to_aes_block(xor_bytes(block, previous)));
            ByteArray encrypted = from_aes_block(enc_b);
            out.insert(out.end(), encrypted.begin(), encrypted.end());
            previous = encrypted;
        }
        return out;
    }

    ByteArray cbc_decrypt(const ByteArray& ciphertext, const ByteArray& iv = {}, bool has_iv = true, bool unpad = true) {
        ByteArray iv_bytes, data;
        if (has_iv) {
            if (ciphertext.size() < 2 * BLOCK_SIZE || ciphertext.size() % BLOCK_SIZE != 0) {
                throw invalid_argument("Ciphertext CBC khong hop le.");
            }
            iv_bytes.assign(ciphertext.begin(), ciphertext.begin() + BLOCK_SIZE);
            data.assign(ciphertext.begin() + BLOCK_SIZE, ciphertext.end());
        } else {
            iv_bytes = require_exact_block(iv, "iv");
            data = ciphertext;
        }

        ByteArray plaintext, previous = iv_bytes;
        for (size_t i = 0; i < data.size(); i += BLOCK_SIZE) {
            ByteArray block(data.begin() + i, data.begin() + i + BLOCK_SIZE);
            AES::Block dec_b = aes.decrypt(to_aes_block(block));
            ByteArray decrypted = xor_bytes(from_aes_block(dec_b), previous);
            plaintext.insert(plaintext.end(), decrypted.begin(), decrypted.end());
            previous = block;
        }
        if (unpad) plaintext = pkcs7_unpadding(plaintext);
        return plaintext;
    }

    // --- CFB ---
    ByteArray cfb_encrypt(const ByteArray& plaintext, const ByteArray& iv = {}, int segment_size = 128, bool prepend_iv = true) {
        size_t segment_bytes = segment_size / 8;
        ByteArray iv_bytes = fresh_iv(iv);
        ByteArray out;
        if (prepend_iv) out.insert(out.end(), iv_bytes.begin(), iv_bytes.end());

        ByteArray reg = iv_bytes;
        for (size_t i = 0; i < plaintext.size(); i += segment_bytes) {
            size_t chunk_len = min(segment_bytes, plaintext.size() - i);
            ByteArray segment(plaintext.begin() + i, plaintext.begin() + i + chunk_len);

            AES::Block stream_b = aes.encrypt(to_aes_block(reg));
            ByteArray stream = from_aes_block(stream_b);
            ByteArray encrypted = xor_bytes(segment, ByteArray(stream.begin(), stream.begin() + chunk_len));
            out.insert(out.end(), encrypted.begin(), encrypted.end());

            if (chunk_len == segment_bytes) {
                ByteArray new_reg(reg.begin() + segment_bytes, reg.end());
                new_reg.insert(new_reg.end(), encrypted.begin(), encrypted.end());
                reg = new_reg;
            }
        }
        return out;
    }

    ByteArray cfb_decrypt(const ByteArray& ciphertext, const ByteArray& iv = {}, bool has_iv = true, int segment_size = 128) {
        size_t segment_bytes = segment_size / 8;
        ByteArray iv_bytes, data;
        if (has_iv) {
            iv_bytes.assign(ciphertext.begin(), ciphertext.begin() + BLOCK_SIZE);
            data.assign(ciphertext.begin() + BLOCK_SIZE, ciphertext.end());
        } else {
            iv_bytes = require_exact_block(iv, "iv");
            data = ciphertext;
        }

        ByteArray out, reg = iv_bytes;
        for (size_t i = 0; i < data.size(); i += segment_bytes) {
            size_t chunk_len = min(segment_bytes, data.size() - i);
            ByteArray segment(data.begin() + i, data.begin() + i + chunk_len);

            AES::Block stream_b = aes.encrypt(to_aes_block(reg));
            ByteArray stream = from_aes_block(stream_b);
            ByteArray decrypted = xor_bytes(segment, ByteArray(stream.begin(), stream.begin() + chunk_len));
            out.insert(out.end(), decrypted.begin(), decrypted.end());

            if (chunk_len == segment_bytes) {
                ByteArray new_reg(reg.begin() + segment_bytes, reg.end());
                new_reg.insert(new_reg.end(), segment.begin(), segment.end());
                reg = new_reg;
            }
        }
        return out;
    }

    // --- OFB ---
    ByteArray ofb_encrypt(const ByteArray& plaintext, const ByteArray& iv = {}, bool prepend_iv = true) {
        ByteArray iv_bytes = fresh_iv(iv);
        ByteArray out;
        if (prepend_iv) out.insert(out.end(), iv_bytes.begin(), iv_bytes.end());

        ByteArray feedback = iv_bytes;
        for (size_t i = 0; i < plaintext.size(); i += BLOCK_SIZE) {
            size_t chunk_len = min(BLOCK_SIZE, plaintext.size() - i);
            ByteArray block(plaintext.begin() + i, plaintext.begin() + i + chunk_len);

            AES::Block fb_b = aes.encrypt(to_aes_block(feedback));
            feedback = from_aes_block(fb_b);
            ByteArray encrypted = xor_bytes(block, ByteArray(feedback.begin(), feedback.begin() + chunk_len));
            out.insert(out.end(), encrypted.begin(), encrypted.end());
        }
        return out;
    }

    ByteArray ofb_decrypt(const ByteArray& ciphertext, const ByteArray& iv = {}, bool has_iv = true) {
        return ofb_encrypt(ciphertext, iv, has_iv); // OFB decrypt trùng logic với encrypt
    }

    // --- CTR ---
private:
    static void increment_counter_128(ByteArray& counter) {
        for (int i = static_cast<int>(BLOCK_SIZE) - 1; i >= 0; --i) {
            if (++counter[i] != 0) break;
        }
    }

public:
    ByteArray ctr_encrypt(const ByteArray& plaintext, const ByteArray& iv = {}, bool prepend_iv = true) {
        ByteArray iv_bytes = fresh_iv(iv);
        ByteArray counter = iv_bytes;
        ByteArray out;
        if (prepend_iv) out.insert(out.end(), iv_bytes.begin(), iv_bytes.end());

        for (size_t i = 0; i < plaintext.size(); i += BLOCK_SIZE) {
            size_t chunk_len = min(BLOCK_SIZE, plaintext.size() - i);
            ByteArray block(plaintext.begin() + i, plaintext.begin() + i + chunk_len);

            AES::Block ks_b = aes.encrypt(to_aes_block(counter));
            ByteArray key_stream = from_aes_block(ks_b);
            ByteArray encrypted = xor_bytes(block, ByteArray(key_stream.begin(), key_stream.begin() + chunk_len));
            out.insert(out.end(), encrypted.begin(), encrypted.end());
            increment_counter_128(counter);
        }
        return out;
    }

    ByteArray ctr_decrypt(const ByteArray& ciphertext, const ByteArray& iv = {}, bool has_iv = true) {
        ByteArray iv_bytes, data;
        if (has_iv) {
            iv_bytes.assign(ciphertext.begin(), ciphertext.begin() + BLOCK_SIZE);
            data.assign(ciphertext.begin() + BLOCK_SIZE, ciphertext.end());
        } else {
            iv_bytes = require_exact_block(iv, "iv");
            data = ciphertext;
        }
        return ctr_encrypt(data, iv_bytes, false);
    }
};

using modes_38a = ModesSP800_38A;

#endif
