#include "sp800_38c.hpp"
#include <algorithm>
#include <limits>

/*
 * Chế độ mã hóa có xác thực CCM theo tiêu chuẩn NIST SP 800-38C.
 *
 * CCM kết hợp cơ chế xác thực CBC-MAC với cơ chế bảo mật dữ liệu bằng chế độ CTR.
 * Phần triển khai sử dụng thuật toán AES cục bộ và hỗ trợ dữ liệu liên kết,
 * nonce có độ dài thay đổi và các độ dài thẻ xác thực tiêu chuẩn của CCM.
 */

namespace lab {
namespace {

// Kiểm tra các ràng buộc về độ dài nonce, thẻ xác thực và bản rõ.
void check_parameters(const Bytes& plaintext, const Bytes& nonce,
                      std::size_t tag_length) {
    if (nonce.size() < 7 || nonce.size() > 13) {
        throw std::invalid_argument("CCM nonce must be 7 to 13 bytes");
    }
    if (tag_length != 4 && tag_length != 6 && tag_length != 8 &&
        tag_length != 10 && tag_length != 12 && tag_length != 14 &&
        tag_length != 16) {
        throw std::invalid_argument(
            "AES-CCM tag_length must be one of 4, 6, 8, 10, 12, 14, 16.");
    }
    const std::size_t q = 15 - nonce.size();
    const std::uint64_t maximum =
        q == 8 ? std::numeric_limits<std::uint64_t>::max()
               : (std::uint64_t{1} << (8 * q)) - 1;
    if (plaintext.size() > maximum) {
        throw std::invalid_argument("CCM plaintext is too long for the nonce");
    }
}

// Xây dựng khối bộ đếm B_i của CCM với giá trị bộ đếm được cung cấp.
Block counter_block(const Bytes& nonce, std::uint64_t counter) {
    const std::size_t q = 15 - nonce.size();
    Block result{};
    result[0] = static_cast<AES::Byte>(q - 1);
    std::copy(nonce.begin(), nonce.end(), result.begin() + 1);
    for (std::size_t i = 0; i < q; ++i) {
        result[15 - i] = static_cast<AES::Byte>(counter & 0xff);
        counter >>= 8;
    }
    return result;
}

// Thêm một số nguyên vào dữ liệu đầu ra theo định dạng big-endian được CCM sử dụng.
void append_length(Bytes& output, std::size_t length, std::size_t width) {
    for (std::size_t i = 0; i < width; ++i) {
        output.push_back(static_cast<AES::Byte>(length >> (8 * (width - 1 - i))));
    }
}

// Mã hóa dữ liệu liên kết bằng cách thêm tiền tố độ dài và đệm cho đủ khối.
Bytes format_aad(const Bytes& aad) {
    if (aad.empty()) return {};
    Bytes result;
    result.reserve(aad.size() + 10);
    if (aad.size() < 0xff00) {
        append_length(result, aad.size(), 2);
    } else if (aad.size() <= std::numeric_limits<std::uint32_t>::max()) {
        result = {0xff, 0xfe};
        append_length(result, aad.size(), 4);
    } else {
        result = {0xff, 0xff};
        append_length(result, aad.size(), 8);
    }
    result.insert(result.end(), aad.begin(), aad.end());
    result.resize((result.size() + 15) / 16 * 16, 0);
    return result;
}

// Tính giá trị CBC-MAC trên B_0, dữ liệu liên kết đã mã hóa và bản rõ.
Block cbc_mac(const AES& aes, const Bytes& plaintext, const Bytes& nonce,
              const Bytes& aad, std::size_t tag_length) {
    const std::size_t q = 15 - nonce.size();
    const bool has_aad = !aad.empty();
    const AES::Byte flags = static_cast<AES::Byte>(
        (has_aad ? 0x40 : 0) | (((tag_length - 2) / 2) << 3) | (q - 1));
    Bytes data{flags};
    data.insert(data.end(), nonce.begin(), nonce.end());
    append_length(data, plaintext.size(), q);
    const Bytes encoded_aad = format_aad(aad);
    data.insert(data.end(), encoded_aad.begin(), encoded_aad.end());
    data.insert(data.end(), plaintext.begin(), plaintext.end());
    data.resize((data.size() + 15) / 16 * 16, 0);

    Block mac{};
    for (std::size_t offset = 0; offset < data.size(); offset += 16) {
        mac = aes.encrypt(xorblock(mac, block(data, offset)));
    }
    return mac;
}

// Mã hóa hoặc giải mã dữ liệu bằng luồng khóa CTR của CCM.
// Bộ đếm 0 được dành riêng để che thẻ xác thực, vì vậy dữ liệu bắt đầu từ bộ đếm 1.
Bytes crypt(const AES& aes, const Bytes& input, const Bytes& nonce) {
    Bytes output;
    for (std::size_t offset = 0, counter = 1; offset < input.size();
         offset += 16, ++counter) {
        const Block stream = aes.encrypt(counter_block(nonce, counter));
        const std::size_t count = std::min<std::size_t>(16, input.size() - offset);
        for (std::size_t i = 0; i < count; ++i) {
            output.push_back(input[offset + i] ^ stream[i]);
        }
    }
    return output;
}

}

// Mã hóa bản rõ và trả về nonce (nếu được yêu cầu), bản mã và thẻ xác thực.
Bytes ccm_encrypt(const AES& aes, const Bytes& plaintext, const Bytes& nonce,
                  const Bytes& aad, std::size_t tag_length, bool prepend_nonce) {
    check_parameters(plaintext, nonce, tag_length);
    const Block mac = cbc_mac(aes, plaintext, nonce, aad, tag_length);
    const Block tag_mask = aes.encrypt(counter_block(nonce, 0));
    Bytes output = crypt(aes, plaintext, nonce);
    for (std::size_t i = 0; i < tag_length; ++i) {
        output.push_back(mac[i] ^ tag_mask[i]);
    }
    if (prepend_nonce) {
        output.insert(output.begin(), nonce.begin(), nonce.end());
    }
    return output;
}

// Giải mã bản mã và xác minh thẻ xác thực trước khi trả về bản rõ.
Bytes ccm_decrypt(const AES& aes, const Bytes& ciphertext_and_tag,
                  const Bytes& nonce, const Bytes& aad,
                  std::size_t tag_length, bool has_nonce,
                  std::size_t nonce_length) {
    if (nonce_length < 7 || nonce_length > 13) {
        throw std::invalid_argument("nonce_length must be between 7 and 13 bytes.");
    }
    Bytes nonce_bytes = nonce;
    Bytes data = ciphertext_and_tag;
    if (has_nonce) {
        if (data.size() < nonce_length + tag_length) {
            throw std::invalid_argument(
                "AES-CCM input with prepended nonce must contain nonce + ciphertext/tag.");
        }
        nonce_bytes.assign(data.begin(),
                           data.begin() + static_cast<std::ptrdiff_t>(nonce_length));
        data.erase(data.begin(),
                   data.begin() + static_cast<std::ptrdiff_t>(nonce_length));
    } else if (nonce_bytes.empty()) {
        throw std::invalid_argument("nonce is required when has_nonce=false.");
    }
    if (nonce_bytes.size() < 7 || nonce_bytes.size() > 13) {
        throw std::invalid_argument(
            "AES-CCM nonce length must be between 7 and 13 bytes.");
    }
    if (data.size() < tag_length) {
        throw std::invalid_argument(
            "AES-CCM input must contain ciphertext plus authentication tag.");
    }
    const Bytes ciphertext(data.begin(),
                           data.end() - static_cast<std::ptrdiff_t>(tag_length));
    const Bytes received_tag(data.end() -
                                 static_cast<std::ptrdiff_t>(tag_length),
                             data.end());
    check_parameters(ciphertext, nonce_bytes, tag_length);
    const Bytes plaintext = crypt(aes, ciphertext, nonce_bytes);
    const Block mac = cbc_mac(aes, plaintext, nonce_bytes, aad, tag_length);
    const Block tag_mask = aes.encrypt(counter_block(nonce_bytes, 0));
    Bytes expected_tag(tag_length);
    for (std::size_t i = 0; i < tag_length; ++i) expected_tag[i] = mac[i] ^ tag_mask[i];
    if (!constant_time_equal(received_tag, expected_tag)) {
        throw std::invalid_argument("CCM authentication failed");
    }
    return plaintext;
}

}