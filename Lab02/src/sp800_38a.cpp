#include "sp800_38a.hpp"
#include <algorithm>

/*
 * Các chế độ bảo mật dữ liệu của AES theo tiêu chuẩn NIST SP 800-38A.
 *
 * Các hàm này xử lý dữ liệu dưới dạng chuỗi byte thô và sử dụng phép toán
 * khối AES từ tệp aes.cpp. ECB và CBC có thể sử dụng đệm PKCS#7 tùy chọn;
 * CFB, OFB và CTR xử lý các đoạn dữ liệu cuối không đủ khối mà không cần đệm.
 */

namespace lab {

// Chế độ Electronic Codebook (ECB): mã hóa từng khối độc lập.
Bytes ecb_encrypt(const AES& aes, const Bytes& input, bool padding) {
    const Bytes data = padding ? pad(input) : input;
    check_aligned(data);

    Bytes output;
    for (std::size_t i = 0; i < data.size(); i += 16) {
        append(output, aes.encrypt(block(data, i)));
    }
    return output;
}

// Chế độ Electronic Codebook (ECB): giải mã từng khối độc lập.
Bytes ecb_decrypt(const AES& aes, const Bytes& input, bool padding) {
    check_aligned(input);

    Bytes output;
    for (std::size_t i = 0; i < input.size(); i += 16) {
        append(output, aes.decrypt(block(input, i)));
    }
    return padding ? unpad(output) : output;
}

// Chế độ Cipher Block Chaining (CBC): thực hiện XOR mỗi khối bản rõ với
// khối bản mã trước đó trước khi tiến hành mã hóa bằng AES.
Bytes cbc_encrypt(const AES& aes, const Bytes& input, const Bytes& iv, bool padding) {
    check_iv(iv);
    const Bytes data = padding ? pad(input) : input;
    check_aligned(data);

    Bytes output;
    Block previous = block(iv, 0);
    for (std::size_t i = 0; i < data.size(); i += 16) {
        previous = aes.encrypt(xorblock(block(data, i), previous));
        append(output, previous);
    }
    return output;
}

// Giải mã theo chế độ Cipher Block Chaining (CBC): giải mã trước, sau đó
// thực hiện XOR với vector khởi tạo (IV) hoặc khối bản mã liền trước.
Bytes cbc_decrypt(const AES& aes, const Bytes& input, const Bytes& iv, bool padding) {
    check_iv(iv);
    check_aligned(input);

    Bytes output;
    Block previous = block(iv, 0);
    for (std::size_t i = 0; i < input.size(); i += 16) {
        const Block current = block(input, i);
        append(output, xorblock(aes.decrypt(current), previous));
        previous = current;
    }
    return padding ? unpad(output) : output;
}

// Hàm triển khai CFB dùng chung. Khi mã hóa, bản mã được đưa trở lại thanh ghi;
// khi giải mã, bản mã nhận được được đưa trở lại thanh ghi.
static Bytes cfb(const AES& aes, const Bytes& input, const Bytes& iv, int bits, bool encrypt) {
    check_iv(iv);
    if (bits < 8 || bits > 128 || bits % 8 != 0) {
        throw std::invalid_argument(
            "CFB segment bits must be 8..128 and byte-aligned");
    }

    const std::size_t segment_size = static_cast<std::size_t>(bits / 8);
    Block register_value = block(iv, 0);
    Bytes output;

    for (std::size_t i = 0; i < input.size(); i += segment_size) {
        const Block stream = aes.encrypt(register_value);
        const std::size_t count =
            std::min(segment_size, input.size() - i);

        for (std::size_t j = 0; j < count; ++j) {
            output.push_back(input[i + j] ^ stream[j]);
        }

        if (count == segment_size) {
            for (std::size_t j = 0; j < 16 - segment_size; ++j) {
                register_value[j] = register_value[j + segment_size];
            }
            for (std::size_t j = 0; j < segment_size; ++j) {
                register_value[16 - segment_size + j] =
                    encrypt ? output[i + j] : input[i + j];
            }
        }
    }
    return output;
}

// Mã hóa CFB với kích thước đoạn dữ liệu là bội số của một byte.
Bytes cfb_encrypt(const AES& aes, const Bytes& input, const Bytes& iv,
                  int bits) {
    return cfb(aes, input, iv, bits, true);
}

// Giải mã CFB với kích thước đoạn dữ liệu là bội số của một byte.
Bytes cfb_decrypt(const AES& aes, const Bytes& input, const Bytes& iv,
                  int bits) {
    return cfb(aes, input, iv, bits, false);
}

// Chế độ Output Feedback (OFB). Quá trình mã hóa và giải mã sử dụng cùng một luồng khóa.
Bytes ofb_crypt(const AES& aes, const Bytes& input, const Bytes& iv) {
    check_iv(iv);

    Block feedback = block(iv, 0);
    Bytes output;
    for (std::size_t i = 0; i < input.size(); i += 16) {
        feedback = aes.encrypt(feedback);
        const std::size_t count =
            std::min<std::size_t>(16, input.size() - i);
        for (std::size_t j = 0; j < count; ++j) {
            output.push_back(input[i + j] ^ feedback[j]);
        }
    }
    return output;
}

// Chế độ Counter (CTR). Bộ đếm 128 bit được tăng theo thứ tự big-endian
// sau mỗi khối hoàn chỉnh và quay về 0 khi tràn theo modulo 2^128.
Bytes ctr_crypt(const AES& aes, const Bytes& input, const Bytes& initial_counter) {
    check_iv(initial_counter);

    Block counter = block(initial_counter, 0);
    Bytes output;
    for (std::size_t i = 0; i < input.size(); i += 16) {
        const Block stream = aes.encrypt(counter);
        const std::size_t count =
            std::min<std::size_t>(16, input.size() - i);
        for (std::size_t j = 0; j < count; ++j) {
            output.push_back(input[i + j] ^ stream[j]);
        }

        if (i + 16 < input.size()) {
            for (int j = 15; j >= 0; --j) {
                if (++counter[static_cast<std::size_t>(j)] != 0) break;
            }
        }
    }
    return output;
}

}