#include "aes.hpp"
#include <algorithm>
#include <exception>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using Byte = AES::Byte;

Byte hex_digit(char value) {
    if (value >= '0' && value <= '9') return static_cast<Byte>(value - '0');
    if (value >= 'a' && value <= 'f') return static_cast<Byte>(value - 'a' + 10);
    if (value >= 'A' && value <= 'F') return static_cast<Byte>(value - 'A' + 10);
    throw std::invalid_argument("hex input contains an invalid character");
}

std::vector<Byte> parse_hex(const std::string& value, const char* name) {
    if (value.size() % 2 != 0) {
        throw std::invalid_argument(std::string(name) + " must contain an even number of hex digits");
    }

    std::vector<Byte> result;
    result.reserve(value.size() / 2);
    for (std::size_t i = 0; i < value.size(); i += 2) {
        result.push_back(static_cast<Byte>((hex_digit(value[i]) << 4) |
                                           hex_digit(value[i + 1])));
    }
    return result;
}

std::string to_hex(const AES::Block& block) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(AES::BLOCK_SIZE * 2);
    for (Byte value : block) {
        result.push_back(digits[value >> 4]);
        result.push_back(digits[value & 0x0f]);
    }
    return result;
}

std::string to_hex(const std::vector<Byte>& data) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(data.size() * 2);
    for (Byte value : data) {
        result.push_back(digits[value >> 4]);
        result.push_back(digits[value & 0x0f]);
    }
    return result;
}

std::vector<Byte> random_bytes(std::size_t count) {
    std::random_device random;
    std::vector<Byte> result(count);
    for (Byte& value : result) {
        value = static_cast<Byte>(random() & 0xffu);
    }
    return result;
}

void run_demo() {
    const std::vector<Byte> key = random_bytes(16);
    const std::vector<Byte> plaintext_bytes = random_bytes(AES::BLOCK_SIZE);

    AES::Block plaintext{};
    std::copy(plaintext_bytes.begin(), plaintext_bytes.end(), plaintext.begin());

    const AES aes(key);
    const AES::Block ciphertext = aes.encrypt(plaintext);
    const AES::Block decrypted = aes.decrypt(ciphertext);

    std::cout << "AES-128 random demonstration\n"
              << "KEY        : " << to_hex(key) << '\n'
              << "PLAINTEXT  : " << to_hex(plaintext) << '\n'
              << "CIPHERTEXT : " << to_hex(ciphertext) << '\n'
              << "DECRYPTED  : " << to_hex(decrypted) << '\n'
              << "RESULT     : "
              << (decrypted == plaintext ? "PASS" : "FAIL") << '\n';
}

void print_usage(const char* program) {
    std::cerr << "Usage: " << program << " <enc|dec> <key-hex> <block-hex>\n"
              << "  key-hex:   32, 48, or 64 hexadecimal characters\n"
              << "  block-hex: exactly 32 hexadecimal characters\n";
}

}

int main(int argc, char* argv[]) {
    if (argc == 1) {
        try {
            run_demo();
            return 0;
        } catch (const std::exception& error) {
            std::cerr << "error: " << error.what() << '\n';
            return 1;
        }
    }

    if (argc != 4 || (std::string(argv[1]) != "enc" &&
                      std::string(argv[1]) != "dec")) {
        print_usage(argv[0]);
        return 2;
    }

    try {
        const std::vector<Byte> key = parse_hex(argv[2], "key");
        const std::vector<Byte> input = parse_hex(argv[3], "block");
        if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
            throw std::invalid_argument("key must be 16, 24, or 32 bytes");
        }
        if (input.size() != AES::BLOCK_SIZE) {
            throw std::invalid_argument("block must be exactly 16 bytes");
        }

        AES::Block block{};
        std::copy(input.begin(), input.end(), block.begin());
        const AES aes(key);
        const AES::Block result =
            std::string(argv[1]) == "enc" ? aes.encrypt(block) : aes.decrypt(block);
        std::cout << to_hex(result) << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
