#pragma once

#include "aes.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace lab {
using Bytes = std::vector<std::uint8_t>;
using Block = AES::Block;

inline void check_aligned(const Bytes& data) {
    if (data.empty() || data.size() % AES::BLOCK_SIZE != 0) {
        throw std::invalid_argument("data length must be a non-zero multiple of 16 bytes");
    }
}

inline void check_iv(const Bytes& iv) {
    if (iv.size() != AES::BLOCK_SIZE) {
        throw std::invalid_argument("IV must be exactly 16 bytes");
    }
}

inline Bytes pad(const Bytes& data) {
    const auto count = AES::BLOCK_SIZE - data.size() % AES::BLOCK_SIZE;
    Bytes result = data;
    result.insert(result.end(), count, static_cast<std::uint8_t>(count));
    return result;
}

inline Bytes unpad(const Bytes& data) {
    check_aligned(data);
    const auto count = data.back();
    if (count == 0 || count > AES::BLOCK_SIZE ||
        !std::all_of(data.end() - count, data.end(),
                     [count](std::uint8_t value) { return value == count; })) {
        throw std::invalid_argument("invalid PKCS#7 padding");
    }
    return Bytes(data.begin(), data.end() - count);
}

inline Block block(const Bytes& data, std::size_t offset) {
    if (offset + AES::BLOCK_SIZE > data.size()) {
        throw std::invalid_argument("block exceeds input");
    }
    Block result{};
    std::copy_n(data.begin() + static_cast<std::ptrdiff_t>(offset),
                AES::BLOCK_SIZE, result.begin());
    return result;
}

inline void append(Bytes& output, const Block& value) {
    output.insert(output.end(), value.begin(), value.end());
}

inline Block xorblock(const Block& left, const Block& right) {
    Block result{};
    for (std::size_t i = 0; i < AES::BLOCK_SIZE; ++i) {
        result[i] = left[i] ^ right[i];
    }
    return result;
}

inline bool constant_time_equal(const Bytes& left, const Bytes& right) {
    if (left.size() != right.size()) return false;
    std::uint8_t difference = 0;
    for (std::size_t i = 0; i < left.size(); ++i) {
        difference = static_cast<std::uint8_t>(difference | (left[i] ^ right[i]));
    }
    return difference == 0;
}
}
