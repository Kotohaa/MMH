#include "aes.hpp"
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>

/*
 * Thành phần cơ bản của mã khối AES dành cho AES-128, AES-192 và AES-256.
 *
 * Cách triển khai này tuân theo cấu trúc hướng dẫn học tập của AES.py:
 * trạng thái AES được lưu dưới dạng state[row][column], và các byte đầu vào
 * được ánh xạ vào trạng thái theo từng cột. Các chế độ hoạt động được triển khai
 * trong những tệp mã nguồn SP 800-38A và SP 800-38C.
 */

// Các hằng số AES: các hộp thay thế và hằng số vòng được sử dụng trong FIPS 197.
const std::array<AES::Byte, 256> AES::S_BOX{
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const std::array<AES::Byte, 256> AES::INV_S_BOX{
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// Các hằng số vòng được sử dụng trong quá trình mở rộng khóa AES.
const std::array<AES::Word, 10> AES::RCON{{
    {0x01, 0x00, 0x00, 0x00}, {0x02, 0x00, 0x00, 0x00},
    {0x04, 0x00, 0x00, 0x00}, {0x08, 0x00, 0x00, 0x00},
    {0x10, 0x00, 0x00, 0x00}, {0x20, 0x00, 0x00, 0x00},
    {0x40, 0x00, 0x00, 0x00}, {0x80, 0x00, 0x00, 0x00},
    {0x1b, 0x00, 0x00, 0x00}, {0x36, 0x00, 0x00, 0x00}
}};

AES::AES(const std::vector<Byte>& key, int keyLengthBits) : key_(key) {
    // Xác định độ dài khóa từ khóa được cung cấp nếu chưa chỉ định.
    if (keyLengthBits == 0) keyLengthBits = static_cast<int>(key_.size() * 8);
    if (keyLengthBits != 128 && keyLengthBits != 192 && keyLengthBits != 256) {
        throw std::invalid_argument("Invalid AES key length. Use 128, 192, or 256 bits.");
    }
    const std::size_t expectedLength = static_cast<std::size_t>(keyLengthBits / 8);
    if (key_.size() != expectedLength) {
        throw std::invalid_argument("AES-" + std::to_string(keyLengthBits) +
                                    " requires " + std::to_string(expectedLength) +
                                    " key bytes; got " + std::to_string(key_.size()) + ".");
    }
    keyLength_ = keyLengthBits;
    numRounds_ = keyLengthBits == 128 ? 10 : keyLengthBits == 192 ? 12 : 14;
    roundKeys_ = keyExpansion(key_);
}

AES::Byte AES::gmul(Byte a, Byte b) {
    // Phép nhân trong trường Galois GF(2^8), sử dụng đa thức AES.
    Byte product = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) product ^= a;
        const Byte highBit = static_cast<Byte>(a & 0x80);
        a = static_cast<Byte>(a << 1);
        if (highBit) a ^= 0x1b;
        b >>= 1;
    }
    return product;
}

AES::State AES::bytesToState(const Block& block) {
    // Ánh xạ khối 16 byte thành state[row][column] theo thứ tự cột.
    State state{};
    for (int row = 0; row < 4; ++row)
        for (int column = 0; column < 4; ++column)
            state[row][column] = block[4 * column + row];
    return state;
}

AES::Block AES::stateToBytes(const State& state) {
    // Chuyển state[row][column] trở lại thành các byte theo thứ tự cột.
    Block block{};
    std::size_t index = 0;
    for (int column = 0; column < 4; ++column)
        for (int row = 0; row < 4; ++row)
            block[index++] = state[row][column];
    return block;
}

void AES::subBytes(State& state) {
    // Thay thế từng byte của trạng thái bằng cách sử dụng hộp S-box AES.
    for (int i = 0; i < 4; ++i)
        for (int j = 0; j < 4; ++j)
            state[i][j] = S_BOX[state[i][j]];
}

void AES::invSubBytes(State& state) {
    // Thay thế từng byte của trạng thái bằng cách sử dụng hộp S-box nghịch đảo AES.
    for (int i = 0; i < 4; ++i)
        for (int j = 0; j < 4; ++j)
            state[i][j] = INV_S_BOX[state[i][j]];
}

void AES::shiftRows(State& state) {
    // Dịch vòng các hàng sang trái một số vị trí bằng chỉ số hàng tương ứng.
    state[1] = State::value_type{state[1][1], state[1][2], state[1][3], state[1][0]};
    state[2] = State::value_type{state[2][2], state[2][3], state[2][0], state[2][1]};
    state[3] = State::value_type{state[3][3], state[3][0], state[3][1], state[3][2]};
}

void AES::invShiftRows(State& state) {
    // Dịch vòng các hàng sang phải một số vị trí bằng chỉ số hàng tương ứng.
    state[1] = State::value_type{state[1][3], state[1][0], state[1][1], state[1][2]};
    state[2] = State::value_type{state[2][2], state[2][3], state[2][0], state[2][1]};
    state[3] = State::value_type{state[3][1], state[3][2], state[3][3], state[3][0]};
}

void AES::mixColumns(State& state) {
    // Trộn từng cột của trạng thái bằng ma trận biến đổi AES.
    for (int i = 0; i < 4; ++i) {
        const Byte a0 = state[0][i], a1 = state[1][i], a2 = state[2][i], a3 = state[3][i];
        state[0][i] = gmul(0x02, a0) ^ gmul(0x03, a1) ^ a2 ^ a3;
        state[1][i] = a0 ^ gmul(0x02, a1) ^ gmul(0x03, a2) ^ a3;
        state[2][i] = a0 ^ a1 ^ gmul(0x02, a2) ^ gmul(0x03, a3);
        state[3][i] = gmul(0x03, a0) ^ a1 ^ a2 ^ gmul(0x02, a3);
    }
}

void AES::invMixColumns(State& state) {
    // Áp dụng phép biến đổi MixColumns nghịch đảo trong quá trình giải mã.
    for (int i = 0; i < 4; ++i) {
        const Byte a0 = state[0][i], a1 = state[1][i], a2 = state[2][i], a3 = state[3][i];
        state[0][i] = gmul(0x0e, a0) ^ gmul(0x0b, a1) ^ gmul(0x0d, a2) ^ gmul(0x09, a3);
        state[1][i] = gmul(0x09, a0) ^ gmul(0x0e, a1) ^ gmul(0x0b, a2) ^ gmul(0x0d, a3);
        state[2][i] = gmul(0x0d, a0) ^ gmul(0x09, a1) ^ gmul(0x0e, a2) ^ gmul(0x0b, a3);
        state[3][i] = gmul(0x0b, a0) ^ gmul(0x0d, a1) ^ gmul(0x09, a2) ^ gmul(0x0e, a3);
    }
}

void AES::addRoundKey(State& state, int round) const {
    // Thực hiện XOR trạng thái với bốn từ khóa đã mở rộng của vòng hiện tại.
    for (int i = 0; i < 4; ++i)
        for (int j = 0; j < 4; ++j)
            state[j][i] ^= roundKeys_[round * 4 + i][j];
}

AES::Word AES::rotWord(Word word) {
    // ROTWORD([a0,a1,a2,a3]) = [a1,a2,a3,a0].
    return Word{word[1], word[2], word[3], word[0]};
}

AES::Word AES::subWord(Word word) {
    // SUBWORD([a0,...,a3]) = [SBOX(a0),...,SBOX(a3)].
    for (auto& byte : word) byte = S_BOX[byte];
    return word;
}

std::vector<AES::Word> AES::keyExpansion(const std::vector<Byte>& key) const {
    /*
     * Tạo các từ khóa đã mở rộng:
     *   AES-128: Nk = 4, 44 từ, 10 vòng
     *   AES-192: Nk = 6, 52 từ, 12 vòng
     *   AES-256: Nk = 8, 60 từ, 14 vòng
     */
    const int keyWords = keyLength_ / 32;
    const int totalWords = 4 * (numRounds_ + 1);
    std::vector<Word> roundKeys;
    // Nk từ đầu tiên được lấy trực tiếp từ khóa ban đầu.
    for (std::size_t i = 0; i < key.size(); i += 4)
        roundKeys.push_back(Word{key[i], key[i + 1], key[i + 2], key[i + 3]});

    // Mở rộng các từ khóa ban đầu cho đến khi tạo đủ tất cả khóa vòng.
    for (int i = keyWords; i < totalWords; ++i) {
        Word temp = roundKeys[i - 1];
        if (i % keyWords == 0) {
            temp = subWord(rotWord(temp));
            temp[0] ^= RCON[(i - keyWords) / keyWords][0];
        } else if (keyWords == 8 && i % keyWords == 4) {
            temp = subWord(temp);
        }
        Word next{};
        for (int j = 0; j < 4; ++j)
            next[j] = roundKeys[i - keyWords][j] ^ temp[j];
        roundKeys.push_back(next);
    }
    return roundKeys;
}

AES::Block AES::encrypt(const Block& data, bool) const {
    // Mã hóa chính xác một khối dữ liệu gồm 16 byte.
    State state = bytesToState(data);
    // Thực hiện AddRoundKey ban đầu.
    addRoundKey(state, 0);
    // Thực hiện Nr - 1 vòng đầy đủ: SubBytes, ShiftRows, MixColumns, AddRoundKey.
    for (int round = 1; round < numRounds_; ++round) {
        // Vòng cuối: không thực hiện MixColumns.
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, round);
    }
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, numRounds_);
    return stateToBytes(state);
}

AES::Block AES::decrypt(const Block& ciphertext, bool) const {
    // Giải mã chính xác một khối bản mã gồm 16 byte.
    State state = bytesToState(ciphertext);
    // Vòng nghịch đảo ban đầu bắt đầu bằng AddRoundKey(Nr).
    addRoundKey(state, numRounds_);
    // Thực hiện Nr - 1 vòng nghịch đảo đầy đủ.
    for (int round = numRounds_ - 1; round > 0; --round) {
        // Vòng nghịch đảo cuối: không thực hiện InvMixColumns.
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, round);
        invMixColumns(state);
    }
    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, 0);
    return stateToBytes(state);
}

std::string AES::byteToHex(Byte byte) {
    std::ostringstream output;
    output << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    return output.str();
}

void AES::printRoundKey(int round) const {
    std::cout << "Round " << round << ": ";
    for (int word = 0; word < 4; ++word)
        for (Byte byte : roundKeys_[round * 4 + word])
            std::cout << byteToHex(byte);
    std::cout << '\n';
}

void AES::printAllRoundKeys() const {
    for (int round = 0; round <= numRounds_; ++round) printRoundKey(round);
}

void AES::printState(const std::string&, const State&) {}