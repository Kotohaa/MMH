#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>

class AES {
public:
    static constexpr std::size_t BLOCK_SIZE = 16;
    using Byte = std::uint8_t;
    using Block = std::array<Byte, BLOCK_SIZE>;
    using Word = std::array<Byte, 4>;
    using State = std::array<std::array<Byte, 4>, 4>;
    AES(const std::vector<Byte>& key, int keyLengthBits = 0);
    Block encrypt(const Block& plaintext, bool trace = false) const;
    Block decrypt(const Block& ciphertext, bool trace = false) const;
    void printAllRoundKeys() const;
private:
    std::vector<Byte> key_;
    int keyLength_ = 0;
    int numRounds_ = 0;
    std::vector<Word> roundKeys_;
    static const std::array<Byte, 256> S_BOX;
    static const std::array<Byte, 256> INV_S_BOX;
    static const std::array<Word, 10> RCON;
    static Byte gmul(Byte a, Byte b);
    static State bytesToState(const Block& block);
    static Block stateToBytes(const State& state);
    static void subBytes(State& state);
    static void invSubBytes(State& state);
    static void shiftRows(State& state);
    static void invShiftRows(State& state);
    static void mixColumns(State& state);
    static void invMixColumns(State& state);
    void addRoundKey(State& state, int round) const;
    static Word rotWord(Word w);
    static Word subWord(Word w);
    std::vector<Word> keyExpansion(const std::vector<Byte>& key) const;
    static std::string byteToHex(Byte b);
    void printRoundKey(int round) const;
    static void printState(const std::string& label, const State& state);
};
