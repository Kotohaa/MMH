#ifndef AES_H
#define AES_H

#include <iostream>
#include <vector>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <iomanip>

using namespace std;

class AES {
public:
    using Byte = uint8_t;
    using Word = array<Byte, 4>;
    using State = array<array<Byte, 4>, 4>;
    using Block = array<Byte, 16>;

private:
    vector<Word> round_keys;
    int key_length;
    int nk, nr;

    static const Byte s_box[256];
    static const Byte inv_s_box[256];

    State bytes_to_state(const Block& data);
    Block state_to_bytes(const State& state);
    static Byte gmul(Byte a, Byte b);
    Word rot_word(const Word& word);
    Word sub_word(const Word& word);
    void key_expansion(const vector<Byte>& key);
    void add_round_key(State& state, int round);
    void sub_bytes(State& state);
    void inv_sub_bytes(State& state);
    void shift_rows(State& state);
    void inv_shift_rows(State& state);
    void mix_columns(State& state);
    void inv_mix_columns(State& state);

public:
    explicit AES(const vector<Byte>& key);
    Block encrypt(const Block& plaintext);
    Block decrypt(const Block& ciphertext);
    int get_key_length() const;
};

#endif // AES_H