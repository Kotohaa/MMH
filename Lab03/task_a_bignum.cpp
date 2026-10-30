#include <openssl/bn.h>
#include <openssl/err.h>

#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

namespace {

// ------------------------------------------------------------- RAII ----
struct BnDeleter  { void operator()(BIGNUM* p) const { BN_clear_free(p); } };
struct CtxDeleter { void operator()(BN_CTX* p) const { BN_CTX_free(p); } };
using Big = std::unique_ptr<BIGNUM, BnDeleter>;
using Ctx = std::unique_ptr<BN_CTX, CtxDeleter>;

struct InputClosed {};  // stdin reached end-of-file

[[noreturn]] void raise(const std::string& msg) { throw std::runtime_error(msg); }
void must(int rc, const char* what) {
    if (rc != 1) raise(std::string("OpenSSL call failed: ") + what);
}
Big newBig() {
    BIGNUM* p = BN_new();
    if (!p) raise("out of memory");
    return Big(p);
}
Ctx newCtx() {
    BN_CTX* c = BN_CTX_new();
    if (!c) raise("out of memory");
    return Ctx(c);
}
Big copyOf(const BIGNUM* x) {
    BIGNUM* p = BN_dup(x);
    if (!p) raise("out of memory");
    return Big(p);
}
std::string toDec(const BIGNUM* x) {
    char* s = BN_bn2dec(x);
    if (!s) raise("BN_bn2dec failed");
    std::string out(s);
    OPENSSL_free(s);
    return out;
}


// ------------------------------------------------------------ input ----
std::string trim(const std::string& s) {
    const char* ws = " \t\r\n";
    size_t b = s.find_first_not_of(ws);
    if (b == std::string::npos) return "";
    return s.substr(b, s.find_last_not_of(ws) - b + 1);
}

std::string askLine(const std::string& prompt) {
    std::cout << prompt << std::flush;
    std::string line;
    if (!std::getline(std::cin, line)) throw InputClosed{};
    return trim(line);
}

// Non-negative decimal integer, strict. Throws runtime_error if malformed.
Big parseNumber(const std::string& text) {
    if (text.empty() || text.size() > 10000) raise("enter 1 to 10000 decimal digits");
    for (char ch : text)
        if (ch < '0' || ch > '9') raise("only digits 0-9 are allowed (no sign, no spaces)");
    BIGNUM* raw = nullptr;
    int used = BN_dec2bn(&raw, text.c_str());
    Big out(raw);
    if (used != static_cast<int>(text.size())) raise("cannot parse number");
    return out;
}

// Ask until the user types a valid number.
Big askNumber(const std::string& name, bool mustBePositive = false) {
    for (;;) {
        std::string line = askLine("Enter " + name + ": ");
        try {
            Big x = parseNumber(line);
            if (mustBePositive && BN_is_zero(x.get())) raise(name + " must be greater than 0");
            return x;
        } catch (const std::runtime_error& e) {
            std::cout << "  Invalid input: " << e.what() << "\n";
        }
    }
}

// --------------------------------------------- hand-written algorithms ----
// Square-and-multiply, scanning the exponent from its most significant bit.
Big powerMod(const BIGNUM* a, const BIGNUM* b, const BIGNUM* m, BN_CTX* ctx) {
    Big acc = newBig(), base = newBig();
    must(BN_one(acc.get()), "BN_one");
    must(BN_nnmod(base.get(), a, m, ctx), "BN_nnmod");
    for (int i = BN_num_bits(b) - 1; i >= 0; --i) {
        must(BN_mod_sqr(acc.get(), acc.get(), m, ctx), "BN_mod_sqr");
        if (BN_is_bit_set(b, i))
            must(BN_mod_mul(acc.get(), acc.get(), base.get(), m, ctx), "BN_mod_mul");
    }
    if (BN_is_one(m)) BN_zero(acc.get());
    return acc;
}

struct InverseResult {
    Big gcd;
    Big inverse;  // null if gcd != 1
};

// Extended Euclid tracking only the coefficient of a.
InverseResult inverseMod(const BIGNUM* a, const BIGNUM* m, BN_CTX* ctx) {
    Big oldR = newBig(), r = copyOf(m), oldS = newBig(), s = newBig();
    Big q = newBig(), rem = newBig(), prod = newBig(), next = newBig();
    must(BN_nnmod(oldR.get(), a, m, ctx), "BN_nnmod");
    must(BN_one(oldS.get()), "BN_one");
    BN_zero(s.get());
    while (!BN_is_zero(r.get())) {
        must(BN_div(q.get(), rem.get(), oldR.get(), r.get(), ctx), "BN_div");
        must(BN_mul(prod.get(), q.get(), s.get(), ctx), "BN_mul");
        must(BN_sub(next.get(), oldS.get(), prod.get()), "BN_sub");
        std::swap(oldR, r);
        std::swap(r, rem);
        std::swap(oldS, s);
        std::swap(s, next);
    }
    InverseResult res;
    res.gcd = copyOf(oldR.get());
    if (BN_is_one(oldR.get())) {
        res.inverse = newBig();
        must(BN_nnmod(res.inverse.get(), oldS.get(), m, ctx), "BN_nnmod");
    }
    return res;
}

// ---------------------------------------------------------- menu actions ----
void doAdd() {
    Big a = askNumber("a"), b = askNumber("b"), m = askNumber("m", true);
    Ctx ctx = newCtx();
    Big r = newBig();
    must(BN_mod_add(r.get(), a.get(), b.get(), m.get(), ctx.get()), "BN_mod_add");
    std::cout << "(a + b) mod m = " << toDec(r.get()) << "\n";
}

void doSub() {
    Big a = askNumber("a"), b = askNumber("b"), m = askNumber("m", true);
    Ctx ctx = newCtx();
    Big r = newBig();
    must(BN_mod_sub(r.get(), a.get(), b.get(), m.get(), ctx.get()), "BN_mod_sub");
    std::cout << "(a - b) mod m = " << toDec(r.get()) << "   (always in [0, m))\n";
}

void doMul() {
    Big a = askNumber("a"), b = askNumber("b"), m = askNumber("m", true);
    Ctx ctx = newCtx();
    Big r = newBig();
    must(BN_mod_mul(r.get(), a.get(), b.get(), m.get(), ctx.get()), "BN_mod_mul");
    std::cout << "(a * b) mod m = " << toDec(r.get()) << "\n";
}

void doGcd() {
    Big a = askNumber("a"), b = askNumber("b");
    Ctx ctx = newCtx();
    Big r = newBig();
    must(BN_gcd(r.get(), a.get(), b.get(), ctx.get()), "BN_gcd");
    std::cout << "gcd(a, b) = " << toDec(r.get()) << "\n";
}

void doPower() {
    Big a = askNumber("a"), b = askNumber("b (exponent)"), m = askNumber("m", true);
    Ctx ctx = newCtx();
    Big viaLib = newBig();
    must(BN_mod_exp(viaLib.get(), a.get(), b.get(), m.get(), ctx.get()), "BN_mod_exp");
    Big viaMine = powerMod(a.get(), b.get(), m.get(), ctx.get());
    std::cout << "a^b mod m = " << toDec(viaLib.get()) << "\n";
    std::cout << (BN_cmp(viaLib.get(), viaMine.get()) == 0
                      ? "[PASS] our square-and-multiply matches BN_mod_exp\n"
                      : "[FAIL] our square-and-multiply differs from BN_mod_exp\n");
}

void doInverse() {
    Big a = askNumber("a"), m = askNumber("m", true);
    Ctx ctx = newCtx();
    if (BN_is_one(m.get())) {
        std::cout << "Modulo 1 every integer is 0: the inverse is not meaningful.\n";
        return;
    }
    InverseResult mine = inverseMod(a.get(), m.get(), ctx.get());
    Big lib(BN_mod_inverse(nullptr, a.get(), m.get(), ctx.get()));
    if (!lib) ERR_clear_error();  // "no inverse" is an expected result
    if (!mine.inverse) {
        std::cout << "No inverse exists: gcd(a, m) = " << toDec(mine.gcd.get()) << " (must be 1)\n";
        std::cout << (!lib ? "[PASS] BN_mod_inverse agrees\n" : "[FAIL] BN_mod_inverse disagrees\n");
        return;
    }
    std::cout << "a^(-1) mod m = " << toDec(mine.inverse.get()) << "\n";
    std::cout << (lib && BN_cmp(mine.inverse.get(), lib.get()) == 0
                      ? "[PASS] our extended Euclid matches BN_mod_inverse\n"
                      : "[FAIL] our extended Euclid differs from BN_mod_inverse\n");
}

// Option 7: random probable prime of the requested size.
// Silently redraws until gcd(65537, p-1) = 1, so p is usable as an RSA factor.
void doPrime() {
    int bits = 0;
    for (;;) {
        std::string line = askLine("Enter prime size in bits (e.g. 512, 1024): ");
        try {
            size_t used = 0;
            bits = std::stoi(line, &used);
            if (used != line.size()) bits = 0;
        } catch (...) {
            bits = 0;
        }
        if (bits >= 16 && bits <= 8192) break;
        std::cout << "Invalid size. Enter an integer between 16 and 8192.\n";
    }

    std::cout << "Generating a " << bits << "-bit probable prime...\n" << std::flush;

    Ctx ctx = newCtx();
    Big e = newBig(), p = newBig(), pm1 = newBig(), g = newBig();
    must(BN_set_word(e.get(), 65537), "BN_set_word");
    do {
        must(BN_generate_prime_ex(p.get(), bits, /*safe=*/0, nullptr, nullptr, nullptr),
             "BN_generate_prime_ex");
        must(BN_sub(pm1.get(), p.get(), BN_value_one()), "BN_sub");
        must(BN_gcd(g.get(), e.get(), pm1.get(), ctx.get()), "BN_gcd");
    } while (!BN_is_one(g.get()));

    std::cout << "Prime generated successfully.\n";
    std::cout << "Actual bit length: " << BN_num_bits(p.get()) << "\n";
    std::cout << "p = " << toDec(p.get()) << "\n";
}

void printMenu() {
    std::cout << "\n==================================\n"
                 "       OpenSSL BIGNUM CLI Lab\n"
                 "==================================\n"
                 "1. Modular addition:       (a + b) mod m\n"
                 "2. Modular subtraction:    (a - b) mod m\n"
                 "3. Modular multiplication: (a * b) mod m\n"
                 "4. Greatest common divisor: gcd(a, b)\n"
                 "5. Modular exponentiation: a^b mod m\n"
                 "6. Modular inverse:        a^(-1) mod m\n"
                 "7. Generate a large prime for RSA\n"
                 "0. Exit\n";
}

}  // namespace

int main() {
    try {
        for (;;) {
            printMenu();
            std::string choice = askLine("Choose: ");
            if (choice == "0") break;
            try {
                if      (choice == "1") doAdd();
                else if (choice == "2") doSub();
                else if (choice == "3") doMul();
                else if (choice == "4") doGcd();
                else if (choice == "5") doPower();
                else if (choice == "6") doInverse();
                else if (choice == "7") doPrime();
                else std::cout << "Unknown option '" << choice << "'. Choose 0-7.\n";
            } catch (const std::runtime_error& e) {
                std::cout << "Error: " << e.what() << "\n";
                ERR_print_errors_fp(stderr);
            }
        }
    } catch (const InputClosed&) {
        // stdin closed: leave quietly
    }
    std::cout << "Bye.\n";
    return 0;
}
