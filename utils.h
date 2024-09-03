#pragma once

#include "lfsr_hash.h"
#include "worker.h"
#include "key.h"
#include <qdebug.h>

namespace const_arr {
constexpr int goods[] = {3, 5, 6, 7, 10, 12, 14, 19, 20, 24, 27, 28, 33, 37, 38, 39,
                         40, 41, 43, 45, 47, 48, 51, 53, 54, 55, 56, 63, 65, 66, 69, 71,
                         74, 75, 76, 77, 78, 80, 82, 83, 85, 86, 87, 90, 91, 93, 94, 96,
                         97, 101, 102, 103, 105, 106, 107, 108, 109, 110, 112, 115, 119, 125, 126, 127,
                         130, 131, 132, 138, 142, 145, 147, 148, 149, 150, 151, 152, 154, 155, 156, 160,
                         161, 163, 164, 166, 167, 170, 171, 172, 174, 175, 177, 179, 180, 181, 182, 183,
                         186, 188, 191, 192, 194, 201, 202, 203, 204, 206, 209, 210, 212, 214, 216, 217,
                         218, 219, 220, 224, 229, 230, 233, 237, 238, 243, 245, 247, 250, 251, 252, 254};
}

namespace main {
    lfsr_rng::Generators pass_gen;
    Worker worker;
    key::Key key;
    lfsr_hash::gens hash_gen;
    QVector<lfsr8::u64> pswd_buff{};
    QString storage{};
    int pin_code[4]{};
    bool needToGeneratePasswords = true;
}

namespace enc {
    lfsr_rng::Generators gamma_gen;
    int aligner64 = 0;
    lfsr_rng::u64 gamma = 0;
}

namespace dec {
    lfsr_rng::Generators gamma_gen;
    int aligner64 = 0;
    lfsr_rng::u64 gamma = 0;
}

namespace enc_inner {
    lfsr_rng::Generators gamma_gen;
    int aligner64 = 0;
    lfsr_rng::u64 gamma = 0;
}

namespace dec_inner {
    lfsr_rng::Generators gamma_gen;
    int aligner64 = 0;
    lfsr_rng::u64 gamma = 0;
}

inline static uint8_t rotl8(uint8_t n, unsigned int c)
{
    const unsigned int mask = CHAR_BIT*sizeof(n) - 1;
    c &= mask;
    return (n << c) | (n >> ( (-c) & mask ));
}

inline static uint8_t rotr8(uint8_t n, unsigned int c)
{
    const unsigned int mask = CHAR_BIT*sizeof(n) - 1;
    c &= mask;
    return (n >> c) | (n << ( (-c) & mask ));
}

inline static void encode_crc(QByteArray& data) {
    int i;
    char crc1 = '\0';
    for (auto b : std::as_const(data)) {
        crc1 ^= b;
    }
    data.push_back(crc1);
    char crc2 = '\0';
    i = 0;
    for (auto b : std::as_const(data)) {
        crc2 = crc2 ^ (i % 2 == 0 ? b : '\0');
        i++;
    }
    data.push_back(crc2);
    char crc3 = '\0';
    i = 0;
    for (auto b : std::as_const(data)) {
        crc3 = crc3 ^ (i % 3 == 0 ? b : '\0');
        i++;
    }
    data.push_back(crc3);
    char crc4 = '\0';
    i = 0;
    for (auto b : std::as_const(data)) {
        crc4 = crc4 ^ (i % 5 == 0 ? b : '\0');
        i++;
    }
    data.push_back(crc4);
}

inline static bool decode_crc(QByteArray& data) {
    if (data.size() < 4) {
        return false;
    }
    int i;
    char crc4 = data.back();
    data.removeLast();
    i = 0;
    for (auto b : std::as_const(data)) {
        crc4 = crc4 ^ (i % 5 == 0 ? b : '\0');
        i++;
    }
    char crc3 = data.back();
    data.removeLast();
    i = 0;
    for (auto b : std::as_const(data)) {
        crc3 = crc3 ^ (i % 3 == 0 ? b : '\0');
        i++;
    }
    char crc2 = data.back();
    data.removeLast();
    i = 0;
    for (auto b : std::as_const(data)) {
        crc2 = crc2 ^ (i % 2 == 0 ? b : '\0');
        i++;
    }
    char crc1 = data.back();
    data.removeLast();
    for (auto b : std::as_const(data)) {
        crc1 ^= b;
    }
    if (crc4 != '\0' || crc3 != '\0' || crc2 != '\0' || crc1 != '\0')
    {
        return false;
    }
    return true;
}

inline static lfsr_hash::salt pin_to_salt_1()
{
    using namespace lfsr_hash;
    const int x1_4bit = (main::pin_code[0] + 0) ^ (main::pin_code[1] + 0) ^ (main::pin_code[2] + 3) ^ (main::pin_code[3] + 6);
    const int x2_4bit = (main::pin_code[0] + 0) ^ (main::pin_code[1] + 0) ^ (main::pin_code[2] + 1) ^ (main::pin_code[3] + 3);
    return {((x1_4bit << 4) | x2_4bit) % 31 + 32,
            static_cast<u16>(1800*(main::pin_code[0] + main::pin_code[1] - main::pin_code[2] - main::pin_code[3]) + 32768),
            static_cast<u16>(1800*(main::pin_code[0] - main::pin_code[1] + main::pin_code[2] - main::pin_code[3]) + 32768) };
}

inline static lfsr_hash::salt pin_to_salt_2()
{
    using namespace lfsr_hash;
    const int x1_4bit = (main::pin_code[0] + 0) ^ (main::pin_code[1] + 0) ^ (main::pin_code[2] + 3) ^ (main::pin_code[3] + 6);
    const int x2_4bit = (main::pin_code[0] + 0) ^ (main::pin_code[1] + 3) ^ (main::pin_code[2] + 5) ^ (main::pin_code[3] + 6);
    return {((x1_4bit << 4) | x2_4bit) % 29 + 32,
            static_cast<u16>(1800*(-main::pin_code[0] - main::pin_code[1] + main::pin_code[2] + main::pin_code[3]) + 32768),
            static_cast<u16>(1800*(-main::pin_code[0] + main::pin_code[1] - main::pin_code[2] + main::pin_code[3]) + 32768) };
}

inline static lfsr_hash::salt hash_to_salt_1(lfsr_hash::u128 hash)
{
    using namespace lfsr_hash;
    return {static_cast<int>(hash.first % 31) + static_cast<int>(hash.first % 17) + 11,
            static_cast<u16>(hash.first),
            static_cast<u16>(hash.second)};
}

inline static lfsr_hash::salt hash_to_salt_2(lfsr_hash::u128 hash)
{
    using namespace lfsr_hash;
    return  {static_cast<int>(hash.first % 19) + static_cast<int>(hash.first % 31) + 13,
            static_cast<u16>(hash.first),
            static_cast<u16>(hash.second)};
}

inline static lfsr_hash::u128 pin_to_hash_1()
{
    using namespace lfsr_hash;
    const int x1_4bit = (main::pin_code[0] + 0) ^ (main::pin_code[1] + 0) ^ (main::pin_code[2] + 3) ^ (main::pin_code[3] + 6);
    const int x2_4bit = (main::pin_code[0] + 3) ^ (main::pin_code[1] + 6) ^ (main::pin_code[2] + 6) ^ (main::pin_code[3] + 6);
    uint8_t b_[64]{static_cast<uint8_t>(x1_4bit),
                   static_cast<uint8_t>(x2_4bit),
                   static_cast<uint8_t>((x1_4bit << 4) | x2_4bit),
                   static_cast<uint8_t>((x2_4bit << 4) | x1_4bit)};
    return hash128<64>(main::hash_gen, b_, pin_to_salt_1());
}

inline static lfsr_hash::u128 pin_to_hash_2() {
    using namespace lfsr_hash;
    const int x1_4bit = (main::pin_code[0] + 0) ^ (main::pin_code[1] + 0) ^ (main::pin_code[2] + 1) ^ (main::pin_code[3] + 3);
    const int x2_4bit = (main::pin_code[0] + 0) ^ (main::pin_code[1] + 3) ^ (main::pin_code[2] + 5) ^ (main::pin_code[3] + 6);
    uint8_t b_[64]{static_cast<uint8_t>(x1_4bit),
                   static_cast<uint8_t>(x2_4bit),
                   static_cast<uint8_t>((x1_4bit << 4) | x2_4bit),
                   static_cast<uint8_t>((x2_4bit << 4) | x1_4bit)};
    return hash128<64>(main::hash_gen, b_, pin_to_salt_2());
}

inline static lfsr_hash::salt pin_to_salt_3(size_t bytesRead, size_t blockSize)
{
    using namespace lfsr_hash;
    const int x1_4bit = (main::pin_code[0] + 0) ^ (main::pin_code[1] + 0) ^ (main::pin_code[2] + 1) ^ (main::pin_code[3] + 3);
    const int x2_4bit = (main::pin_code[0] + 3) ^ (main::pin_code[1] + 6) ^ (main::pin_code[2] + 6) ^ (main::pin_code[3] + 6);
    return {((x1_4bit << 4) | x2_4bit) % 31 + 32,
            static_cast<u16>(1800*(main::pin_code[0] + main::pin_code[1] - main::pin_code[2] - main::pin_code[3]) + blockSize),
            static_cast<u16>(1800*(main::pin_code[0] - main::pin_code[1] + main::pin_code[2] - main::pin_code[3]) + bytesRead) };
}

inline static lfsr_hash::salt pin_to_salt_4(size_t bytesRead, size_t blockSize)
{
    using namespace lfsr_hash;
    const int x1_4bit = (main::pin_code[0] + 0) ^ (main::pin_code[1] + 3) ^ (main::pin_code[2] + 5) ^ (main::pin_code[3] + 6);
    const int x2_4bit = (main::pin_code[0] + 3) ^ (main::pin_code[1] + 6) ^ (main::pin_code[2] + 6) ^ (main::pin_code[3] + 6);
    return {((x1_4bit << 4) | x2_4bit) % 29 + 32,
            static_cast<u16>(1800*(-main::pin_code[0] - main::pin_code[1] + main::pin_code[2] + main::pin_code[3]) + bytesRead),
            static_cast<u16>(1800*(-main::pin_code[0] + main::pin_code[1] - main::pin_code[2] + main::pin_code[3]) + blockSize) };
}

inline static lfsr_hash::salt get_salt(size_t bytesRead, size_t blockSize)
{
    using namespace lfsr_hash;
    const int x1_4bit = (0 + 0) ^ (0 + 3) ^ (0 + 5) ^ (0 + 6);
    const int x2_4bit = (0 + 3) ^ (0 + 6) ^ (0 + 6) ^ (0 + 6);
    return {((x1_4bit << 4) | x2_4bit) % 41 + 36,
            static_cast<u16>(bytesRead*2 + 11),
            static_cast<u16>(blockSize*3 + 7)};
}


inline static void init_encryption() {
    enc::aligner64 = 0;
    const int sum_of_pin = main::pin_code[0] + main::pin_code[1] + main::pin_code[2] + main::pin_code[3] + 16;
    #pragma optimize( "", off )
    for (int i = 0; i < sum_of_pin; ++i) {
        enc::gamma_gen.next_u64();
    }
    #pragma optimize( "", on )
    enc::gamma = 0;
}

inline static void finalize_encryption() {
    #pragma optimize( "", off )
    if (enc::aligner64 % sizeof(lfsr_rng::u64) != 0) {
        enc::gamma_gen.next_u64();
    }
    enc::gamma = 0;
    #pragma optimize( "", on )
}

inline static void encrypt256_inner(const QByteArray& in, QByteArray& out) {
    if (in.size() % 256 != 0) {
        qDebug() << "Encryption error: data size is not a 256*k bytes";
        return;
    }
    for (auto it = in.begin(); it != in.end(); it++) {
        if (enc_inner::aligner64 % sizeof(lfsr_rng::u64) == 0) {
            enc_inner::gamma = enc_inner::gamma_gen.next_u64();
        }
        uint8_t b = *it;
        out.push_back(char(b) ^ char(enc_inner::gamma));
        enc_inner::gamma >>= 8;
        ++enc_inner::aligner64;
    }
}

inline static void decrypt256_inner(const QByteArray& in, QByteArray& out) {
    if (in.size() % 256 != 0) {
        qDebug() << "Decryption error: data size is not a 256*k bytes";
        return;
    }
    for (auto it = in.begin(); it != in.end(); it++) {
        if (dec_inner::aligner64 % sizeof(lfsr_rng::u64) == 0) {
            dec_inner::gamma = dec_inner::gamma_gen.next_u64();
        }
        uint8_t b = *it;
        out.push_back(char(b) ^ char(dec_inner::gamma));
        dec_inner::gamma >>= 8;
        ++dec_inner::aligner64;
    }
}

inline static void encrypt(const QByteArray& in, QByteArray& out) {
    for (auto it = in.begin(); it != in.end(); it++) {
        if (enc::aligner64 % sizeof(lfsr_rng::u64) == 0) {
            enc::gamma = enc::gamma_gen.next_u64();
        }
        uint8_t b = *it;
        const int rot = enc::gamma % 8;
        b = rotr8(b, rot);
        out.push_back(char(b) ^ char(enc::gamma));
        enc::gamma >>= 8;
        ++enc::aligner64;
    }
}

inline static void init_decryption() {
    dec::aligner64 = 0;
    const int sum_of_pin = main::pin_code[0] + main::pin_code[1] + main::pin_code[2] + main::pin_code[3] + 16;
    #pragma optimize( "", off )
    for (int i = 0; i < sum_of_pin; ++i) {
        dec::gamma_gen.next_u64();
    }
    #pragma optimize( "", on )
    dec::gamma = 0;
}

inline static void finalize_decryption() {
    #pragma optimize( "", off )
    if (dec::aligner64 % sizeof(lfsr_rng::u64) != 0) {
        dec::gamma_gen.next_u64();
    }
    dec::gamma = 0;
    #pragma optimize( "", on )
}

inline static void decrypt(const QByteArray& in, QByteArray& out) {
    for (auto it = in.begin(); it != in.end(); it++) {
        if (dec::aligner64 % sizeof(lfsr_rng::u64) == 0) {
            dec::gamma = dec::gamma_gen.next_u64();
        }
        const int rot = dec::gamma % 8;
        uint8_t b = *it ^ char(dec::gamma);
        b = rotl8(b, rot);
        out.push_back(char(b));
        dec::gamma >>= 8;
        ++dec::aligner64;
    }
}

inline static void padd_256(QByteArray& data) {
    constexpr int p = 257;  // prime, modulo.
    const int n = data.size();
    const int r =  n % (p - 1) != 0 ? (p - 1) - n % (p - 1) : 0;
    int counter = 0;
    while (counter++ < r) {
        data.push_back('\0');
    }
}

inline static void dpadd_256(QByteArray& data) {
    if (data.isEmpty()) {
        return;
    }
    while (!data.isEmpty() && data.back() == '\0') {
        data.removeLast();
    }
}

inline static void encode_dlog256(const QByteArray& in, QByteArray& out) {
    constexpr int p = 257;  // prime, modulo.
    const int n = in.size();
    out.resize(n);
    const int ch = n / (p - 1);
    for (int i=0; i<ch; ++i) {
        int x = 1;
        char xor_val = in[i*(p-1)];
        for (int j=1; j<p-1; ++j) {
            xor_val ^= in[i*(p-1) + j];
        }
        const int a = const_arr::goods[((int)xor_val + 128) % std::ssize(const_arr::goods)];
        {
            int counter = 0;
            while (counter++ < (p-1)) {
                out[i*(p-1) + x - 1] = in[i*(p-1) + counter - 1];
                x *= a;
                x %= p;
            }
        }
    }
}

inline static void decode_dlog256(const QByteArray& in, QByteArray& out) {
    constexpr int p = 257;  // prime, modulo.
    const int n = in.size();
    if (n % (p - 1) != 0) {
        qDebug() << "Decode dlog256 error\n";
        return;
    }
    out.resize(n);
    const int ch = n / (p - 1);
    for (int i=0; i<ch; ++i) {
        int x = 1;
        char xor_val = in[i*(p-1)];
        for (int j=1; j<p-1; ++j) {
            xor_val ^= in[i*(p-1) + j];
        }
        const int a = const_arr::goods[((int)xor_val + 128) % std::ssize(const_arr::goods)];
        {
            int counter = 0;
            while (counter++ < (p-1)) {
                out[i*(p-1) + counter - 1] = in[i*(p-1) + x - 1];
                x *= a;
                x %= p;
            }
        }
    }
}

inline static QString Encode94(lfsr8::u32 x)
{
    constexpr int m = 5; // See the password_len_per_request.
    QString res;
    res.resize(m);
    for (int i=0; i<m; ++i) {
        auto y = x % 94;
        res[m-i-1] = (char)(y + 33);
        x -= y;
        x /= 94;
    }
    return res;
}
