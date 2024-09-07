#pragma once

#include <array> // std::array

#include <QDebug>
#include <QFutureWatcher>
#include <qglobalstatic.h>

#include "lfsr_hash.h"
#include "storagemanager.h"
#include "worker.h"
#include "key.h"
#include "constants.h"

namespace const_arr {
    static inline constexpr int goods[] = {3, 5, 6, 7, 10, 12, 14, 19, 20, 24, 27, 28, 33, 37, 38, 39,
                             40, 41, 43, 45, 47, 48, 51, 53, 54, 55, 56, 63, 65, 66, 69, 71,
                             74, 75, 76, 77, 78, 80, 82, 83, 85, 86, 87, 90, 91, 93, 94, 96,
                             97, 101, 102, 103, 105, 106, 107, 108, 109, 110, 112, 115, 119, 125, 126, 127,
                             130, 131, 132, 138, 142, 145, 147, 148, 149, 150, 151, 152, 154, 155, 156, 160,
                             161, 163, 164, 166, 167, 170, 171, 172, 174, 175, 177, 179, 180, 181, 182, 183,
                             186, 188, 191, 192, 194, 201, 202, 203, 204, 206, 209, 210, 212, 214, 216, 217,
                             218, 219, 220, 224, 229, 230, 233, 237, 238, 243, 245, 247, 250, 251, 252, 254};
}

struct PasswordBuffer {
    QVector<lfsr8::u64> mPasswords{};
};

namespace password {
    static inline lfsr_rng::Generators pass_gen;
    static inline lfsr_hash::gens hash_gen;
    Q_GLOBAL_STATIC( Worker, worker );
    Q_GLOBAL_STATIC( key::Key, key );
    Q_GLOBAL_STATIC(PasswordBuffer, pswd_buff);
    static inline std::array<int, 4> pin_code{};
    static inline bool needToGeneratePasswords = true;
}

namespace utils {

inline static void request_passwords(QFutureWatcher<QVector<lfsr8::u64>>& watcher, int password_len) {
    const int Nw = (password_len * constants::num_of_passwords) / constants::password_len_per_request + 1;
    watcher.setFuture( password::worker->gen_n(std::ref(password::pass_gen), Nw) );
    watcher.waitForFinished();
    password::pswd_buff->mPasswords = watcher.result();
    qDebug() << "Passwords were requested.";
}

inline static void fill_pin(QString&& pin) {
    QString mPin {pin};
    password::pin_code[0] = mPin[0].digitValue();
    password::pin_code[1] = mPin[1].digitValue();
    password::pin_code[2] = mPin[2].digitValue();
    password::pin_code[3] = mPin[3].digitValue();
    #pragma optimize( "", off )
        for (auto& el : mPin) {
            el = '\0';
        }
    #pragma optimize( "", on )
}

inline static void fill_key_by_hash128(lfsr_hash::u128 hash) {
    auto x = hash.first;
    auto y = hash.second;
    {
        using password::key;
        key->set_key(x % 65536, 3);
        key->set_key((x >> 16) % 65536, 2);
        key->set_key((x >> 32) % 65536, 1);
        key->set_key((x >> 48) % 65536, 0);
        key->set_key(y % 65536, 7);
        key->set_key((y >> 16) % 65536, 6);
        key->set_key((y >> 32) % 65536, 5);
        key->set_key((y >> 48) % 65536, 4);
    }
    #pragma optimize( "", off )
    x ^= x; y ^= y;
    #pragma optimize( "", on )
}

inline static lfsr_rng::STATE fill_state_by_hash(lfsr_hash::u128 hash) {
    lfsr_rng::STATE st;
    for (int i=0; i<8; ++i) {
        lfsr_hash::u16 byte_1 = 255 & (hash.first >> 8*i);
        lfsr_hash::u16 byte_2 = 255 & (hash.second >> 8*i);
        st[i] = (byte_1 << 8) | byte_2;
    }
    return st;
}

inline static void clear_main_key() {
    #pragma optimize( "", off )
        using password::key;
        key->set_key(0, 3);
        key->set_key(0, 2);
        key->set_key(0, 1);
        key->set_key(0, 0);
        key->set_key(0, 7);
        key->set_key(0, 6);
        key->set_key(0, 5);
        key->set_key(0, 4);
    #pragma optimize( "", on )
}

inline static void clear_lfsr_rng_state(lfsr_rng::STATE& st) {
    #pragma optimize( "", off )
        st[0] = 0;
        st[1] = 0;
        st[2] = 0;
        st[3] = 0;
        st[4] = 0;
        st[5] = 0;
        st[6] = 0;
        st[7] = 0;
    #pragma optimize( "", on )
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
    using namespace password;
    const int x1_4bit = (pin_code[0] + 0) ^ (pin_code[1] + 0) ^ (pin_code[2] + 3) ^ (pin_code[3] + 6);
    const int x2_4bit = (pin_code[0] + 0) ^ (pin_code[1] + 0) ^ (pin_code[2] + 1) ^ (pin_code[3] + 3);
    return {((x1_4bit << 4) | x2_4bit) % 31 + 32,
            static_cast<u16>(1800*(pin_code[0] + pin_code[1] - pin_code[2] - pin_code[3]) + 32768),
            static_cast<u16>(1800*(pin_code[0] - pin_code[1] + pin_code[2] - pin_code[3]) + 32768) };
}

inline static lfsr_hash::salt pin_to_salt_2()
{
    using namespace lfsr_hash;
    using namespace password;
    const int x1_4bit = (pin_code[0] + 0) ^ (pin_code[1] + 0) ^ (pin_code[2] + 3) ^ (pin_code[3] + 6);
    const int x2_4bit = (pin_code[0] + 0) ^ (pin_code[1] + 3) ^ (pin_code[2] + 5) ^ (pin_code[3] + 6);
    return {((x1_4bit << 4) | x2_4bit) % 29 + 32,
            static_cast<u16>(1800*(-pin_code[0] - pin_code[1] + pin_code[2] + pin_code[3]) + 32768),
            static_cast<u16>(1800*(-pin_code[0] + pin_code[1] - pin_code[2] + pin_code[3]) + 32768) };
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
    using namespace password;
    const int x1_4bit = (pin_code[0] + 0) ^ (pin_code[1] + 0) ^ (pin_code[2] + 3) ^ (pin_code[3] + 6);
    const int x2_4bit = (pin_code[0] + 3) ^ (pin_code[1] + 6) ^ (pin_code[2] + 6) ^ (pin_code[3] + 6);
    uint8_t b_[64]{static_cast<uint8_t>(x1_4bit),
                   static_cast<uint8_t>(x2_4bit),
                   static_cast<uint8_t>((x1_4bit << 4) | x2_4bit),
                   static_cast<uint8_t>((x2_4bit << 4) | x1_4bit)};
    return hash128<64>(hash_gen, b_, pin_to_salt_1());
}

inline static lfsr_hash::u128 pin_to_hash_2()
{
    using namespace lfsr_hash;
    using namespace password;
    const int x1_4bit = (pin_code[0] + 0) ^ (pin_code[1] + 0) ^ (pin_code[2] + 1) ^ (pin_code[3] + 3);
    const int x2_4bit = (pin_code[0] + 0) ^ (pin_code[1] + 3) ^ (pin_code[2] + 5) ^ (pin_code[3] + 6);
    uint8_t b_[64]{static_cast<uint8_t>(x1_4bit),
                   static_cast<uint8_t>(x2_4bit),
                   static_cast<uint8_t>((x1_4bit << 4) | x2_4bit),
                   static_cast<uint8_t>((x2_4bit << 4) | x1_4bit)};
    return hash128<64>(hash_gen, b_, pin_to_salt_2());
}

inline static lfsr_hash::salt pin_to_salt_3(size_t bytesRead, size_t blockSize)
{
    using namespace lfsr_hash;
    using namespace password;
    const int x1_4bit = (pin_code[0] + 0) ^ (pin_code[1] + 0) ^ (pin_code[2] + 1) ^ (pin_code[3] + 3);
    const int x2_4bit = (pin_code[0] + 3) ^ (pin_code[1] + 6) ^ (pin_code[2] + 6) ^ (pin_code[3] + 6);
    return {((x1_4bit << 4) | x2_4bit) % 31 + 32,
            static_cast<u16>(1800*(pin_code[0] + pin_code[1] - pin_code[2] - pin_code[3]) + blockSize),
            static_cast<u16>(1800*(pin_code[0] - pin_code[1] + pin_code[2] - pin_code[3]) + bytesRead) };
}

inline static lfsr_hash::salt pin_to_salt_4(size_t bytesRead, size_t blockSize)
{
    using namespace lfsr_hash;
    using namespace password;
    const int x1_4bit = (pin_code[0] + 0) ^ (pin_code[1] + 3) ^ (pin_code[2] + 5) ^ (pin_code[3] + 6);
    const int x2_4bit = (pin_code[0] + 3) ^ (pin_code[1] + 6) ^ (pin_code[2] + 6) ^ (pin_code[3] + 6);
    return {((x1_4bit << 4) | x2_4bit) % 29 + 32,
            static_cast<u16>(1800*(-pin_code[0] - pin_code[1] + pin_code[2] + pin_code[3]) + bytesRead),
            static_cast<u16>(1800*(-pin_code[0] + pin_code[1] - pin_code[2] + pin_code[3]) + blockSize) };
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

inline static lfsr_hash::u128 gen_hash_for_pass_gen(const QString& text, uint seed)
{
    lfsr_hash::u128 hash = utils::pin_to_hash_1();
    constexpr size_t blockSize = 64;
    {
        auto bytes = text.toUtf8();
        while (seed != 0) {
            bytes.push_back(static_cast<char>(seed % 256));
            seed >>= 8;
        }
        {
            const auto bytesRead = bytes.size();
            const size_t r = bytesRead % blockSize;
            bytes.resize(bytesRead + (r > 0 ? blockSize - r : 0), '\0'); // Zero padding.
        }
        const auto bytesRead = bytes.size();
        {
            using namespace lfsr_hash;
            const salt& original_size_salt = utils::pin_to_salt_3(bytesRead, blockSize);
            const size_t n = bytesRead / blockSize;
            for (size_t i=0; i<n; ++i) {
                u128 inner_hash = hash128<blockSize>(password::hash_gen,
                                                     reinterpret_cast<const uint8_t*>(bytes.data() + i*blockSize), original_size_salt);
                hash.first ^= inner_hash.first;
                hash.second ^= inner_hash.second;
            }
        }
    }
    return hash;
}

inline static lfsr_hash::u128 gen_hash_for_storage(const QString& text)
{
    lfsr_hash::u128 hash_fs = utils::pin_to_hash_2();
    constexpr size_t blockSize = 64;
    {
        auto bytes = text.toUtf8();
        {
            const auto bytesRead = bytes.size();
            const size_t r = bytesRead % blockSize;
            bytes.resize(bytesRead + (r > 0 ? blockSize - r : 0), '\0'); // Zero padding.
        }
        const auto bytesRead = bytes.size();
        {
            using namespace lfsr_hash;
            const salt& original_size_salt = utils::pin_to_salt_4(bytesRead, blockSize);
            const size_t n = bytesRead / blockSize;
            for (size_t i=0; i<n; ++i) {
                u128 inner_hash = hash128<blockSize>(password::hash_gen,
                                                     reinterpret_cast<const uint8_t*>(bytes.data() + i*blockSize), original_size_salt);
                hash_fs.first ^= inner_hash.first;
                hash_fs.second ^= inner_hash.second;
            }
        }
    }
    return hash_fs;
}

inline static lfsr_hash::u128 gen_hash_for_encryption(const QString& text)
{
    lfsr_hash::u128 hash_enc = utils::pin_to_hash_1();
    constexpr size_t blockSize = 64;
    {
        auto bytes = text.toUtf8();
        {
            const auto bytesRead = bytes.size();
            const size_t r = bytesRead % blockSize;
            bytes.resize(bytesRead + (r > 0 ? blockSize - r : 0), '\0'); // Zero padding.
        }
        const auto bytesRead = bytes.size();
        {
            using namespace lfsr_hash;
            const salt& original_size_salt = utils::pin_to_salt_4(bytesRead, blockSize);
            const size_t n = bytesRead / blockSize;
            for (size_t i=0; i<n; ++i) {
                u128 inner_hash = hash128<blockSize>(password::hash_gen,
                                                     reinterpret_cast<const uint8_t*>(bytes.data() + i*blockSize), original_size_salt);
                hash_enc.first ^= inner_hash.first;
                hash_enc.second ^= inner_hash.second;
            }
        }
    }
    return hash_enc;
}

inline static lfsr_hash::u128 gen_hash_for_inner_encryption(const QString& text)
{
    lfsr_hash::u128 hash_enc_inner = utils::pin_to_hash_2();
    constexpr size_t blockSize = 64;
    {
        auto bytes = text.toUtf8();
        {
            const auto bytesRead = bytes.size();
            const size_t r = bytesRead % blockSize;
            bytes.resize(bytesRead + (r > 0 ? blockSize - r : 0), '\0'); // Zero padding.
        }
        const auto bytesRead = bytes.size();
        {
            using namespace lfsr_hash;
            const salt& original_size_salt = utils::pin_to_salt_3(bytesRead, blockSize);
            const size_t n = bytesRead / blockSize;
            for (size_t i=0; i<n; ++i) {
                u128 inner_hash = hash128<blockSize>(password::hash_gen,
                                                     reinterpret_cast<const uint8_t*>(bytes.data() + i*blockSize), original_size_salt);
                hash_enc_inner.first ^= inner_hash.first;
                hash_enc_inner.second ^= inner_hash.second;
            }
        }
    }
    return hash_enc_inner;
}

inline static void init_encryption(Encryption& enc) {
    using namespace password;
    enc.aligner64 = 0;
    const int sum_of_pin = pin_code[0] + pin_code[1] + pin_code[2] + pin_code[3] + 16;
    #pragma optimize( "", off )
    for (int i = 0; i < sum_of_pin; ++i) {
        enc.gamma_gen.next_u64();
    }
    #pragma optimize( "", on )
    enc.gamma = 0;
}

inline static void finalize_encryption(Encryption& enc) {
    #pragma optimize( "", off )
    if (enc.aligner64 % sizeof(lfsr_rng::u64) != 0) {
        enc.gamma_gen.next_u64();
    }
    enc.gamma = 0;
    #pragma optimize( "", on )
}

inline static void encrypt256_inner(const QByteArray& in, QByteArray& out, Encryption& enc) {
    if (in.size() % 256 != 0) {
        qDebug() << "Encryption error: data size is not a 256*k bytes";
        return;
    }
    for (auto it = in.begin(); it != in.end(); it++) {
        if (enc.aligner64 % sizeof(lfsr_rng::u64) == 0) {
            enc.gamma = enc.gamma_gen.next_u64();
        }
        uint8_t b = *it;
        out.push_back(char(b) ^ char(enc.gamma));
        enc.gamma >>= 8;
        ++enc.aligner64;
    }
}

inline static void decrypt256_inner(const QByteArray& in, QByteArray& out, Encryption& enc) {
    if (in.size() % 256 != 0) {
        qDebug() << "Decryption error: data size is not a 256*k bytes";
        return;
    }
    for (auto it = in.begin(); it != in.end(); it++) {
        if (enc.aligner64 % sizeof(lfsr_rng::u64) == 0) {
            enc.gamma = enc.gamma_gen.next_u64();
        }
        uint8_t b = *it;
        out.push_back(char(b) ^ char(enc.gamma));
        enc.gamma >>= 8;
        ++enc.aligner64;
    }
}

inline static void encrypt(const QByteArray& in, QByteArray& out, Encryption& enc) {
    for (auto it = in.begin(); it != in.end(); it++) {
        if (enc.aligner64 % sizeof(lfsr_rng::u64) == 0) {
            enc.gamma = enc.gamma_gen.next_u64();
        }
        uint8_t b = *it;
        const int rot = enc.gamma % 8;
        b = rotr8(b, rot);
        out.push_back(char(b) ^ char(enc.gamma));
        enc.gamma >>= 8;
        ++enc.aligner64;
    }
}

inline static void init_decryption(Encryption& enc) {
    using namespace password;
    enc.aligner64 = 0;
    const int sum_of_pin = pin_code[0] + pin_code[1] + pin_code[2] + pin_code[3] + 16;
    #pragma optimize( "", off )
    for (int i = 0; i < sum_of_pin; ++i) {
        enc.gamma_gen.next_u64();
    }
    #pragma optimize( "", on )
    enc.gamma = 0;
}

inline static void finalize_decryption(Encryption& enc) {
    #pragma optimize( "", off )
    if (enc.aligner64 % sizeof(lfsr_rng::u64) != 0) {
        enc.gamma_gen.next_u64();
    }
    enc.gamma = 0;
    #pragma optimize( "", on )
}

inline static void decrypt(const QByteArray& in, QByteArray& out, Encryption& enc) {
    for (auto it = in.begin(); it != in.end(); it++) {
        if (enc.aligner64 % sizeof(lfsr_rng::u64) == 0) {
            enc.gamma = enc.gamma_gen.next_u64();
        }
        const int rot = enc.gamma % 8;
        uint8_t b = *it ^ char(enc.gamma);
        b = rotl8(b, rot);
        out.push_back(char(b));
        enc.gamma >>= 8;
        ++enc.aligner64;
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

inline static void insert_hash128_256padd(QByteArray& bytes) {
    lfsr_hash::u128 hash = {0, 0};
    constexpr size_t blockSize = 256;
    {
        {
            const auto bytesRead = bytes.size();
            const size_t r = bytesRead % blockSize;
            bytes.resize(bytesRead + (r > 0 ? blockSize - r : 0), '\0'); // Zero padding.
        }
        const auto bytesRead = bytes.size();
        {
            using namespace lfsr_hash;
            const salt& original_size_salt = utils::get_salt(bytesRead, blockSize);
            const size_t n = bytesRead / blockSize;
            for (size_t i=0; i<n; ++i) {
                u128 inner_hash = hash128<blockSize>(password::hash_gen,
                                                     reinterpret_cast<const uint8_t*>(bytes.data() + i*blockSize), original_size_salt);
                hash.first ^= inner_hash.first;
                hash.second ^= inner_hash.second;
            }
        }
    }
    while (hash.first) {
        bytes.append(char(hash.first));
        hash.first >>= 8;
    }
    while (hash.second) {
        bytes.append(char(hash.second));
        hash.second >>= 8;
    }
}

inline static bool extract_and_check_hash128_256padd(QByteArray& bytes) {
    if (bytes.size() < 16) {
        qDebug() << "Small size while hash128 extracting: " << bytes.size();
        return false;
    }
    lfsr_hash::u128 extracted_hash = {0, 0};
    for (int i=0; i<8; ++i) {
        extracted_hash.second |= lfsr8::u64(uint8_t(bytes.back())) << (7-i)*8;
        bytes.removeLast();
    }
    for (int i=0; i<8; ++i) {
        extracted_hash.first |= lfsr8::u64(uint8_t(bytes.back())) << (7-i)*8;
        bytes.removeLast();
    }
    lfsr_hash::u128 hash = {0, 0};
    constexpr size_t blockSize = 256;
    {
        const auto bytesRead = bytes.size();
        {
            using namespace lfsr_hash;
            const salt& original_size_salt = utils::get_salt(bytesRead, blockSize);
            const size_t n = bytesRead / blockSize;
            for (size_t i=0; i<n; ++i) {
                u128 inner_hash = hash128<blockSize>(password::hash_gen,
                                                     reinterpret_cast<const uint8_t*>(bytes.data() + i*blockSize), original_size_salt);
                hash.first ^= inner_hash.first;
                hash.second ^= inner_hash.second;
            }
        }
    }
    while (!bytes.isEmpty() && bytes.back() == '\0') {
        bytes.removeLast();
    }
    return extracted_hash == hash;
}

inline static QString GetPassword(int len)
{
    using namespace password;
    QString pswd{};
    int capacity = 2;
    lfsr8::u64 raw64;
    while (pswd.size() < len) {
        if (pswd_buff->mPasswords.empty()) {
            break;
        }
    #pragma optimize( "", off )
        raw64 = capacity == 2 ? pswd_buff->mPasswords.back() : raw64;
        if (capacity == 2) {
            pswd_buff->mPasswords.back() = 0;
            pswd_buff->mPasswords.pop_back();
        }
        pswd += Encode94(raw64);
        capacity -= 1;
        capacity = capacity == 0 ? 2 : capacity;
        raw64 >>= 32;
    #pragma optimize( "", on )
    }
    return pswd;
}

inline static QString GenerateStorageName(lfsr_hash::u128 hash)
{
    using namespace lfsr_hash;
    using namespace password;
    static constexpr auto allowed {"0123456789abcdefghijklmnopqrstuvwxyz"};
    const int allowed_len = std::strlen(allowed);
    if (allowed_len < 36) {
        qDebug() << "Allowed alphabet is small.";
        return "";
    }
    if (allowed_len > 36) {
        qDebug() << "Allowed alphabet is big.";
        return "";
    }
    uint8_t b_[64]{};
    for (int i=0; i<8; ++i) {
        b_[2*i] = hash.first >> 8*i;
        b_[2*i + 1] = hash.second >> 8*i;
    }
    u128 hash2 = hash128<64>(hash_gen, b_, utils::hash_to_salt_1(hash));
    QString name {};
    for (int i=0; i<8; ++i) {
        name.push_back( allowed[(hash2.first >> 8*i) % 36] );
        name.push_back( allowed[(hash2.second >> 8*i) % 36] );
    }
    for (int i=0; i<8; ++i) {
        b_[16 + 2*i] = hash2.first >> 8*i;
        b_[16 + 2*i + 1] = hash2.second >> 8*i;
    }
    u128 hash3 = hash128<64>(hash_gen, b_, utils::hash_to_salt_2(hash2));
    for (int i=0; i<8; ++i) {
        name.push_back( allowed[(hash3.first >> 8*i) % 36] );
        name.push_back( allowed[(hash3.second >> 8*i) % 36] );
    }
    return name;
}

}
