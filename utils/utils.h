#pragma once

#include <array> // std::array

#include <QDebug>
#include <QFutureWatcher>
#include <qglobalstatic.h>

#include "lfsr_hash.h"
#include "key.h"
#include "constants.h"
#include "../worker.h"

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

class MyQByteArray : public QByteArray {
public:
    explicit MyQByteArray(QByteArray * parent): QByteArray(*parent) {};
    char back() const {
        return this->at(size() - 1);
    }
    char& back() {
        return operator[](size() - 1);
    }
    MyQByteArray& removeLast() {
        if (!this->isEmpty())
            this->remove(size() - 1, 1);
        return *this;
    }
    MyQByteArray& resize(int new_size, char filler = '\0') {
        if (new_size >= 0) {
            while (this->size() > new_size) {
                this->removeLast();
            }
            while (this->size() < new_size) {
                this->push_back(filler);
            }
        }
        return *this;
    }
};

struct PasswordBuffer {
    QVector<lfsr8::u64> mPasswords{};
};

struct PinCode {
    std::array<int, 4> mPinCode{};
};

namespace password {
    static inline lfsr_rng::Generators pass_gen;
    static inline lfsr_hash::gens hash_gen;
    Q_GLOBAL_STATIC( Worker, worker );
    Q_GLOBAL_STATIC( key::Key, key );
    Q_GLOBAL_STATIC(PasswordBuffer, pswd_buff);
    Q_GLOBAL_STATIC(PinCode, pin_code);
    Q_GLOBAL_STATIC(PinCode, old_pin_code);
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
    QString mPin = std::move(pin);
    using namespace password;
    pin_code->mPinCode[0] = mPin[0].digitValue();
    pin_code->mPinCode[1] = mPin[1].digitValue();
    pin_code->mPinCode[2] = mPin[2].digitValue();
    pin_code->mPinCode[3] = mPin[3].digitValue();
    #pragma optimize( "", off )
        for (auto& el : mPin) {
            el = '\0';
        }
    #pragma optimize( "", on )
}

inline static void back_up_pin() {
    using namespace password;
    old_pin_code->mPinCode = pin_code->mPinCode;
}

inline static void restore_pin() {
    using namespace password;
    pin_code->mPinCode = old_pin_code->mPinCode;
}

inline static bool check_pin(QString&& pin) {
    const QString& mPin = std::move(pin);
    using namespace password;
    bool ok = true;
    ok &= pin_code->mPinCode[0] == mPin[0].digitValue() &&
    pin_code->mPinCode[1] == mPin[1].digitValue() &&
    pin_code->mPinCode[2] == mPin[2].digitValue() &&
    pin_code->mPinCode[3] == mPin[3].digitValue();
    return ok;
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

inline static void erase_bytes(uint8_t* b, int len) {
    #pragma optimize( "", off )
        for (int i=0; i<len; ++i) {
            b[i] = 0;
        }
    #pragma optimize( "", on )
}

inline static void erase_bytes(QByteArray& b) {
#pragma optimize( "", off )
    for (int i=0; i<b.length(); ++i) {
        b[i] = '\0';
    }
#pragma optimize( "", on )
}

inline static void erase_string(QString& str) {
    #pragma optimize( "", off )
        for (auto& el : str) {
            el = '\0';
        }
    #pragma optimize( "", on )
}

inline static void clear_lfsr_hash(lfsr_hash::u128& hash) {
    #pragma optimize( "", off )
        hash.first = 0;
        hash.second = 0;
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

inline static char xor_val(const QByteArray& data) {
    char xor_val = data.isEmpty() ? '\0' : data[0];
    for (int j=1; j<data.size(); ++j) {
        xor_val ^= data[j];
    }
    return xor_val;
}

inline static QByteArray xor_bytes(const QByteArray& data_1, const QByteArray& data_2) {
    QByteArray result;
    for (int j=0; j<qMin(data_1.size(), data_2.size()); ++j) {
        result.push_back(data_1.at(j) ^ data_2.at(j));
    }
    return result;
}

inline QByteArray seed_to_bytes(uint32_t seed) {
    QByteArray result;
    for (int i=0; i<sizeof(uint32_t); ++i) {
        result.append( static_cast<char>(seed % 256) );
        seed >>= 8;
    }
    return result;
}

inline uint32_t seed_from_bytes_pop_back(QByteArray& data) {
    uint32_t seed = 0;
    if (data.size() < sizeof(uint32_t)) {
        return seed;
    }
    #if QT_VERSION < QT_VERSION_CHECK(6, 4, 0)
        MyQByteArray& data_ref = static_cast<MyQByteArray&>(data);
    #else
        QByteArray& data_ref = data;
    #endif
    for (int i=0; i<sizeof(uint32_t); ++i) {
        const auto b = static_cast<uint8_t>(data_ref.back());
        data_ref.removeLast();
        seed |= (uint32_t(b) << (8*sizeof(uint32_t) - 8 - 8*i));
    }
    return seed;
}

inline static QByteArray xor_data_by_seed(const QByteArray& data, uint32_t seed) {
    QByteArray result;
    const int r = data.size() % sizeof(uint32_t);
    const int k = data.size() / sizeof(uint32_t);
    const QByteArray seed_b = seed_to_bytes(seed);
    for (int j=0; j<k; ++j) {
        const QByteArray tmp {data.data() +  sizeof(uint32_t)*j, sizeof(uint32_t)};
        result.push_back(xor_bytes(seed_b, tmp));
    }
    for (int j=0; j<r; ++j) {
        result.push_back(data.at(k*sizeof(uint32_t) + j));
    }
    return result;
}

template <int N>
inline static void padd(QByteArray& data) {
    const int n = data.size();
    const int r =  n % N != 0 ? N - n % N : 0;
    int counter = 0;
    while (counter++ < r) {
        data.push_back('\0');
    }
}

inline static void dpadd(QByteArray& data) {
    if (data.isEmpty()) {
        return;
    }
    #if QT_VERSION < QT_VERSION_CHECK(6, 4, 0)
        MyQByteArray& data_ref = static_cast<MyQByteArray&>(data);
    #else
        QByteArray& data_ref = data;
    #endif
    while (!data_ref.isEmpty() && data_ref.back() == '\0') {
        data_ref.removeLast();
    }
}

inline static uint8_t rotl8(uint8_t value, unsigned int count)
{
    const unsigned int mask = CHAR_BIT*sizeof(value) - 1;
    count &= mask;
    return (value << count) | (value >> ( (-count) & mask ));
}

inline static uint8_t rotr8(uint8_t value, unsigned int count)
{
    const unsigned int mask = CHAR_BIT*sizeof(value) - 1;
    count &= mask;
    return (value >> count) | (value << ( (-count) & mask ));
}

inline static QString encode_u32_to_94(lfsr8::u32 sample)
{
    constexpr int num_of_symbols_per_sample = 5; // See the password_len_per_request.
    QString word(num_of_symbols_per_sample, '\0');
    for (int i=0; i<num_of_symbols_per_sample; ++i) {
        const auto code = sample % 94 + 33;
        word[num_of_symbols_per_sample-i-1] = char(code);
        sample -= code;
        sample /= 94;
    }
    return word;
}

inline static lfsr_hash::salt pin_to_salt_1()
{
    using namespace lfsr_hash;
    const auto& code = password::pin_code->mPinCode;
    const int x1_4bit = (code[0] + 0) ^ (code[1] + 0) ^ (code[2] + 3) ^ (code[3] + 6);
    const int x2_4bit = (code[0] + 0) ^ (code[1] + 0) ^ (code[2] + 1) ^ (code[3] + 3);
    return {((x1_4bit << 4) | x2_4bit) % 31 + 32,
            static_cast<u16>(1800*(code[0] + code[1] - code[2] - code[3]) + 32768),
            static_cast<u16>(1800*(code[0] - code[1] + code[2] - code[3]) + 32768) };
}

inline static lfsr_hash::salt pin_to_salt_2()
{
    using namespace lfsr_hash;
    const auto& code = password::pin_code->mPinCode;
    const int x1_4bit = (code[0] + 0) ^ (code[1] + 0) ^ (code[2] + 3) ^ (code[3] + 6);
    const int x2_4bit = (code[0] + 0) ^ (code[1] + 3) ^ (code[2] + 5) ^ (code[3] + 6);
    return {((x1_4bit << 4) | x2_4bit) % 29 + 32,
            static_cast<u16>(1800*(-code[0] - code[1] + code[2] + code[3]) + 32768),
            static_cast<u16>(1800*(-code[0] + code[1] - code[2] + code[3]) + 32768) };
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
    const auto& code = password::pin_code->mPinCode;
    const int x1_4bit = (code[0] + 0) ^ (code[1] + 0) ^ (code[2] + 3) ^ (code[3] + 6);
    const int x2_4bit = (code[0] + 3) ^ (code[1] + 6) ^ (code[2] + 6) ^ (code[3] + 6);
    uint8_t b_[64]{static_cast<uint8_t>(x1_4bit),
                   static_cast<uint8_t>(x2_4bit),
                   static_cast<uint8_t>((x1_4bit << 4) | x2_4bit),
                   static_cast<uint8_t>((x2_4bit << 4) | x1_4bit)};
    const auto hash = hash128<64>(password::hash_gen, b_, pin_to_salt_1());
    utils::erase_bytes(b_, 64);
    return hash;
}

inline static lfsr_hash::u128 pin_to_hash_2()
{
    using namespace lfsr_hash;
    const auto& code = password::pin_code->mPinCode;
    const int x1_4bit = (code[0] + 0) ^ (code[1] + 0) ^ (code[2] + 1) ^ (code[3] + 3);
    const int x2_4bit = (code[0] + 0) ^ (code[1] + 3) ^ (code[2] + 5) ^ (code[3] + 6);
    uint8_t b_[64]{static_cast<uint8_t>(x1_4bit),
                   static_cast<uint8_t>(x2_4bit),
                   static_cast<uint8_t>((x1_4bit << 4) | x2_4bit),
                   static_cast<uint8_t>((x2_4bit << 4) | x1_4bit)};
    const auto hash = hash128<64>(password::hash_gen, b_, pin_to_salt_2());
    utils::erase_bytes(b_, 64);
    return hash;
}

inline static lfsr_hash::salt pin_to_salt_3(size_t bytesRead, size_t blockSize)
{
    using namespace lfsr_hash;
    const auto& code = password::pin_code->mPinCode;
    const int x1_4bit = (code[0] + 0) ^ (code[1] + 0) ^ (code[2] + 1) ^ (code[3] + 3);
    const int x2_4bit = (code[0] + 3) ^ (code[1] + 6) ^ (code[2] + 6) ^ (code[3] + 6);
    return {((x1_4bit << 4) | x2_4bit) % 31 + 32,
            static_cast<u16>(1800*(code[0] + code[1] - code[2] - code[3]) + blockSize),
            static_cast<u16>(1800*(code[0] - code[1] + code[2] - code[3]) + bytesRead) };
}

inline static lfsr_hash::salt pin_to_salt_4(size_t bytesRead, size_t blockSize)
{
    using namespace lfsr_hash;
    const auto& code = password::pin_code->mPinCode;
    const int x1_4bit = (code[0] + 0) ^ (code[1] + 3) ^ (code[2] + 5) ^ (code[3] + 6);
    const int x2_4bit = (code[0] + 3) ^ (code[1] + 6) ^ (code[2] + 6) ^ (code[3] + 6);
    return {((x1_4bit << 4) | x2_4bit) % 29 + 32,
            static_cast<u16>(1800*(-code[0] - code[1] + code[2] + code[3]) + bytesRead),
            static_cast<u16>(1800*(-code[0] + code[1] - code[2] + code[3]) + blockSize) };
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
        #if QT_VERSION < QT_VERSION_CHECK(6, 4, 0)
            MyQByteArray& bytes_ref = static_cast<MyQByteArray&>(bytes);
        #else
            QByteArray& bytes_ref = bytes;
        #endif
        for (int i=0; i<sizeof(uint); ++i) {
            bytes_ref.push_back(static_cast<char>(seed % 256));
            seed >>= 8;
        }
        {
            const auto bytesRead = bytes_ref.size();
            const size_t res = bytesRead % blockSize;
            bytes_ref.resize(bytesRead + (res > 0 ? blockSize - res : 0), '\0'); // Zero padding.
        }
        const auto bytesRead = bytes_ref.size();
        {
            using namespace lfsr_hash;
            const salt& original_size_salt = utils::pin_to_salt_3(bytesRead, blockSize);
            const size_t n = bytesRead / blockSize;
            for (size_t i=0; i<n; ++i) {
                u128 inner_hash = hash128<blockSize>(password::hash_gen,
                                                     reinterpret_cast<const uint8_t*>(bytes_ref.data() + i*blockSize), original_size_salt);
                hash.first ^= inner_hash.first;
                hash.second ^= inner_hash.second;
            }
        }
        utils::erase_bytes(bytes_ref);
    }
    return hash;
}

inline static lfsr_hash::u128 gen_hash_for_storage(const QString& text)
{
    lfsr_hash::u128 hash_fs = utils::pin_to_hash_2();
    constexpr size_t blockSize = 64;
    {
        auto bytes = text.toUtf8();
        #if QT_VERSION < QT_VERSION_CHECK(6, 4, 0)
            MyQByteArray& bytes_ref = static_cast<MyQByteArray&>(bytes);
        #else
            QByteArray& bytes_ref = bytes;
        #endif
        {
            const auto bytesRead = bytes_ref.size();
            const size_t r = bytesRead % blockSize;
            bytes_ref.resize(bytesRead + (r > 0 ? blockSize - r : 0), '\0'); // Zero padding.
        }
        const auto bytesRead = bytes_ref.size();
        {
            using namespace lfsr_hash;
            const salt& original_size_salt = utils::pin_to_salt_4(bytesRead, blockSize);
            const size_t n = bytesRead / blockSize;
            for (size_t i=0; i<n; ++i) {
                u128 inner_hash = hash128<blockSize>(password::hash_gen,
                                                     reinterpret_cast<const uint8_t*>(bytes_ref.data() + i*blockSize), original_size_salt);
                hash_fs.first ^= inner_hash.first;
                hash_fs.second ^= inner_hash.second;
            }
        }
        utils::erase_bytes(bytes_ref);
    }
    return hash_fs;
}

inline static lfsr_hash::u128 gen_hash_for_encryption(const QString& text)
{
    lfsr_hash::u128 hash_enc = utils::pin_to_hash_1();
    constexpr size_t blockSize = 64;
    {
        auto bytes = text.toUtf8();
        #if QT_VERSION < QT_VERSION_CHECK(6, 4, 0)
            MyQByteArray& bytes_ref = static_cast<MyQByteArray&>(bytes);
        #else
            QByteArray& bytes_ref = bytes;
        #endif
        {
            const auto bytesRead = bytes_ref.size();
            const size_t r = bytesRead % blockSize;
            bytes_ref.resize(bytesRead + (r > 0 ? blockSize - r : 0), '\0'); // Zero padding.
        }
        const auto bytesRead = bytes_ref.size();
        {
            using namespace lfsr_hash;
            const salt& original_size_salt = utils::pin_to_salt_4(bytesRead, blockSize);
            const size_t n = bytesRead / blockSize;
            for (size_t i=0; i<n; ++i) {
                u128 inner_hash = hash128<blockSize>(password::hash_gen,
                                                     reinterpret_cast<const uint8_t*>(bytes_ref.data() + i*blockSize), original_size_salt);
                hash_enc.first ^= inner_hash.first;
                hash_enc.second ^= inner_hash.second;
            }
        }
        utils::erase_bytes(bytes_ref);
    }
    return hash_enc;
}

inline static lfsr_hash::u128 gen_hash_for_inner_encryption(const QString& text)
{
    lfsr_hash::u128 hash_enc_inner = utils::pin_to_hash_2();
    constexpr size_t blockSize = 64;
    {
        auto bytes = text.toUtf8();
        #if QT_VERSION < QT_VERSION_CHECK(6, 4, 0)
            MyQByteArray& bytes_ref = static_cast<MyQByteArray&>(bytes);
        #else
            QByteArray& bytes_ref = bytes;
        #endif
        {
            const auto bytesRead = bytes_ref.size();
            const size_t r = bytesRead % blockSize;
            bytes_ref.resize(bytesRead + (r > 0 ? blockSize - r : 0), '\0'); // Zero padding.
        }
        const auto bytesRead = bytes_ref.size();
        {
            using namespace lfsr_hash;
            const salt& original_size_salt = utils::pin_to_salt_3(bytesRead, blockSize);
            const size_t n = bytesRead / blockSize;
            for (size_t i=0; i<n; ++i) {
                u128 inner_hash = hash128<blockSize>(password::hash_gen,
                                                     reinterpret_cast<const uint8_t*>(bytes_ref.data() + i*blockSize), original_size_salt);
                hash_enc_inner.first ^= inner_hash.first;
                hash_enc_inner.second ^= inner_hash.second;
            }
        }
        utils::erase_bytes(bytes_ref);
    }
    return hash_enc_inner;
}

inline static QString try_to_get_password(int len)
{
    using namespace password;
    QString pswd{};
    int capacity = 2;
    lfsr8::u64 raw64;
    while (pswd.size() < len) {
        if (pswd_buff->mPasswords.empty()) {
            break;
        }
        raw64 = capacity == 2 ? pswd_buff->mPasswords.back() : raw64;
        if (capacity == 2) {
            pswd_buff->mPasswords.back() = 0;
            pswd_buff->mPasswords.pop_back();
        }
        pswd += encode_u32_to_94(raw64);
        #pragma optimize( "", off )
            capacity -= 1;
            capacity = capacity == 0 ? 2 : capacity;
            raw64 >>= 32;
        #pragma optimize( "", on )
    }
    return pswd;
}

inline static QString generate_storage_name(lfsr_hash::u128 hash)
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
    constexpr int buffer_len = 64;
    uint8_t b_[buffer_len]{};
    if (buffer_len < 2*8) {
        return "";
    }
    for (int i=0; i<8; ++i) {
        b_[2*i] = hash.first >> 8*i;
        b_[2*i + 1] = hash.second >> 8*i;
    }
    u128 hash2 = hash128<buffer_len>(hash_gen, b_, utils::hash_to_salt_1(hash));
    QString name {};
    for (int i=0; i<8; ++i) {
        name.push_back( allowed[(hash2.first >> 8*i) % 36] );
        name.push_back( allowed[(hash2.second >> 8*i) % 36] );
    }
    for (int i=0; i<8; ++i) {
        b_[16 + 2*i] = hash2.first >> 8*i;
        b_[16 + 2*i + 1] = hash2.second >> 8*i;
    }
    u128 hash3 = hash128<buffer_len>(hash_gen, b_, utils::hash_to_salt_2(hash2));
    for (int i=0; i<8; ++i) {
        name.push_back( allowed[(hash3.first >> 8*i) % 36] );
        name.push_back( allowed[(hash3.second >> 8*i) % 36] );
    }
    utils::erase_bytes(b_, buffer_len);
    return name;
}

}
