#include "storagemanager.h"
#include "utils.h"
#include "constants.h"

#ifdef __unix__
    #undef OS_Windows
#elif defined(_WIN32) || defined(WIN32)
    #define OS_Windows
    #include <windows.h>
#endif

#include <QTableWidget>
#include <QFile>
#include <QMessageBox>
#include <QSet>

#if QT_VERSION >= QT_VERSION_CHECK(6, 6, 0)
    #include <QStringEncoder>
#endif

#include <random> // std::random_device

static const QSet<QString> g_supported_as_version_1 {
                        QString("v1.00"),
                        QString("v1.01")
                    };

static const QSet<QString> g_supported_as_version_2 {
    QString("v1.02"),
    QString("v1.03"),
    QString("v1.04")
};

static const QSet<QString> g_supported_as_version_3 {
    QString("v1.05"),
    QString("v1.06"),
    QString("v1.07"),
    QString("v1.08")
};

#ifdef OS_Windows
    static void do_hidden(wchar_t* fileLPCWSTR) {
        int attr = GetFileAttributes(fileLPCWSTR);
        if ((attr & FILE_ATTRIBUTE_HIDDEN) == 0) {
            SetFileAttributes(fileLPCWSTR, attr | FILE_ATTRIBUTE_HIDDEN);
        }
    }
#endif

namespace api_v1 {

template <int basic_modulo, int swap_modulo, bool initial_swap, int initial_s0>
static char core_crc(const QByteArray& data, int initial_crc='\0') {
    char crc = initial_crc;
    const int N = data.size() + 1;
    bool current_swap = initial_swap;
    int sequence = initial_s0;
    for (int i=1; i<N; i++) {
        const bool doit = current_swap ? i % basic_modulo != 0 : i % basic_modulo == 0;
        sequence = doit ? (sequence % basic_modulo) + ((sequence % basic_modulo) % 2) + 1 : sequence + 2;
        char mul = doit ? sequence : 0;
        crc ^= mul * data.at(i-1);
        if constexpr (swap_modulo > 0) {
            current_swap ^= i % swap_modulo == 0;
        }
    }
    return crc;
};

static QByteArray encode_crc(const QByteArray& data) {
    QByteArray out_crc;
    {
        char crc1 = '\0';
        for (const auto b : std::as_const(data)) {
            crc1 ^= b;
        }
        out_crc.push_back(crc1);
        char crc2 = core_crc<11, 16, false, 13>(data);
        out_crc.push_back(crc2);
        char crc8 = core_crc<41, 205, false, 13>(data);
        out_crc.push_back(crc8);
        char crc16 = core_crc<17, 7, false, 13>(data);
        out_crc.push_back(crc16);
    }
    {
        char crc2 = core_crc<11, 16, true, 13>(data);
        out_crc.push_back(crc2);
        char crc8 = core_crc<41, 205, true, 13>(data);
        out_crc.push_back(crc8);
        char crc16 = core_crc<17, 7, true, 13>(data);
        out_crc.push_back(crc16);
    }
    return out_crc;
}

static bool decode_crc(const QByteArray& data, QByteArray& crc) {
    if (crc.size() != 7) {
        return false;
    }
    #if QT_VERSION < QT_VERSION_CHECK(6, 5, 0)
        MyQByteArray& crc_ref = static_cast<MyQByteArray&>(crc);
    #else
        QByteArray& crc_ref = crc;
    #endif
    {
        char crc16 = core_crc<17, 7, true, 13>(data, crc_ref.back());
        crc_ref.removeLast();
        char crc8 = core_crc<41, 205, true, 13>(data, crc_ref.back());
        crc_ref.removeLast();
        char crc2 = core_crc<11, 16, true, 13>(data, crc_ref.back());
        crc_ref.removeLast();
        if (crc16 != '\0' || crc8 != '\0' || crc2 != '\0')
        {
            return false;
        }
    }
    {
        char crc16 = core_crc<17, 7, false, 13>(data, crc_ref.back());
        crc_ref.removeLast();
        char crc8 = core_crc<41, 205, false, 13>(data, crc_ref.back());
        crc_ref.removeLast();
        char crc2 = core_crc<11, 16, false, 13>(data, crc_ref.back());
        crc_ref.removeLast();
        char crc1 = crc_ref.back();
        crc_ref.removeLast();
        for (const auto b : std::as_const(data)) {
            crc1 ^= b;
        }
        if (crc16 != '\0' || crc8 != '\0' || crc2 != '\0' || crc1 != '\0')
        {
            return false;
        }
    }
    return true;
}

static void init_encryption(Encryption& enc, const QByteArray& salt1 = {}, uint salt2 = 0) {
    enc.aligner64 = 0;
    assert(enc.counter == 0);
    const int steps = 256 + (int)utils::xor_val(salt1) + (salt2 % 65536);
    for (int i = 0; i < steps; ++i) {
        enc.gamma_gen.next_u64();
        enc.counter++;
    }
    enc.gamma = 0;
}

static void finalize_encryption(Encryption& enc) {
    while (enc.counter != 0) {
        enc.gamma_gen.back_u64();
        enc.counter--;
    }
    enc.gamma = 0;
}

static void encrypt256_inner(const QByteArray& in, QByteArray& out, Encryption& enc) {
    if (in.size() % 256 != 0) {
        qDebug() << "Encryption error: data size is not a 256*k bytes";
        return;
    }
    for (auto it = in.begin(); it != in.end(); it++) {
        if (enc.aligner64 % sizeof(lfsr_rng::u64) == 0) {
            enc.gamma = enc.gamma_gen.next_u64();
            enc.counter++;
        }
        uint8_t b = *it;
        out.push_back(char(b) ^ char(enc.gamma));
        enc.gamma >>= CHAR_BIT;
        ++enc.aligner64;
    }
}

static void decrypt256_inner(const QByteArray& in, QByteArray& out, Encryption& dec) {
    if (in.size() % 256 != 0) {
        qDebug() << "Inner decryption error: data size is not a 256*k bytes";
        return;
    }
    for (auto it = in.begin(); it != in.end(); it++) {
        if (dec.aligner64 % sizeof(lfsr_rng::u64) == 0) {
            dec.gamma = dec.gamma_gen.next_u64();
            dec.counter++;
        }
        uint8_t b = *it;
        out.push_back(char(b) ^ char(dec.gamma));
        dec.gamma >>= CHAR_BIT;
        ++dec.aligner64;
    }
}

static void encrypt(const QByteArray& in, QByteArray& out, Encryption& enc) {
    for (auto it = in.begin(); it != in.end(); it++) {
        if (enc.aligner64 % sizeof(lfsr_rng::u64) == 0) {
            enc.gamma = enc.gamma_gen.next_u64();
            enc.counter++;
        }
        uint8_t b = *it;
        const int rot = enc.gamma % CHAR_BIT;
        b = utils::rotr8(b, rot);
        out.push_back(char(b) ^ char(enc.gamma));
        enc.gamma >>= CHAR_BIT;
        ++enc.aligner64;
    }
}

static void decrypt(const QByteArray& in, QByteArray& out, Encryption& dec) {
    for (auto it = in.begin(); it != in.end(); it++) {
        if (dec.aligner64 % sizeof(lfsr_rng::u64) == 0) {
            dec.gamma = dec.gamma_gen.next_u64();
            dec.counter++;
        }
        const int rot = dec.gamma % CHAR_BIT;
        uint8_t b = *it ^ char(dec.gamma);
        b = utils::rotl8(b, rot);
        out.push_back(char(b));
        dec.gamma >>= CHAR_BIT;
        ++dec.aligner64;
    }
}

static void encode_dlog256(const QByteArray& in, QByteArray& out) {
    constexpr int p = 257;  // prime, modulo.
    const int n = in.size();
    out.resize(n);
    const int ch = n / (p - 1);
    for (int i=0; i<ch; ++i) {
        char xor_val = in[i*(p-1)];
        for (int j=1; j<p-1; ++j) {
            xor_val ^= in[i*(p-1) + j];
        }
        const int a = const_arr::goods[((int)xor_val - std::numeric_limits<char>::min()) % std::ssize(const_arr::goods)];
        int x = a;
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

static void decode_dlog256(const QByteArray& in, QByteArray& out) {
    constexpr int p = 257;  // prime, modulo.
    const int n = in.size();
    if (n % (p - 1) != 0) {
        qDebug() << "Decode dlog256 error\n";
        return;
    }
    out.resize(n);
    const int ch = n / (p - 1);
    for (int i=0; i<ch; ++i) {
        char xor_val = in[i*(p-1)];
        for (int j=1; j<p-1; ++j) {
            xor_val ^= in[i*(p-1) + j];
        }
        const int a = const_arr::goods[((int)xor_val - std::numeric_limits<char>::min()) % std::ssize(const_arr::goods)];
        int x = a;
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

static void insert_hash128(QByteArray& bytes) {
    if (bytes.size() % 128 != 0) {
        qDebug() << "Insert hash128 error: input size is not a 128*k bytes: " << bytes.size();
        return;
    }
    lfsr_hash::u128 hash = {0, 0};
    constexpr size_t blockSize = 128;
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
    const int num_of_bytes = sizeof(hash.first);
    for (int i=0; i<num_of_bytes; ++i) {
        bytes.append(char(hash.first));
        hash.first >>= CHAR_BIT;
    }
    for (int i=0; i<num_of_bytes; ++i) {
        bytes.append(char(hash.second));
        hash.second >>= CHAR_BIT;
    }
}

static bool extract_and_check_hash128(QByteArray& bytes) {
    #if QT_VERSION < QT_VERSION_CHECK(6, 5, 0)
        MyQByteArray& bytes_ref = static_cast<MyQByteArray&>(bytes);
    #else
        QByteArray& bytes_ref = bytes;
    #endif
    if (bytes.size() % 16 != 0) {
        qDebug() << "Extract hash128 error: input size is not a 16*k bytes: " << bytes.size();
        return false;
    }
    lfsr_hash::u128 extracted_hash = {0, 0};
    const int num_of_bytes = sizeof(extracted_hash.first);
    if (bytes.size() < 2*num_of_bytes) {
        qDebug() << "Small size while hash128 extracting: " << bytes.size();
        return false;
    }
    for (int i=0; i<num_of_bytes; ++i) {
        extracted_hash.second |= lfsr8::u64(uint8_t(bytes_ref.back())) << (num_of_bytes-1-i)*CHAR_BIT;
        bytes_ref.removeLast();
    }
    for (int i=0; i<num_of_bytes; ++i) {
        extracted_hash.first |= lfsr8::u64(uint8_t(bytes_ref.back())) << (num_of_bytes-1-i)*CHAR_BIT;
        bytes_ref.removeLast();
    }
    lfsr_hash::u128 calculated_hash = {0, 0};
    constexpr size_t blockSize = 128;
    {
        const auto bytesRead = bytes.size();
        {
            using namespace lfsr_hash;
            const salt& original_size_salt = utils::get_salt(bytesRead, blockSize);
            const size_t n = bytesRead / blockSize;
            for (size_t i=0; i<n; ++i) {
                u128 inner_hash = hash128<blockSize>(password::hash_gen,
                                                     reinterpret_cast<const uint8_t*>(bytes.data() + i*blockSize), original_size_salt);
                calculated_hash.first ^= inner_hash.first;
                calculated_hash.second ^= inner_hash.second;
            }
        }
    }
    return extracted_hash == calculated_hash;
}

} // api_v1.

namespace api_v2 {

template <int basic_modulo, int swap_modulo, bool initial_swap, int initial_s0=0>
static char core_crc(const QByteArray& data, int initial_crc='\0') {
    char crc = initial_crc;
    const int N = data.size() + 1;
    bool current_swap = initial_swap;
    int sequence = initial_s0;
    for (int i=1; i<N; i++) {
        const bool doit = current_swap ? i % basic_modulo != 0 : i % basic_modulo == 0;
        sequence = doit ? (sequence % basic_modulo) + 1 : sequence + 1;
        char mul = doit ? sequence : 0;
        crc ^= mul * data.at(i-1);
        if constexpr (swap_modulo > 0) {
            current_swap ^= i % swap_modulo == 0;
        }
    }
    return crc;
};

static constexpr std::array<int, 6> params {237, 234, 55, 1, 124, 75};
static QByteArray encode_crc(const QByteArray& data) {
    QByteArray out_crc;
    {
        char crc1 = '\0';
        for (const auto b : std::as_const(data)) {
            crc1 ^= b;
        }
        out_crc.push_back(crc1);
        char crc2 = core_crc<params[0], params[3], false>(data);
        out_crc.push_back(crc2);
        char crc8 = core_crc<params[1], params[4], false>(data);
        out_crc.push_back(crc8);
        char crc16 = core_crc<params[2], params[5], false>(data);
        out_crc.push_back(crc16);
    }
    {
        char crc2 = core_crc<params[0], params[3], true>(data);
        out_crc.push_back(crc2);
        char crc8 = core_crc<params[1], params[4], true>(data);
        out_crc.push_back(crc8);
        char crc16 = core_crc<params[2], params[5], true>(data);
        out_crc.push_back(crc16);
    }
    return out_crc;
}

static bool decode_crc(const QByteArray& data, QByteArray& crc) {
    if (crc.size() != 7) {
        return false;
    }
    #if QT_VERSION < QT_VERSION_CHECK(6, 5, 0)
        MyQByteArray& crc_ref = static_cast<MyQByteArray&>(crc);
    #else
        QByteArray& crc_ref = crc;
    #endif
    {
        char crc16 = core_crc<params[2], params[5], true>(data, crc_ref.back());
        crc_ref.removeLast();
        char crc8 = core_crc<params[1], params[4], true>(data, crc_ref.back());
        crc_ref.removeLast();
        char crc2 = core_crc<params[0], params[3], true>(data, crc_ref.back());
        crc_ref.removeLast();
        if (crc16 != '\0' || crc8 != '\0' || crc2 != '\0')
        {
            return false;
        }
    }
    {
        char crc16 = core_crc<params[2], params[5], false>(data, crc_ref.back());
        crc_ref.removeLast();
        char crc8 = core_crc<params[1], params[4], false>(data, crc_ref.back());
        crc_ref.removeLast();
        char crc2 = core_crc<params[0], params[3], false>(data, crc_ref.back());
        crc_ref.removeLast();
        char crc1 = crc_ref.back();
        crc_ref.removeLast();
        for (const auto b : std::as_const(data)) {
            crc1 ^= b;
        }
        if (crc16 != '\0' || crc8 != '\0' || crc2 != '\0' || crc1 != '\0')
        {
            return false;
        }
    }
    return true;
}

using namespace api_v1;

} // api_v2.

namespace api_v3 {

static constexpr std::array<int, 16> params {119, 15, 20, 65, 140, 106, 74, 41, 208, 1, 119, 20, 201, 109, 26, 203};
static QByteArray encode_crc(const QByteArray& data) {
    QByteArray out_crc;
    {
        char crc1 = '\0';
        for (const auto b : std::as_const(data)) {
            crc1 ^= b;
        }
        out_crc.push_back(crc1);
        char crc2 = api_v2::core_crc<params[0], params[4], false, 10>(data);
        out_crc.push_back(crc2);
        char crc8 = api_v2::core_crc<params[1], params[5], false, 10>(data);
        out_crc.push_back(crc8);
        char crc16 = api_v2::core_crc<params[2], params[6], false, 10>(data);
        out_crc.push_back(crc16);
        char crc32 = api_v2::core_crc<params[3], params[7], false, 10>(data);
        out_crc.push_back(crc32);
        char crc64 = api_v2::core_crc<params[0], params[4], true, 10>(data);
        out_crc.push_back(crc64);
        char crc128 = api_v2::core_crc<params[1], params[5], true, 10>(data);
        out_crc.push_back(crc128);
        char crc256 = api_v2::core_crc<params[2], params[6], true, 10>(data);
        out_crc.push_back(crc256);
        char crc512 = api_v2::core_crc<params[3], params[7], true, 10>(data);
        out_crc.push_back(crc512);
    }
    {
        char crc2 = api_v2::core_crc<params[8], params[12], false, 61>(data);
        out_crc.push_back(crc2);
        char crc8 = api_v2::core_crc<params[9], params[13], false, 61>(data);
        out_crc.push_back(crc8);
        char crc16 = api_v2::core_crc<params[10], params[14], false, 61>(data);
        out_crc.push_back(crc16);
        char crc32 = api_v2::core_crc<params[11], params[15], false, 61>(data);
        out_crc.push_back(crc32);
        char crc64 = api_v2::core_crc<params[8], params[12], true, 61>(data);
        out_crc.push_back(crc64);
        char crc128 = api_v2::core_crc<params[9], params[13], true, 61>(data);
        out_crc.push_back(crc128);
        char crc256 = api_v2::core_crc<params[10], params[14], true, 61>(data);
        out_crc.push_back(crc256);
        char crc512 = api_v2::core_crc<params[11], params[15], true, 61>(data);
        out_crc.push_back(crc512);
    }
    return out_crc;
}

static bool decode_crc(const QByteArray& data, QByteArray& crc) {
    if (crc.size() != 17) {
        return false;
    }
    #if QT_VERSION < QT_VERSION_CHECK(6, 5, 0)
        MyQByteArray& crc_ref = static_cast<MyQByteArray&>(crc);
    #else
        QByteArray& crc_ref = crc;
    #endif
    {
        char crc512 = api_v2::core_crc<params[11], params[15], true, 61>(data, crc_ref.back());
        crc_ref.removeLast();
        char crc256 = api_v2::core_crc<params[10], params[14], true, 61>(data, crc_ref.back());
        crc_ref.removeLast();
        char crc128 = api_v2::core_crc<params[9], params[13], true, 61>(data, crc_ref.back());
        crc_ref.removeLast();
        char crc64 = api_v2::core_crc<params[8], params[12], true, 61>(data, crc_ref.back());
        crc_ref.removeLast();
        char crc32 = api_v2::core_crc<params[11], params[15], false, 61>(data, crc_ref.back());
        crc_ref.removeLast();
        char crc16 = api_v2::core_crc<params[10], params[14], false, 61>(data, crc_ref.back());
        crc_ref.removeLast();
        char crc8 = api_v2::core_crc<params[9], params[13], false, 61>(data, crc_ref.back());
        crc_ref.removeLast();
        char crc2 = api_v2::core_crc<params[8], params[12], false, 61>(data, crc_ref.back());
        crc_ref.removeLast();
        if (crc512 != '\0' || crc256 != '\0' || crc128 != '\0' || crc64 != '\0' \
            || crc32 != '\0' || crc16 != '\0' || crc8 != '\0' || crc2 != '\0')
        {
            return false;
        }
    }
    {
        char crc512 = api_v2::core_crc<params[3], params[7], true, 10>(data, crc_ref.back());
        crc_ref.removeLast();
        char crc256 = api_v2::core_crc<params[2], params[6], true, 10>(data, crc_ref.back());
        crc_ref.removeLast();
        char crc128 = api_v2::core_crc<params[1], params[5], true, 10>(data, crc_ref.back());
        crc_ref.removeLast();
        char crc64 = api_v2::core_crc<params[0], params[4], true, 10>(data, crc_ref.back());
        crc_ref.removeLast();
        char crc32 = api_v2::core_crc<params[3], params[7], false, 10>(data, crc_ref.back());
        crc_ref.removeLast();
        char crc16 = api_v2::core_crc<params[2], params[6], false, 10>(data, crc_ref.back());
        crc_ref.removeLast();
        char crc8 = api_v2::core_crc<params[1], params[5], false, 10>(data, crc_ref.back());
        crc_ref.removeLast();
        char crc2 = api_v2::core_crc<params[0], params[4], false, 10>(data, crc_ref.back());
        crc_ref.removeLast();
        char crc1 = crc_ref.back();
        crc_ref.removeLast();
        for (const auto b : std::as_const(data)) {
            crc1 ^= b;
        }
        if (crc512 != '\0' || crc256 != '\0' || crc128 != '\0' || crc64 != '\0' || crc32 != '\0' || \
            crc16 != '\0' || crc8 != '\0' || crc2 != '\0' || crc1 != '\0')
        {
            return false;
        }
    }
    return true;
}

using namespace api_v2;
} // api_v3.


StorageManager::StorageManager() {}

template <int version>
QByteArray do_encode(QByteArray& encoded_string, Encryption& enc, Encryption& enc_inner) {
    QByteArray out;
    #define my_encode(ns, K, R) \
    ns::init_encryption(enc); \
    utils::padd<K>(encoded_string); \
    const int N = encoded_string.length(); \
    const int Q = N / K; \
    QByteArray crc; \
    const auto it = encoded_string.cbegin(); \
    for (int q=0; q<Q; ++q) { QByteArray in(it + q*K, K); crc.append(ns::encode_crc(in)); } \
    encoded_string.append(crc); \
    if (encoded_string.length() % (K + R) != 0) { \
        qDebug() << "CRC encode failure: output size is not a multpile of " << \
            (K+R) << " : " << encoded_string.size() << \
            ", Q: " << Q; \
        ns::finalize_encryption(enc); \
        return {}; \
    } \
    uint32_t seed2 = 0; \
    if constexpr (version >= 3) { \
        seed2 = std::random_device{}(); \
    } \
    ns::init_encryption(enc_inner, crc, seed2); \
    QByteArray encrypted_inner; \
    ns::encrypt256_inner(encoded_string, encrypted_inner, enc_inner); \
    QByteArray permuted; \
    ns::encode_dlog256(encrypted_inner, permuted); \
    ns::insert_hash128(permuted); \
    crc = utils::xor_data_by_seed(crc, seed2); \
    permuted.append(crc); \
    if constexpr (version >= 3) { \
        QByteArray seed_b = utils::seed_to_bytes(seed2); \
        permuted.append(seed_b); \
    } \
    ns::encrypt(permuted, out, enc); \
    ns::finalize_encryption(enc); \
    ns::finalize_encryption(enc_inner);

    if constexpr (version == 1) {
        my_encode(api_v1, (256-7), 7);
    }
    if constexpr (version == 2) {
        my_encode(api_v2, (256-7), 7);
    }
    if constexpr (version == 3) {
        my_encode(api_v3, (256-17), 17);
    }
    return out;
}

template <int version>
QByteArray do_decode(QByteArray& data, Encryption& dec, Encryption& dec_inner) {
    QByteArray decoded_data;
    #define my_decode(ns, K, R) \
    constexpr int hash_size = 16; \
    ns::init_encryption(dec); \
    QByteArray decrypted; \
    ns::decrypt(data, decrypted, dec); \
    uint32_t seed2 = 0; \
    if constexpr (version >= 3) { \
    if (decrypted.size() < static_cast<int>(sizeof(seed2))) { \
            qDebug() << "Decode failure: input size is too small: " << \
                                                              decrypted.size(); \
            ns::finalize_encryption(dec); \
            return {}; \
        } \
        seed2 = utils::seed_from_bytes_pop_back(decrypted); \
    } \
    const int Q = (decrypted.size() - hash_size) / (K + 2*R); \
    const int Res = (decrypted.size() - hash_size) % (K + 2*R); \
    if (Res != 0) { \
        qDebug() << "CRC decode failure: input size is not a multiple of " << \
            (K + 2*R) << " : " << decrypted.size() << \
            ", Q: " << Q; \
        ns::finalize_encryption(dec); \
        return {}; \
    } \
    QByteArray crc; \
    MyQByteArray& decrypted_ref = static_cast<MyQByteArray&>(decrypted); \
    for (int q=0; q<Q; ++q) { \
        for (int i=0; i<R; ++i) {crc.push_back(decrypted_ref.back()); decrypted_ref.removeLast();}; \
    } \
    std::reverse(crc.begin(), crc.end()); \
    if (!ns::extract_and_check_hash128(decrypted)) { \
        ns::finalize_encryption(dec); \
        return {}; \
    } \
    crc = utils::xor_data_by_seed(crc, seed2); \
    QByteArray depermuted; \
    ns::decode_dlog256(decrypted, depermuted); \
    ns::init_encryption(dec_inner, crc, seed2); \
    ns::decrypt256_inner(depermuted, decoded_data, dec_inner); \
    QByteArray crc_copy; \
    MyQByteArray& decoded_ref = static_cast<MyQByteArray&>(decoded_data); \
    for (int q=0; q<Q; ++q) { \
        for (int i=0; i<R; ++i) {crc_copy.push_back(decoded_ref.back()); decoded_ref.removeLast();}; \
    } \
    std::reverse(crc_copy.begin(), crc_copy.end()); \
    if (crc != crc_copy) { \
        qDebug() << "CRC decode failure: crc != crc_copy."; \
        ns::finalize_encryption(dec); \
        ns::finalize_encryption(dec_inner); \
        return {}; \
    } \
    auto it = decoded_data.cbegin(); \
    auto it_crc = crc_copy.cbegin(); \
    for (int q=0; q<Q; ++q) { \
        const QByteArray in(it + q*K, K); \
        QByteArray crc_(it_crc + q*R, R); \
        if (!ns::decode_crc(in, crc_)) { \
            qDebug() << "CRC: storage data failure, q: " << q; \
            ns::finalize_encryption(dec); \
            ns::finalize_encryption(dec_inner); \
            return {}; \
        } \
    } \
    utils::dpadd(decoded_data); \
    ns::finalize_encryption(dec); \
    ns::finalize_encryption(dec_inner);

    if constexpr (version == 1) {
        my_decode(api_v1, (256-7), 7);
    }
    if constexpr (version == 2) {
        my_decode(api_v2, (256-7), 7);
    }
    if constexpr (version == 3) {
        my_decode(api_v3, (256-17), 17);
    }
    return decoded_data;
}

void StorageManager::SaveToStorage(const QTableWidget* const ro_table, bool save_to_tmp )
{
    const QString& file_name = save_to_tmp ? mStorageNameTmp : mStorageName;
    if (file_name.isEmpty()) {
        qDebug() << "Empty storage.";
        return;
    }
    if (!mEnc.gamma_gen.is_succes()) {
        qDebug() << "Empty encryption.";
        return;
    }
    if (!mEncInner.gamma_gen.is_succes()) {
        qDebug() << "Empty inner encryption.";
        return;
    }
    QByteArray packed_data_bytes;
    #if QT_VERSION >= QT_VERSION_CHECK(6, 6, 0)
        auto fromUtf16 = QStringEncoder(QStringEncoder::Utf8);
    #endif
    QString packed_data_str;
    for( int row = 0; row < ro_table->rowCount(); ++row )
    {
        QStringList data_rows;
        for( int col = 0; col < ro_table->columnCount(); ++col )
        {
            if (ro_table->item(row, col)) {
                if (col != constants::pswd_column_idx) {
                    const auto& txt = ro_table->item(row, col)->text();
                    data_rows << (txt == "" ? symbols::empty_item : txt);
                } else {
                    data_rows << ro_table->item(row, col)->data(Qt::UserRole).toString();
                }
            } else {
                data_rows << symbols::empty_item;
            }
        }
        packed_data_str = data_rows.join( symbols::row_delimiter );
        if (row < ro_table->rowCount() - 1) {
            packed_data_str.append( symbols::col_delimiter );
            #if QT_VERSION >= QT_VERSION_CHECK(6, 6, 0)
                packed_data_bytes.append( fromUtf16( packed_data_str ) );
            #else
                packed_data_bytes.append( packed_data_str.toUtf8() );
            #endif
        }
    }
    { // Конец сообщения.
        packed_data_str.append( symbols::end_message );
        #if QT_VERSION >= QT_VERSION_CHECK(6, 6, 0)
            packed_data_bytes.append( fromUtf16( packed_data_str ) );
        #else
            packed_data_bytes.append( packed_data_str.toUtf8() );
        #endif
    }
    QByteArray encoded_data_bytes;
    QFile file(file_name);
    QString current_version = QString::fromUtf8(VERSION_LABEL);
    current_version.remove(g_version_prefix);
    if (g_supported_as_version_1.contains(current_version)) {
        encoded_data_bytes = do_encode<1>(packed_data_bytes, mEnc, mEncInner);
    }
    else if (g_supported_as_version_2.contains(current_version)) {
        encoded_data_bytes = do_encode<2>(packed_data_bytes, mEnc, mEncInner);
    }
    else if (g_supported_as_version_3.contains(current_version)) {
        encoded_data_bytes = do_encode<3>(packed_data_bytes, mEnc, mEncInner);
    }
    if (encoded_data_bytes.isEmpty()) {
        return;
    }
    encoded_data_bytes.append(VERSION_LABEL);
    utils::padd<128>(encoded_data_bytes);
    if (file.open(QFile::WriteOnly))
    {
        file.write(encoded_data_bytes);
        file.close();
        if (save_to_tmp) {
            return;
        }
        QFile file_backup(mStorageNameBackUp);
        if (file_backup.open(QFile::WriteOnly)) {
            file_backup.write(encoded_data_bytes);
            file_backup.close();
            #ifdef OS_Windows
                do_hidden(file_backup.fileName().toStdWString().data());
            #endif
            qDebug() << "Make backup: " << mStorageNameBackUp;
        }
    } else {
        if (save_to_tmp) {
            return;
        }
        QFile file_backup(mStorageNameBackUp);
        if (file_backup.open(QFile::WriteOnly)) {
            file_backup.write(encoded_data_bytes);
            file_backup.close();
            #ifdef OS_Windows
                do_hidden(file_backup.fileName().toStdWString().data());
            #endif
            qDebug() << "Make backup only: " << mStorageNameBackUp;
        } else {
            QMessageBox mb;
            mb.critical(nullptr, QString::fromUtf8("Ошибка сохранения."),
                        QString::fromUtf8("Файловая ошибка сохранения таблицы в хранилище."));
        }
    }
}

Loading_Errors StorageManager::LoadFromStorage(QTableWidget * const wr_table, FileTypes type)
{
    const auto& file_name = [this, type]() -> QString {
        switch (type) {
        case FileTypes::BACKUP:
            return mStorageNameBackUp;
            break;
        case FileTypes::TEMPORARY:
            return mStorageNameTmp;
            break;
        default:
            return mStorageName;
            break;
        }
    }();
    if (file_name.isEmpty()) {
        qDebug() << "Empty storage.";
        return Loading_Errors::EMPTY_STORAGE;
    }
    if (!mDec.gamma_gen.is_succes()) {
        qDebug() << "Empty decryption.";
        return Loading_Errors::EMPTY_ENCRYPTION;
    }
    if (!mDecInner.gamma_gen.is_succes()) {
        qDebug() << "Empty inner decryption.";
        return Loading_Errors::EMPTY_ENCRYPTION;
    }
    if (wr_table->rowCount() > 0) {
        qDebug() << "Table is not empty.";
        return Loading_Errors::TABLE_IS_NOT_EMPTY;
    }
    QFile file(file_name);
    QByteArray decoded_data_bytes;
    if (file.open(QFile::ReadOnly))
    {
        QByteArray raw_data = file.readAll();
        file.close();
        utils::dpadd(raw_data);
        QString read_version;
        #if QT_VERSION < QT_VERSION_CHECK(6, 5, 0)
                MyQByteArray& raw_ref = static_cast<MyQByteArray&>(raw_data);
        #else
                QByteArray& raw_ref = raw_data;
        #endif
        while (!raw_ref.isEmpty() && raw_ref.back() != g_version_prefix) {
            read_version.push_back(raw_ref.back());
            raw_ref.removeLast();
        }
        if (!raw_ref.isEmpty()) {
            raw_ref.removeLast();
        }
        std::reverse(read_version.begin(), read_version.end());
        if (g_supported_as_version_1.contains(read_version)) {
            decoded_data_bytes = do_decode<1>(raw_ref, mDec, mDecInner);
            if (decoded_data_bytes.isEmpty()) {
                return Loading_Errors::CRC_FAILURE;
            }
        }
        else if (g_supported_as_version_2.contains(read_version)) {
            decoded_data_bytes = do_decode<2>(raw_ref, mDec, mDecInner);
            if (decoded_data_bytes.isEmpty()) {
                return Loading_Errors::CRC_FAILURE;
            }
        }
        else if (g_supported_as_version_3.contains(read_version)) {
            decoded_data_bytes = do_decode<3>(raw_ref, mDec, mDecInner);
            if (decoded_data_bytes.isEmpty()) {
                return Loading_Errors::CRC_FAILURE;
            }
        }
        else {
            return Loading_Errors::UNKNOWN_FORMAT;
        }
    } else {
        // qDebug() << "Storage cannot be opened.";
        if (file.exists()) {
            return Loading_Errors::CANNOT_BE_OPENED;
        } else {
            return Loading_Errors::NEW_STORAGE;
        }
    }
    #if QT_VERSION >= QT_VERSION_CHECK(6, 6, 0)
        auto toUtf16 = QStringDecoder(QStringDecoder::Utf8);
        QString decoded_data_str = toUtf16(decoded_data_bytes);
    #else
        QString decoded_data_str(decoded_data_bytes);
    #endif
    if (decoded_data_str.isEmpty()) {
        qDebug() << "Unrecognized error while loading.";
        return Loading_Errors::UNRECOGNIZED;
    }
    decoded_data_str.remove(decoded_data_str.size() - 1, 1);
    QStringList data_rows;
    data_rows = decoded_data_str.split(symbols::col_delimiter);
    if (data_rows.isEmpty() || (!data_rows.isEmpty() && data_rows[0].isEmpty())) {
        qDebug() << "Empty row data.";
        return Loading_Errors::EMPTY_TABLE;
    }
    QStringList data_items;
    for (int row = 0; row < data_rows.size(); row++)
    {
        data_items = data_rows.at(row).split(symbols::row_delimiter);
        if (data_items.size() <= wr_table->columnCount()) {
            wr_table->insertRow(row);
        } else {
            qDebug() << "Small column size in table: table: " << wr_table->columnCount() << " vs loaded data: " << data_items.size();
            return Loading_Errors::UNRECOGNIZED;
        }
        for (int col = 0; col < data_items.size(); col++)
        {
            const QString& row_str = data_items.at(col);
            QTableWidgetItem *item = new QTableWidgetItem();
            if (col == constants::pswd_column_idx) {
                item->setData(Qt::DisplayRole, g_asterics);
                item->setData(Qt::UserRole, row_str.at(0) == symbols::empty_item ? "" : row_str);
            } else {
                item->setText(row_str.at(0) == symbols::empty_item ? "" : row_str);
            }
            wr_table->setItem(row, col, item);
        }
    }
    qDebug() << "Table has been loaded!";
    return Loading_Errors::OK;
}

void StorageManager::RemoveTmpFile()
{
    QFile tmp_file(mStorageNameTmp);
    if (tmp_file.exists()) {
        tmp_file.remove();
    }
}

bool StorageManager::FileIsExist() const
{
    const QFile file(mStorageName);
    return file.exists();
}

bool StorageManager::BackupFileIsExist() const
{
    const QFile backup_file(mStorageNameBackUp);
    return backup_file.exists();
}

bool StorageManager::TmpFileIsExist() const
{
    const QFile tmp_file(mStorageNameTmp);
    return tmp_file.exists();
}

bool StorageManager::WasUpdated() const
{
    return mWasUpdated;
}

bool StorageManager::IsSuccess() const {
    return mEnc.gamma_gen.is_succes() && mDec.gamma_gen.is_succes() &&
        mEncInner.gamma_gen.is_succes() && mDecInner.gamma_gen.is_succes();
}

bool StorageManager::IsTryToLoadFromTmp() const
{
    return mTryToLoadFromTmp;
}

void StorageManager::BeforeUpdate()
{
    mSetCounter = 0;
    mWasUpdated = false;
}

void StorageManager::AfterUpdate()
{
    assert(mSetCounter == 6); // Ожидаемое количество сеттеров.
    mWasUpdated = true;
}

void StorageManager::SetName(const QString &name)
{
    if (!name.isEmpty()) mSetCounter++;
    mStorageName = name;
    mStorageNameBackUp = QString::fromUtf8(".") + name;
}

void StorageManager::SetTmpName(const QString &name)
{
    if (!name.isEmpty()) mSetCounter++;
    mStorageNameTmp = name + QString::fromUtf8(".tmp");
}

QString StorageManager::Name() const
{
    return mStorageName;
}

QString StorageManager::NameTmp() const
{
    return mStorageNameTmp;
}

void StorageManager::SetTryToLoadFromTmp(bool value)
{
    mTryToLoadFromTmp = value;
}

void StorageManager::SetEncGammaGenerator(const lfsr_rng::Generators &generator)
{
    mSetCounter++;
    mEnc.gamma_gen = generator;
}

void StorageManager::SetDecGammaGenerator(const lfsr_rng::Generators &generator)
{
    mSetCounter++;
    mDec.gamma_gen = generator;
}

void StorageManager::SetEncInnerGammaGenerator(const lfsr_rng::Generators &generator)
{
    mSetCounter++;
    mEncInner.gamma_gen = generator;
}

void StorageManager::SetDecInnerGammaGenerator(const lfsr_rng::Generators &generator)
{
    mSetCounter++;
    mDecInner.gamma_gen = generator;
}
