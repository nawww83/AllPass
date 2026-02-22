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
    QString("v1.08"),
    QString("v1.09")
};

static const QSet<QString> g_supported_as_version_4 {
    QString("v1.10"),
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

namespace api_v4 {

// S-Box для нелинейности
static constexpr unsigned char SBOX[256] = {
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

// Эта проверка не занимает времени при работе программы,
// она сработает только в момент компиляции.
static constexpr bool validate_sbox() {
    bool seen[256] = {false};
    for (int i = 0; i < 256; ++i) {
        if (seen[SBOX[i]]) return false;
        seen[SBOX[i]] = true;
    }
    return true;
}

static_assert(sizeof(SBOX) == 256, "SBOX must have 256 elements!");
static_assert(validate_sbox(), "SBOX must be a valid permutation (no duplicates)!");

// Секретная соль (выберите любое число от 1 до 255)
// Изменение этого числа полностью меняет все результаты CRC
static constexpr uchar SECRET_SALT = 0x5A;

// Объект-вычислитель для одного прохода
struct CRCProcessor {
    int b_mod, s_mod, s0;
    bool init_swap;

    uchar crc = SECRET_SALT;
    int sequence;
    bool current_swap;

    // Конструктор инициализирует начальное состояние
    CRCProcessor(int b, int s, bool sw, int _s0)
        : b_mod(b), s_mod(s), s0(_s0), init_swap(sw), sequence(_s0), current_swap(sw) {}

    // Обработка одного байта
    inline void process(int i, uchar byte) {
        const bool doit = current_swap ? i % b_mod != 0 : i % b_mod == 0;
        sequence = doit ? (sequence % b_mod) + 1 : sequence + 1;

        uchar mul = doit ? static_cast<uchar>(sequence ^ crc) : 0;
        crc = SBOX[crc ^ static_cast<uchar>(mul * byte)];
        crc = static_cast<uchar>((crc << 3) | (crc >> 5));

        if (s_mod > 0 && (i % s_mod) == 0) current_swap = !current_swap;
    }
};

static QByteArray encode_crc(const QByteArray& data) {
    // 1. Создаем кортеж со всеми 16 процессорами.
    auto processors = std::make_tuple(
        CRCProcessor(119, 140, false, 10), CRCProcessor(15, 106, false, 10),
        CRCProcessor(20, 74, false, 10),  CRCProcessor(65, 41, false, 10),
        CRCProcessor(119, 140, true, 10),  CRCProcessor(15, 106, true, 10),
        CRCProcessor(20, 74, true, 10),   CRCProcessor(65, 41, true, 10),

        CRCProcessor(208, 201, false, 61), CRCProcessor(1, 109, false, 61),
        CRCProcessor(119, 26, false, 61),  CRCProcessor(20, 203, false, 61),
        CRCProcessor(208, 201, true, 61),  CRCProcessor(1, 109, true, 61),
        CRCProcessor(119, 26, true, 61),   CRCProcessor(20, 203, true, 61)
        );

    uchar c1 = SECRET_SALT ^ 0xFF;

    // 2. ЕДИНСТВЕННЫЙ проход по данным
    for (int i = 1; i <= data.size(); ++i) {
        uchar byte = static_cast<uchar>(data.at(i - 1));
        c1 = SBOX[c1 ^ byte];

        // Применяем лямбду ко всем элементам кортежа
        std::apply([i, byte](auto&... p) {
            (p.process(i, byte), ...); // Fold expression (C++17)
        }, processors);
    }

    // 3. Сборка результата
    QByteArray out;
    out.reserve(17);
    out.append(static_cast<char>(c1));

    std::apply([&out](auto&... p) {
        (out.append(static_cast<char>(p.crc)), ...);
    }, processors);

    return out;
}

static bool decode_crc(const QByteArray& data, const QByteArray& received_crc) {
    if (received_crc.size() != 17) return false;

    // Прямое сравнение - единственный надежный способ для нелинейного хеша
    return (encode_crc(data) == received_crc);
}

using namespace api_v3;

} // api_v4

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
    if constexpr (version == 4) {
        my_encode(api_v4, (256-17), 17);
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
    if constexpr (version == 4) {
        my_decode(api_v4, (256-17), 17);
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
    else if (g_supported_as_version_4.contains(current_version)) {
        encoded_data_bytes = do_encode<4>(packed_data_bytes, mEnc, mEncInner);
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
        else if (g_supported_as_version_4.contains(read_version)) {
            decoded_data_bytes = do_decode<4>(raw_ref, mDec, mDecInner);
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

            // Проверяем, пустое ли значение (используя ваш символ empty_item)
            QString final_str = (row_str.isEmpty() || row_str.at(0) == symbols::empty_item)
                                    ? ""
                                    : row_str;

            if (col == constants::pswd_column_idx) {
                // --- ИСПРАВЛЕНИЕ: Динамическая маска ---
                QString mask(final_str.length(), '*');

                item->setData(Qt::DisplayRole, mask);      // Визуально: звездочки
                item->setData(Qt::UserRole, final_str);    // Внутри: реальный пароль
            } else {
                item->setText(final_str);
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
