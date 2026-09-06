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
    QString("v3.00")
};

#ifdef OS_Windows
    static void do_hidden(wchar_t* fileLPCWSTR) {
        int attr = GetFileAttributes(fileLPCWSTR);
        if ((attr & FILE_ATTRIBUTE_HIDDEN) == 0) {
            SetFileAttributes(fileLPCWSTR, attr | FILE_ATTRIBUTE_HIDDEN);
        }
    }
#endif

namespace api_v1
{

static void finalize_encryption(Encryption& enc) {
    while (enc.counter > 0) {
        enc.gamma_gen.back_u64();
        enc.counter--;
    }
    enc.counter = 0;
    enc.aligner64 = 0;
    enc.gamma = 0;
}

static void init_encryption(Encryption& enc, uint seed) {
    enc.aligner64 = 0;
    // Защита от повторной инициализации
    if (enc.counter != 0) {
        qDebug() << "Warning: enc.counter is not zero during init. Finalizing first.";
        finalize_encryption(enc);
    }
    const int steps = 512 + (seed % 65536u);
    for (int i = 0; i < steps; ++i) {
        enc.gamma_gen.next_u64();
        enc.counter++;
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

static void encode_dlog256(const QByteArray& in, QByteArray& out, uint8_t key_byte) {
    constexpr int p = 257;
    const int n = in.size();
    out.resize(n);
    const int ch = n / (p - 1);

    for (int i = 0; i < ch; ++i) {
        // Уникальный генератор для каждого блока, скрытый от злоумышленника
        uint8_t crypto_index = static_cast<uint8_t>(key_byte + i);
        const int a = const_arr::goods[crypto_index % std::ssize(const_arr::goods)];

        int x = a;
        int counter = 0;
        while (counter++ < (p - 1)) {
            if (x <= 0 || x >= p) x = 1; // Защита от потенциального повреждения памяти

            out[i * (p - 1) + x - 1] = in[i * (p - 1) + counter - 1];
            x = (x * a) % p;
        }
    }
}

static void decode_dlog256(const QByteArray& in, QByteArray& out, uint8_t key_byte) {
    constexpr int p = 257;
    const int n = in.size();
    if (n % (p - 1) != 0) {
        qDebug() << "Decode dlog256 error: bad size";
        return;
    }
    out.resize(n);
    const int ch = n / (p - 1);

    for (int i = 0; i < ch; ++i) {
        uint8_t crypto_index = static_cast<uint8_t>(key_byte + i);
        const int a = const_arr::goods[crypto_index % std::ssize(const_arr::goods)];

        int x = a;
        int counter = 0;
        while (counter++ < (p - 1)) {
            if (x <= 0 || x >= p) x = 1;

            out[i * (p - 1) + counter - 1] = in[i * (p - 1) + x - 1];
            x = (x * a) % p;
        }
    }
}

static void insert_hash128(QByteArray& bytes) {
    if (bytes.size() % 128 != 0) {
        qDebug() << "Insert hash128 error: input size is not a 128*k bytes: " << bytes.size();
        return;
    }
    password::hash_gen.reset();
    lfsr_hash::u128 hash = {0, 0};
    constexpr size_t blockSize = 128;

    // Вычисление хэша
    {
        const auto bytesRead = bytes.size();
        using namespace lfsr_hash;
        const salt original_size_salt = utils::get_salt(bytesRead, blockSize);
        const size_t n = bytesRead / blockSize;
        const auto& bytes_span = std::span(reinterpret_cast<const std::byte*>(bytes.constData()), bytes.size());
        password::hash_gen.add_salt(original_size_salt);
        for (size_t i = 0; i < n; ++i) {
            auto chunk = bytes_span.subspan(i * blockSize, blockSize);
            auto inner_hash = hash128(password::hash_gen, chunk);
            hash.first ^= inner_hash.first;
            hash.second ^= inner_hash.second;
        }
    }

    // БЕЗОПАСНАЯ И БЫСТРАЯ ЗАПИСЬ ДЛЯ C++:
    const int current_size = bytes.size();
    constexpr size_t hash_size = sizeof(lfsr_hash::u128); // 16 байт
    bytes.resize(current_size + hash_size);

    // Приводим указатель к типу std::byte* или char* и копируем N байт
    std::copy_n(
        reinterpret_cast<const char*>(&hash),
        hash_size,
        bytes.data() + current_size
        );
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

    constexpr size_t hash_size = sizeof(lfsr_hash::u128); // 16 байт
    if (bytes.size() < static_cast<int>(hash_size)) {
        qDebug() << "Small size while hash128 extracting: " << bytes.size();
        return false;
    }

    // БЕЗОПАСНОЕ И БЫСТРОЕ ИЗВЛЕЧЕНИЕ ДЛЯ C++:
    lfsr_hash::u128 extracted_hash;
    const int hash_offset = bytes_ref.size() - hash_size;

    // Копируем байты из хвоста массива в структуру extracted_hash
    std::copy_n(
        bytes_ref.constData() + hash_offset,
        hash_size,
        reinterpret_cast<char*>(&extracted_hash)
        );

    // Принудительно затираем нулями оригинальный хэш в ОЗУ перед удалением хвоста
    std::memset(bytes_ref.data() + hash_offset, 0, hash_size);
    bytes_ref.resize(hash_offset); // Отрезаем хэш от массива за один шаг O(1)

    // Вычисляем хэш от оставшихся данных для проверки
    password::hash_gen.reset();
    lfsr_hash::u128 calculated_hash = {0, 0};
    constexpr size_t blockSize = 128;
    {
        const auto bytesRead = bytes.size();
        using namespace lfsr_hash;
        const salt original_size_salt = utils::get_salt(bytesRead, blockSize);
        const size_t n = bytesRead / blockSize;
        const auto& bytes_span = std::span(reinterpret_cast<const std::byte*>(bytes.constData()), bytes.size());
        password::hash_gen.add_salt(original_size_salt);
        for (size_t i = 0; i < n; ++i) {
            auto chunk = bytes_span.subspan(i * blockSize, blockSize);
            auto inner_hash = hash128(password::hash_gen, chunk);
            calculated_hash.first ^= inner_hash.first;
            calculated_hash.second ^= inner_hash.second;
        }
    }

    return extracted_hash.first == calculated_hash.first &&
           extracted_hash.second == calculated_hash.second;
}

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

} // api_v1

StorageManager::StorageManager() {}

template <int version>
QByteArray do_encode(QByteArray& encoded_string, Encryption& enc, Encryption& enc_inner) {
    QByteArray out;
    #define my_encode(ns, K, R) \
    ns::init_encryption(enc, 0); \
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
    uint32_t seed2 = std::random_device{}(); \
    ns::init_encryption(enc_inner, seed2); \
    QByteArray encrypted_inner; \
    ns::encrypt256_inner(encoded_string, encrypted_inner, enc_inner); \
    QByteArray permuted; \
    uint8_t dlog_key = static_cast<uint8_t>(seed2 & 0xFF); \
    ns::encode_dlog256(encrypted_inner, permuted, dlog_key); \
    ns::insert_hash128(permuted); \
    crc = utils::xor_data_by_seed(crc, seed2); \
    permuted.append(crc); \
    QByteArray seed_b = utils::seed_to_bytes(seed2); \
    permuted.append(seed_b); \
    ns::encrypt(permuted, out, enc); \
    ns::finalize_encryption(enc); \
    ns::finalize_encryption(enc_inner); \
    /* Затираем промежуточные секретные буферы перед выходом */ \
    utils::erase_bytes(encrypted_inner); \
    utils::erase_bytes(permuted);

    if constexpr (version == 1) {
        my_encode(api_v1, (256-17), 17);
    }
    #undef my_encode
    return out;
}

template <int version>
QByteArray do_decode(QByteArray& data, Encryption& dec, Encryption& dec_inner) {
    QByteArray decoded_data;
    #define my_decode(ns, K, R) \
    constexpr int hash_size = 16; \
    ns::init_encryption(dec, 0); \
    QByteArray decrypted; \
    ns::decrypt(data, decrypted, dec); \
    uint32_t seed2 = 0; \
    if (decrypted.size() < static_cast<int>(sizeof(seed2))) { \
        qDebug() << "Decode failure: input size is too small: " << \
                                                          decrypted.size(); \
        ns::finalize_encryption(dec); \
        return {}; \
    } \
    seed2 = utils::seed_from_bytes_pop_back(decrypted); \
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
            for (int i=0; i<R; ++i) { \
                crc.push_back(decrypted_ref.back()); \
                /* Безопасно затираем байт в ОЗУ перед тем, как Qt его отсечет */ \
                decrypted_ref.data()[decrypted_ref.size() - 1] = '\0'; \
                decrypted_ref.removeLast(); \
        } \
    } \
    std::reverse(crc.begin(), crc.end()); \
    if (!ns::extract_and_check_hash128(decrypted)) { \
        ns::finalize_encryption(dec); \
        return {}; \
    } \
    crc = utils::xor_data_by_seed(crc, seed2); \
    QByteArray depermuted; \
    uint8_t dlog_key = static_cast<uint8_t>(seed2 & 0xFF); \
    ns::decode_dlog256(decrypted, depermuted, dlog_key); \
    ns::init_encryption(dec_inner, seed2); \
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
    ns::finalize_encryption(dec_inner); \
    /* ОЧИЩАЕМ ПАДДИНГ ISO ТУТ, когда данные полностью расшифрованы и проверены! */ \
    utils::dpadd(decoded_data); \
    ns::finalize_encryption(dec); \
    ns::finalize_encryption(dec_inner); \
    /* Затираем промежуточные бинарные буферы */ \
    utils::erase_bytes(decrypted); \
    utils::erase_bytes(depermuted);

    if constexpr (version == 1) {
        my_decode(api_v1, (256-17), 17);
    }
    #undef my_decode
    return decoded_data;
}

bool StorageManager::SaveToStorage(const QTableWidget *const ro_table, bool save_to_tmp)
{
    const QString &file_name = save_to_tmp ? mStorageNameTmp : mStorageName;
    if (file_name.isEmpty()) {
        qDebug() << "Empty storage.";
        return true;
    }
    if (!mEnc.gamma_gen.is_succes() || !mEncInner.gamma_gen.is_succes()) {
        qDebug() << "Encryption generators are not ready.";
        return false;
    }

    QByteArray packed_data_bytes;
    // Предварительно резервируем память для минимизации realloc в куче
    packed_data_bytes.reserve(ro_table->rowCount() * ro_table->columnCount() * 16);

    {
        QDataStream stream(&packed_data_bytes, QIODevice::WriteOnly);

        // Преобразуем управляющие символы в сырые UTF-8 байты
        const char col_byte = static_cast<char>(symbols::col_delimiter.unicode()); // 0x1F (между ячейками)
        const char row_byte = static_cast<char>(symbols::row_delimiter.unicode()); // 0x1E (между строками)
        const char end_byte = static_cast<char>(symbols::end_message.unicode());   // 0x03 (конец сообщения)
        const char empty_byte = static_cast<char>(symbols::empty_item.unicode());  // 0x08 (пустая ячейка)


        for (int row = 0; row < ro_table->rowCount(); ++row) {
            for (int col = 0; col < ro_table->columnCount(); ++col) {

                if (ro_table->item(row, col)) {
                    const QString &txt = ro_table->item(row, col)->text();
                    if (txt.isEmpty()) {
                        stream.writeRawData(&empty_byte, 1);
                    } else {
                        QByteArray cell_bytes = txt.toUtf8();
                        stream.writeRawData(cell_bytes.constData(), cell_bytes.size());
                        utils::erase_bytes(cell_bytes); // Сразу уничтожаем пароль ячейки в RAM!
                    }
                } else {
                    stream.writeRawData(&empty_byte, 1);
                }

                // Разделитель КОЛОНОК (ячеек) внутри одной строки
                if (col < ro_table->columnCount() - 1) {
                    stream.writeRawData(&col_byte, 1);
                }
            }

            // Разделитель СТРОК между строками таблицы
            if (row < ro_table->rowCount() - 1) {
                stream.writeRawData(&row_byte, 1);
            }
        }
        // Записываем маркер конца сообщения
        stream.writeRawData(&end_byte, 1);
    }

    // --- СИСТЕМНАЯ ЛОГИКА (ШИФРОВАНИЕ) ---

    QByteArray encoded_data_bytes;
    QString current_version = QString::fromUtf8(VERSION_LABEL);
    current_version.remove(g_version_prefix);

    if (g_supported_as_version_1.contains(current_version)) {
        // 2. Шифруем полностью выровненный блок
        encoded_data_bytes = do_encode<1>(packed_data_bytes, mEnc, mEncInner);
    }

    // Очищаем временный буфер открытого текста
    utils::erase_bytes(packed_data_bytes);

    if (encoded_data_bytes.isEmpty()) {
        return true;
    }

    // 3. Дописываем ОТКРЫТУЮ версию в самый конец зашифрованного массива (как футер)
    encoded_data_bytes.append(VERSION_LABEL);

    // 4. Запись в файл и создание бэкапа
    QFile file(file_name);
    if (file.open(QFile::WriteOnly)) {
        file.write(encoded_data_bytes);
        file.close();
        if (save_to_tmp) {
            return true;
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
            return true;
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
            mb.critical(nullptr,
                        QString::fromUtf8("Ошибка сохранения."),
                        QString::fromUtf8("Файловая ошибка сохранения таблицы в хранилище."));
            return false;
        }
    }
    return true;
}

Loading_Errors StorageManager::LoadFromStorage(QTableWidget *const wr_table, FileTypes type)
{
    const auto &file_name = [this, type]() -> QString {
        switch (type) {
        case FileTypes::BACKUP: return mStorageNameBackUp;
        case FileTypes::TEMPORARY: return mStorageNameTmp;
        default: return mStorageName;
        }
    }();

    if (file_name.isEmpty()) return Loading_Errors::EMPTY_STORAGE;
    if (!mDec.gamma_gen.is_succes() || !mDecInner.gamma_gen.is_succes()) return Loading_Errors::EMPTY_ENCRYPTION;
    if (wr_table->rowCount() > 0) return Loading_Errors::TABLE_IS_NOT_EMPTY;

    QFile file(file_name);
    QByteArray decoded_data_bytes;

    if (file.open(QFile::ReadOnly)) {
        QByteArray raw_data = file.readAll();
        file.close();

        if (raw_data.isEmpty()) return Loading_Errors::EMPTY_TABLE;

        // 1. Отсекаем и считываем ОТКРЫТУЮ ВЕРСИЮ из конца файла
        QString read_version;
#if QT_VERSION < QT_VERSION_CHECK(6, 5, 0)
        MyQByteArray &raw_ref = static_cast<MyQByteArray &>(raw_data);
#else
        QByteArray &raw_ref = raw_data;
#endif
        while (!raw_ref.isEmpty() && raw_ref.back() != g_version_prefix) {
            read_version.push_back(raw_ref.back());
            raw_ref.removeLast();
        }
        if (!raw_ref.isEmpty()) {
            raw_ref.removeLast(); // Удаляем сам g_version_prefix
        }
        std::reverse(read_version.begin(), read_version.end());

        // 2. Дешифруем массив, который теперь строго кратен размеру блока
        if (g_supported_as_version_1.contains(read_version)) {
            decoded_data_bytes = do_decode<1>(raw_ref, mDec, mDecInner);
            if (decoded_data_bytes.isEmpty()) {
                return Loading_Errors::CRC_FAILURE;
            }
        } else {
            return Loading_Errors::UNKNOWN_FORMAT;
        }
    } else {
        return file.exists() ? Loading_Errors::CANNOT_BE_OPENED : Loading_Errors::NEW_STORAGE;
    }

    // 4. Переводим расшифрованные байты в строку UTF-16
#if QT_VERSION >= QT_VERSION_CHECK(6, 6, 0)
    auto toUtf16 = QStringDecoder(QStringDecoder::Utf8);
    QString decoded_data_str = toUtf16(decoded_data_bytes);
#else
    QString decoded_data_str = QString::fromUtf8(decoded_data_bytes);
#endif

    // Сразу затираем открытый бинарный текст в памяти
    utils::erase_bytes(decoded_data_bytes);

    if (decoded_data_str.isEmpty()) return Loading_Errors::UNRECOGNIZED;

    // 5. Валидация и удаление технического маркера конца сообщения
    if (decoded_data_str.back() == symbols::end_message) {
        decoded_data_str.chop(1);
    } else {
        return Loading_Errors::UNRECOGNIZED;
    }

    // Если после удаления маркера конца строка оказалась абсолютно пустой,
    // это означает, что была сохранена пустая таблица. Завершаем работу без добавления строк.
    if (decoded_data_str.isEmpty()) {
        qDebug() << "Loaded storage is empty (0 rows).";
        return Loading_Errors::OK; // Возвращаем успех, таблица остается чистой
    }

    // 6. Парсинг с восстановленной иерархией разделителей
    // Разделяем монолит на СТРОКИ таблицы по row_delimiter (0x1E)
    QStringList data_rows = decoded_data_str.split(symbols::row_delimiter);
    if (data_rows.isEmpty()) {
        return Loading_Errors::EMPTY_TABLE;
    }

    for (int row = 0; row < data_rows.size(); ++row) {
        // Каждую строку разделяем на ЯЧЕЙКИ (колонки) по col_delimiter (0x1F)
        QStringList data_items = data_rows.at(row).split(symbols::col_delimiter);

        if (data_items.size() <= wr_table->columnCount()) {
            wr_table->insertRow(row);
        } else {
            return Loading_Errors::UNRECOGNIZED;
        }

        for (int col = 0; col < data_items.size(); ++col) {
            const QString &cell_str = data_items.at(col);
            QTableWidgetItem *item = new QTableWidgetItem();

            // Извлечение пустых значений
            QString final_str = "";
            if (!cell_str.isEmpty() && cell_str.at(0) != symbols::empty_item) {
                final_str = cell_str;
            }

            if (col == constants::pswd_column_idx) {
                // Пишем чистый прочитанный пароль в обе роли модели
                item->setData(Qt::DisplayRole, final_str);
                item->setData(Qt::EditRole, final_str);
            } else {
                item->setText(final_str);
            }

            wr_table->setItem(row, col, item);
        }
    }

    qDebug() << "Table has been successfully loaded!";
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
