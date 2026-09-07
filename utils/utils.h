#pragma once

#include <array> // std::array
#include <cstring>
#include <string.h>

#include <QDebug>
#include <QFutureWatcher>
#include <QByteArray>
#include <QMutex>
#include <QMutexLocker>
#include <QCryptographicHash>
#include <QDataStream>
#include <QIODevice>
#include <qglobalstatic.h>

#include <QString>
#include <cstdint>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#endif

#include "lfsr_hash.h"
#include "key.h"
#include "constants.h"
#include "../AppCore/worker.h"

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
    explicit MyQByteArray(QByteArray * parent): QByteArray(*parent) {}
    char back() const {
        return this->at(size() - 1);
    }
    char& back() {
        return this->data()[size() - 1];
    }
    MyQByteArray& removeLast() {
        if (!this->isEmpty())
            this->remove(size() - 1, 1);
        return *this;
    }
    MyQByteArray& resize(int new_size, char filler = '\0') {
        if (new_size >= 0) {
            while (size() > new_size) {
                this->removeLast();
            }
            while (size() < new_size) {
                this->push_back(filler);
            }
        }
        return *this;
    }
};

struct PasswordBuffer {
    QVector<lfsr8::u64> mPasswords;
    mutable QMutex mMutex;
};

struct PinCode {
    std::array<int, constants::pin_code_len> mPinCode{};
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

// Базовая функция очистки сырого буфера
inline static void erase_bytes(uint8_t *b, int len)
{
    if (!b || len <= 0)
        return;

#if defined(_WIN32)
    // На Windows используем системную функцию
    SecureZeroMemory(b, len);
#elif defined(__linux__) || defined(__GLIBC__)
    // В современных Linux / glibc используем explicit_bzero, защищенную от оптимизаций
    explicit_bzero(b, len);
#elif defined(__STDC_LIB_EXT1__) && defined(__STDC_WANT_LIB_EXT1__) && (__STDC_WANT_LIB_EXT1__ == 1)
    // C11 безопасный memset_s (если реально поддерживается компилятором)
    memset_s(b, len, 0, len);
#else
    // Кроссплатформенный барьер через asm или volatile
    volatile uint8_t *p = b;
    while (len--) {
        *p++ = 0;
    }
// Сигнализируем компилятору, что память была изменена
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(b) : "memory");
#endif
#endif
}

// Функция очистки QByteArray
inline static void erase_bytes(QByteArray& b) {
    if (b.isEmpty()) return;

    // Передаем указатель на внутренний неконстантный буфер Qt
    erase_bytes(reinterpret_cast<uint8_t*>(b.data()), b.size());
    b.clear(); // Сбрасываем размер в Qt
}

// Функция очистки QString (UTF-16)
inline static void erase_string(QString& str) {
    if (str.isEmpty()) return;

    // Размер в байтах для UTF-16 — это количество символов * 2
    int size_in_bytes = str.size() * sizeof(char16_t);

    erase_bytes(reinterpret_cast<uint8_t*>(str.data()), size_in_bytes);
    str.clear(); // Безопасно очищаем объект Qt
}

inline static void fill_pin(QString pin) {
    using namespace password;
    for (int i = 0; i < constants::pin_code_len; ++i)
        pin_code->mPinCode[i] = pin[i].digitValue();
    erase_string(pin);
}

inline static void back_up_pin() {
    using namespace password;
    old_pin_code->mPinCode = pin_code->mPinCode;
}

inline static void restore_pin() {
    using namespace password;
    pin_code->mPinCode = old_pin_code->mPinCode;
}

inline static bool check_pin(QString pin) {
    using namespace password;
    bool ok = true;
    for (int i = 0; i < constants::pin_code_len; ++i)
        ok &= pin_code->mPinCode[i] == pin[i].digitValue();
    return ok;
}


// Инициализация ключей
inline static void fill_key_by_hash128(lfsr_hash::u128 hash) {
    auto x = hash.first;
    auto y = hash.second;

    {
        using password::key;
        // Операция & 0xFFFF (маска) эквивалентна % 65536, но выполняется процессором мгновенно
        key->set_key(x & 0xFFFF,         3);
        key->set_key((x >> 16) & 0xFFFF, 2);
        key->set_key((x >> 32) & 0xFFFF, 1);
        key->set_key((x >> 48) & 0xFFFF, 0);

        key->set_key(y & 0xFFFF,         7);
        key->set_key((y >> 16) & 0xFFFF, 6);
        key->set_key((y >> 32) & 0xFFFF, 5);
        key->set_key((y >> 48) & 0xFFFF, 4);
    }

    // Кроссплатформенное затирание локальной копии hash на GCC/Clang/MSVC
    volatile uint64_t* px = &x;
    volatile uint64_t* py = &y;
    *px = 0; *py = 0;
}

// Инициализация стейта ГПСЧ
inline static lfsr_rng::STATE fill_state_by_hash(lfsr_hash::u128 hash) {
    lfsr_rng::STATE st;
    for (int i = 0; i < 8; ++i) {
        lfsr_hash::u16 byte_1 = 255 & (hash.first >> (8 * i));
        lfsr_hash::u16 byte_2 = 255 & (hash.second >> (8 * i));
        st[i] = (byte_1 << 8) | byte_2;
    }
    return st;
}

// Безопасная очистка главного ключа
inline static void clear_main_key() {
    using password::key;

    // Напрямую зануляем ключи. Чтобы гарантировать выполнение на любом компиляторе,
    // используем volatile указатель, если set_key позволяет принимать volatile,
    // либо полагаемся на то, что объект key сам по себе должен быть обернут в очистку.
    // Если set_key — обычный метод, пишем последовательное зануление:
    key->set_key(0, 3);
    key->set_key(0, 2);
    key->set_key(0, 1);
    key->set_key(0, 0);
    key->set_key(0, 7);
    key->set_key(0, 6);
    key->set_key(0, 5);
    key->set_key(0, 4);

    // Дополнительный барьер для оптимизатора, показывающий, что мы производим деструктивные действия
    std::atomic_thread_fence(std::memory_order_seq_cst);
}

// Безопасная очистка 128-битного хэша по ССЫЛКЕ
inline static void clear_lfsr_hash(lfsr_hash::u128& hash) {
    // Получаем прямой доступ к памяти структуры через volatile
    volatile uint64_t* p_first = &hash.first;
    volatile uint64_t* p_second = &hash.second;
    *p_first = 0;
    *p_second = 0;
}

// Безопасная очистка внутреннего состояния генератора (массива std::array)
inline static void clear_lfsr_rng_state(lfsr_rng::STATE& st) {
    // Вызываем .data() для получения указателя на первый элемент сырого массива внутри std::array
    volatile auto* p_st = reinterpret_cast<volatile lfsr_hash::u16*>(st.data());
    for (int i = 0; i < 8; ++i) {
        p_st[i] = 0;
    }
}

inline static char xor_val(const QByteArray& data) {
    if (data.isEmpty()) return '\0';

    const char* ptr = data.constData();
    char result = ptr[0];
    const int size = data.size();
    for (int j = 1; j < size; ++j) {
        result ^= ptr[j];
    }
    return result;
}

inline static QByteArray xor_bytes(const QByteArray& data_1, const QByteArray& data_2) {
    const int min_size = std::min(data_1.size(), data_2.size());
    QByteArray result;
    result.resize(min_size);

    const char* p1 = data_1.constData();
    const char* p2 = data_2.constData();
    char* r = result.data();

    for (int j = 0; j < min_size; ++j) {
        r[j] = p1[j] ^ p2[j];
    }
    return result;
}

inline QByteArray seed_to_bytes(uint32_t seed) {
    QByteArray result;
    result.resize(sizeof(uint32_t));
    char* ptr = result.data();

    // Побитовое выделение байт (быстрее, чем операция остатка от деления '%')
    for (size_t i = 0; i < sizeof(uint32_t); ++i) {
        ptr[i] = static_cast<char>(seed & 0xFF);
        seed >>= 8;
    }
    return result;
}

inline uint32_t seed_from_bytes_pop_back(QByteArray& data) {
    uint32_t seed = 0;
    if (data.size() < static_cast<int>(sizeof(uint32_t))) {
        return seed;
    }

#if QT_VERSION < QT_VERSION_CHECK(6, 4, 0)
    MyQByteArray& data_ref = static_cast<MyQByteArray&>(data);
#else
    QByteArray& data_ref = data;
#endif

    // Добавляем обязательное затирание извлекаемого сида в ОЗУ
    for (size_t i = 0; i < sizeof(uint32_t); ++i) {
        const auto b = static_cast<uint8_t>(data_ref.back());

        // Перезаписываем байт перед удалением
        data_ref.data()[data_ref.size() - 1] = '\0';
        data_ref.removeLast();

        seed |= (static_cast<uint32_t>(b) << (8 * sizeof(uint32_t) - 8 - 8 * i));
    }
    return seed;
}

inline static QByteArray xor_data_by_seed(const QByteArray& data, uint32_t seed) {
    QByteArray result;
    const int size = data.size();
    result.resize(size); // Выделяем память под массив ОДИН раз

    const char* src = data.constData();
    char* dest = result.data();

    // Раскладываем seed на массив байт в соответствии с Little-Endian упаковкой seed_to_bytes
    const uint8_t seed_bytes[4] = {
        static_cast<uint8_t>(seed & 0xFF),
        static_cast<uint8_t>((seed >> 8) & 0xFF),
        static_cast<uint8_t>((seed >> 16) & 0xFF),
        static_cast<uint8_t>((seed >> 24) & 0xFF)
    };

    // Линейный XOR без создания временных QByteArray (устраняет утечки памяти и вылеты)
    for (int i = 0; i < size; ++i) {
        dest[i] = src[i] ^ static_cast<char>(seed_bytes[i % 4]);
    }

    return result;
}


template <int block_size>
inline static void padd(QByteArray& data) {
#if QT_VERSION < QT_VERSION_CHECK(6, 4, 0)
    MyQByteArray& data_ref = static_cast<MyQByteArray&>(data);
#else
    QByteArray& data_ref = data;
#endif

    const int old_size = data.size();

    // По стандарту ISO маркер 0x80 добавляется ВСЕГДА, поэтому +1
    const int res = (old_size + 1) % block_size;
    const int new_size = (old_size + 1) + (res != 0 ? block_size - res : 0);

    data_ref.resize(new_size, '\0');
    data_ref[old_size] = static_cast<char>(0x80); // Ставим маркер конца реальных данных
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

    const char* const begin = data_ref.constData();
    const char* ptr = begin + data_ref.size() - 1;

    // Быстро пропускаем нули с конца без вызова тяжелых методов Qt
    while (ptr >= begin && *ptr == '\0') {
        --ptr;
    }

    // Если нашли наш маркер 0x80, отрезаем всё лишнее за один шаг
    if (ptr >= begin && *ptr == static_cast<char>(0x80)) {
        const int real_size = static_cast<int>(ptr - begin);
        data_ref.resize(real_size);
    }
    // Если маркер не найден — данные повреждены или не имели паддинга, не трогаем их
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

inline static QString encode_u32_simple_level(lfsr8::u32 sample)
{
    //constants::password_len_per_u32 обычно равен 4 или 5 в зависимости от архитектуры
    QString word(constants::password_len_per_u32, '\0');

    // Алфавит: 0-9 (10), A-Z (26), a-z (26). Всего 62 символа.
    for (int i = 0; i < constants::password_len_per_u32; ++i) {
        lfsr8::u32 r = sample % 62u;
        sample /= 62u;

        auto code = r + 48u;
        if (code > 57u && code < 65u)  code += 7u;  // Пропуск знаков между 9 и A
        if (code > 90u && code < 97u)  code += 6u;  // Пропуск знаков между Z и a

        word[constants::password_len_per_u32 - i - 1] = QChar(code);
    }
    return word;
}

inline static QString encode_u32_hard_level(lfsr8::u32 sample)
{
    QString word(constants::password_len_per_u32, '\0');
    bool has_special_symbol = false;
    int last_idx = constants::password_len_per_u32 - 1;

    for (int i = 0; i < constants::password_len_per_u32; ++i) {
        lfsr8::u32 r = sample % 77u;
        sample /= 77u;

        auto code = r + 33u;
        if (code >= 33u && code <= 47u) {
            has_special_symbol = true;
        }

        if (code > 57u && code < 65u)  code += 7u;
        if (code > 90u && code < 97u)  code += 6u;

        word[last_idx - i] = QChar(code);
    }

    // Если спецсимвол не выпал случайно, мы принудительно заменяем самый первый
    // символ строки на гарантированный спецсимвол (например, восклицательный знак '!', ASCII 33).
    // Это сохраняет размер строки, не ломает цикл while и гарантирует выполнение условий сложности!
    if (!has_special_symbol) {
        word[0] = QChar(33u); // '!'
    }

    return word;
}

inline static void fill_buffer_from_pin(uint8_t (&buffer)[64])
{
    const auto& code = password::pin_code->mPinCode;

    // 1. Упаковываем ПИН-код в массив байт
    QByteArray inputBytes;
    QDataStream writer(&inputBytes, QIODevice::WriteOnly);
    for (int i = 0; i < constants::pin_code_len; ++i) {
        writer << static_cast<char>('0' + code[i]);
    }

    // 2. Хэшируем с помощью SHA-512 (результат — ровно 64 байта)
    QByteArray hashResult = QCryptographicHash::hash(inputBytes, QCryptographicHash::Sha512);

    // 3. Безопасно копируем 64 байта в целевой массив
    std::copy_n(reinterpret_cast<const uint8_t*>(hashResult.constData()), 64, buffer);
}

inline static QByteArray lfsr_hash_to_bytes(lfsr_hash::u128 hash)
{
    QByteArray output;
    constexpr size_t hash_size = sizeof(hash); // Ровно 16 байт (2 * sizeof(uint64_t))

    // 1. Предварительно выделяем память одной операцией во избежание лишних realloc
    output.resize(static_cast<int>(hash_size));

    // 2. Безопасно копируем байты структуры в буфер QByteArray
    std::copy_n(
        reinterpret_cast<const char*>(&hash),
        hash_size,
        output.data()
        );

    return output;
}

inline static lfsr_hash::u128 bytes_to_lfsr_hash(const QByteArray& input)
{
    constexpr size_t hash_size = sizeof(lfsr_hash::u128); // Ровно 16 байт
    lfsr_hash::u128 hash = {0, 0}; // Инициализируем дефолтными нулями

    // КРИТИЧЕСКАЯ ЗАЩИТА: Проверяем, что входной массив содержит достаточно байт.
    // Если байт меньше 16, чтение памяти приведет к аварийному падению (Crash).
    if (input.size() < static_cast<int>(hash_size)) {
        qDebug() << "Error: QByteArray size is too small to restore u128 hash: " << input.size();
        return hash; // Возвращаем пустой хэш {0, 0}
    }

    // Безопасно копируем 16 байт из массива обратно в структуру пары
    std::copy_n(
        input.constData(),
        hash_size,
        reinterpret_cast<char*>(&hash)
        );

    return hash;
}

inline static lfsr_hash::salt pin_to_salt(const QByteArray& inner_salt)
{
    using namespace lfsr_hash;
    QByteArray inputBuffer;
    QDataStream writer(&inputBuffer, QIODevice::WriteOnly);
    const auto& code = password::pin_code->mPinCode;

    for (int i = 0; i < constants::pin_code_len; ++i) {
        writer << static_cast<char>('0' + code[i]);
    }
    writer << inner_salt;
    QByteArray hashResult = QCryptographicHash::hash(inputBuffer, QCryptographicHash::Sha256);

    QDataStream reader(hashResult);
    int raw_q;
    u16 raw_s0;
    u16 raw_s1;
    reader >> raw_q >> raw_s0 >> raw_s1;
    int q = 32 + (std::abs(raw_q) % 32);
    return { q, raw_s0, raw_s1 };
}

inline static lfsr_hash::salt hash_to_salt(lfsr_hash::u128 hash)
{
    using namespace lfsr_hash;

    // 1. Упаковываем 128-битный хэш (два uint64_t / quint64) в массив байт
    QByteArray inputBytes;
    QDataStream writer(&inputBytes, QIODevice::WriteOnly);
    writer << static_cast<quint64>(hash.first)
           << static_cast<quint64>(hash.second);

    // 2. Хэшируем с помощью SHA-256. Получаем 32 байта лавинно-перемешанных данных
    QByteArray shaResult = QCryptographicHash::hash(inputBytes, QCryptographicHash::Sha256);

    // 3. Вырезаем из хэша необходимые типы данных для структуры salt
    QDataStream reader(shaResult);
    int raw_q;
    u16 s0;
    u16 s1;
    reader >> raw_q >> s0 >> s1;

    int q = 11 + (std::abs(raw_q) % 47);
    return { q, s0, s1 };
}

inline static lfsr_hash::u128 pin_to_hash(const QByteArray& inner_salt)
{
    using namespace lfsr_hash;
    uint8_t b_[64];
    fill_buffer_from_pin(b_);
    password::hash_gen.add_salt(pin_to_salt(inner_salt));
    const auto hash = hash128(password::hash_gen, std::as_bytes( std::span(b_) ));
    utils::erase_bytes(b_, 64);
    return hash;
}

inline static lfsr_hash::salt get_salt(size_t bytesRead, size_t blockSize)
{
    using namespace lfsr_hash;

    // 1. Собираем все входные компоненты в один буфер через QDataStream
    QByteArray inputBuffer;
    QDataStream writer(&inputBuffer, QIODevice::WriteOnly);

    writer << static_cast<quint64>(bytesRead);
    writer << static_cast<quint64>(blockSize);

    // 2. Хэшируем буфер. SHA-256 выдаст 32 байта идеального "белого шума"
    QByteArray hashResult = QCryptographicHash::hash(inputBuffer, QCryptographicHash::Sha256);

    // 3. Достаем первые 8 байт (размер int + u16 + u16) для заполнения структуры
    QDataStream reader(hashResult);
    int raw_q;
    u16 raw_s0;
    u16 raw_s1;

    reader >> raw_q >> raw_s0 >> raw_s1;

    // 4. Нормализуем q без магических чисел.
    // Задаем прозрачный диапазон, например, от 32 до 63 тактов (всего 32 варианта)
    int q = 32 + (std::abs(raw_q) % 32);

    return { q, raw_s0, raw_s1 };
}

inline static lfsr_hash::u128 gen_hash_for_pass_gen(const QString& text, uint seed)
{
    password::hash_gen.reset();
    lfsr_hash::u128 hash = utils::pin_to_hash(text.toUtf8());
    constexpr size_t blockSize = 64;
    {
        auto bytes = text.toUtf8();
        for (int i=0; i<sizeof(uint); ++i) {
            bytes.push_back(static_cast<char>(seed % 256));
            seed >>= 8;
        }
        padd<blockSize>(bytes);
        const auto bytesRead = bytes.size();
        {
            using namespace lfsr_hash;
            const salt original_size_salt = utils::get_salt(bytesRead, blockSize);
            const size_t n = bytesRead / blockSize;
            const auto& bytes_span = std::span(reinterpret_cast<const std::byte*>(bytes.constData()), bytes.size());
            password::hash_gen.add_salt(original_size_salt);
            for (size_t i = 0; i < n; ++i) {
                auto chunk = bytes_span.subspan(i*blockSize, blockSize);
                auto inner_hash = hash128(password::hash_gen, chunk);
                hash.first ^= inner_hash.first;
                hash.second ^= inner_hash.second;
            }
        }
        utils::erase_bytes(bytes);
    }
    return hash;
}

inline static lfsr_hash::u128 gen_hash_for_storage(const QString& text)
{
    password::hash_gen.reset();

    constexpr size_t blockSize = 72;

    auto bytes = text.toUtf8();

    // Рассчитываем размер с учетом паддинга ISO/IEC 9797-1 заранее!
    const int old_size = bytes.size();
    const int res = (old_size + 1) % blockSize;
    const int padding_needed = 1 + (res != 0 ? blockSize - res : 0);

    // Резервируем память ДО заполнения данными, чтобы избежать realloc в куче
    bytes.reserve(old_size + padding_needed);

    lfsr_hash::u128 hash_fs = utils::pin_to_hash(bytes);

    padd<blockSize>(bytes);
    const auto bytesRead = bytes.size();
    {
        using namespace lfsr_hash;
        const salt original_size_salt = utils::get_salt(bytesRead, blockSize);
        const size_t n = bytesRead / blockSize;
        const auto& bytes_span = std::span(reinterpret_cast<const std::byte*>(bytes.constData()), bytes.size());
        password::hash_gen.add_salt(original_size_salt);
        for (size_t i = 0; i < n; ++i) {
            auto chunk = bytes_span.subspan(i*blockSize, blockSize);
            auto inner_hash = hash128(password::hash_gen, chunk);
            hash_fs.first ^= inner_hash.first;
            hash_fs.second ^= inner_hash.second;
        }
    }

    utils::erase_bytes(bytes);

    return hash_fs;
}

inline static lfsr_hash::u128 gen_hash_for_encryption(const QString& text)
{
    password::hash_gen.reset();
    constexpr size_t blockSize = 128;

    // 1. Делаем конвертацию ОДИН раз
    auto bytes = text.toUtf8();

    // 2. Рассчитываем размер с учетом паддинга ISO/IEC 9797-1 заранее!
    const int old_size = bytes.size();
    const int res = (old_size + 1) % blockSize;
    const int padding_needed = 1 + (res != 0 ? blockSize - res : 0);

    // Резервируем память ДО заполнения данными, чтобы избежать realloc в куче
    bytes.reserve(old_size + padding_needed);

    // 3. Сначала считаем базовый хэш по еще не дополненным байтам (вместо text.toUtf8())
    lfsr_hash::u128 hash_enc = utils::pin_to_hash(bytes);

    // 4. Применяем паддинг (теперь resize не вызовет перевыделения памяти, так как есть reserve)
    padd<blockSize>(bytes);
    const auto bytesRead = bytes.size();

    {
        using namespace lfsr_hash;
        const salt original_size_salt = utils::get_salt(bytesRead, blockSize);
        const size_t n = bytesRead / blockSize;
        const auto& bytes_span = std::span(reinterpret_cast<const std::byte*>(bytes.constData()), bytes.size());

        password::hash_gen.add_salt(original_size_salt);

        for (size_t i = 0; i < n; ++i) {
            auto chunk = bytes_span.subspan(i * blockSize, blockSize);
            auto inner_hash = hash128(password::hash_gen, chunk);
            hash_enc.first ^= inner_hash.first;
            hash_enc.second ^= inner_hash.second;
        }
    }

    // 5. Теперь эта очистка гарантированно сотрет ЕДИНСТВЕННУЮ UTF-8 копию пароля
    utils::erase_bytes(bytes);

    return hash_enc;
}

inline static lfsr_hash::u128 gen_hash_for_inner_encryption(const QString& text)
{
    password::hash_gen.reset();
    constexpr size_t blockSize = 96;

    // 1. Делаем конвертацию ОДИН раз
    auto bytes = text.toUtf8();

    // 2. Рассчитываем размер с учетом паддинга ISO/IEC 9797-1 заранее!
    const int old_size = bytes.size();
    const int res = (old_size + 1) % blockSize;
    const int padding_needed = 1 + (res != 0 ? blockSize - res : 0);

    // Резервируем память ДО заполнения данными, чтобы избежать realloc в куче
    bytes.reserve(old_size + padding_needed);

    // 3. Сначала считаем базовый хэш по еще не дополненным байтам (вместо text.toUtf8())
    lfsr_hash::u128 hash_enc = utils::pin_to_hash(bytes);

    // 4. Применяем паддинг (теперь resize не вызовет перевыделения памяти, так как есть reserve)
    padd<blockSize>(bytes);
    const auto bytesRead = bytes.size();

    {
        using namespace lfsr_hash;
        const salt original_size_salt = utils::get_salt(bytesRead, blockSize);
        const size_t n = bytesRead / blockSize;
        const auto& bytes_span = std::span(reinterpret_cast<const std::byte*>(bytes.constData()), bytes.size());

        password::hash_gen.add_salt(original_size_salt);

        for (size_t i = 0; i < n; ++i) {
            auto chunk = bytes_span.subspan(i * blockSize, blockSize);
            auto inner_hash = hash128(password::hash_gen, chunk);
            hash_enc.first ^= inner_hash.first;
            hash_enc.second ^= inner_hash.second;
        }
    }

    // 5. Теперь эта очистка гарантированно сотрет ЕДИНСТВЕННУЮ UTF-8 копию пароля
    utils::erase_bytes(bytes);

    return hash_enc;
}

inline static void request_passwords(QFutureWatcher<QVector<lfsr8::u64>>& watcher, int password_len) {
    const int Nw = (password_len * constants::num_of_passwords) / constants::password_len_per_u64 + 1;
    watcher.setFuture( password::worker->gen_n(password::pass_gen, Nw) );
    watcher.waitForFinished();

    {
        QMutexLocker locker(&password::pswd_buff->mMutex);

        // Перед записью нового пула, если старый буфер не пуст,
        // принудительно затираем его остатки через volatile
        if (!password::pswd_buff->mPasswords.isEmpty()) {
            volatile lfsr8::u64* data_ptr = reinterpret_cast<volatile lfsr8::u64*>(password::pswd_buff->mPasswords.data());
            std::fill_n(data_ptr, password::pswd_buff->mPasswords.size(), 0);
        }

        password::pswd_buff->mPasswords = watcher.result();
    }
    qDebug() << "Passwords were requested.";
}

inline static QString try_to_get_password(int len, int level)
{
    auto* buffer = password::pswd_buff();
    QMutexLocker locker(&buffer->mMutex);

    QString pswd;
    if (len <= 0) return pswd;

    // ОПТИМИЗАЦИЯ: Резервируем память под строку пароля заранее,
    // чтобы избежать перевыделений в куче внутри цикла while
    pswd.reserve(len);

    while (pswd.size() < len) {
        if (buffer->mPasswords.empty()) {
            // Буфер опустел — перед выходом очищаем частично собранную строку,
            // чтобы не возвращать огрызок пароля, и уберечь данные
            pswd.clear();
            return {};
        }

        // КРИПТО-ИСПРАВЛЕНИЕ: Безопасное извлечение с занулением памяти в векторе
        lfsr8::u64 raw64 = buffer->mPasswords.last(); // Берем число

        // Затираем ячейку прямо в куче вектора mPasswords через volatile
        volatile lfsr8::u64* cell_ptr = reinterpret_cast<volatile lfsr8::u64*>(&buffer->mPasswords.last());
        *cell_ptr = 0;

        buffer->mPasswords.removeLast(); // Теперь Qt может безопасно уменьшить размер

        // Разделение разрядов (побитовые операции эффективны)
        uint32_t high = static_cast<uint32_t>(raw64 >> 32);
        uint32_t low  = static_cast<uint32_t>(raw64 & 0xFFFFFFFF);

        if (level == 0) {
            pswd.append(encode_u32_simple_level(low));
            if (pswd.size() < len) {
                pswd.append(encode_u32_simple_level(high));
            }
        } else {
            pswd.append(encode_u32_hard_level(low));
            if (pswd.size() < len) {
                pswd.append(encode_u32_hard_level(high));
            }
        }

        // Стираем локальную копию случайного числа в стеке
        volatile lfsr8::u64* p_raw = &raw64;
        *p_raw = 0;
    }

    if (pswd.size() > len) {
        pswd.resize(len);
    }
    return pswd;
}

inline static QString generate_storage_name(lfsr_hash::u128 hash)
{
    using namespace lfsr_hash;
    password::hash_gen.reset();
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

    const auto& bytes_span = std::span(reinterpret_cast<const std::byte*>(b_), buffer_len);
    password::hash_gen.add_salt(utils::hash_to_salt(hash));
    u128 hash2 = hash128(password::hash_gen, bytes_span);
    QString name {};
    for (int i=0; i<8; ++i) {
        name.push_back( allowed[(hash2.first >> 8*i) % 36] );
        name.push_back( allowed[(hash2.second >> 8*i) % 36] );
    }
    for (int i=0; i<8; ++i) {
        b_[16 + 2*i] = hash2.first >> 8*i;
        b_[16 + 2*i + 1] = hash2.second >> 8*i;
    }
    password::hash_gen.add_salt(utils::hash_to_salt(hash2));
    u128 hash3 = hash128(password::hash_gen, bytes_span);
    for (int i=0; i<8; ++i) {
        name.push_back( allowed[(hash3.first >> 8*i) % 36] );
        name.push_back( allowed[(hash3.second >> 8*i) % 36] );
    }
    utils::erase_bytes(b_, buffer_len);
    return name;
}

}
