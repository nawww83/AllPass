#pragma once

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
#include <cstring>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#endif

#include "constants.h"
#include "lfsr_hash.h"
#include "stream_cipher.h"

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

namespace utils {

// Базовая функция очистки сырого буфера
inline void erase_bytes(uint8_t *b, std::size_t len)
{
    if (!b || len == 0)
        return;

#if defined(_WIN32)
    SecureZeroMemory(b, len);
#elif defined(__linux__) || defined(__GLIBC__)
    explicit_bzero(b, len);
#elif defined(__APPLE__)
    // В macOS/iOS memset_s доступна по умолчанию
    memset_s(b, len, 0, len);
#elif defined(__STDC_LIB_EXT1__) && defined(__STDC_WANT_LIB_EXT1__) && (__STDC_WANT_LIB_EXT1__ == 1)
    memset_s(b, len, 0, len);
#else
    volatile uint8_t *p = b;
    while (len--) {
        *p++ = 0;
    }
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(b) : "memory");
#endif
#endif
}

// Функция очистки QByteArray
inline void erase_bytes(QByteArray& b) {
    if (b.isEmpty()) return;

    // Передаем указатель на внутренний неконстантный буфер Qt
    erase_bytes(reinterpret_cast<uint8_t*>(b.data()), b.size());
    b.clear(); // Сбрасываем размер в Qt
}

// Функция очистки QString (UTF-16)
inline void erase_string(QString& str) {
    if (str.isEmpty()) return;

    // Размер в байтах для UTF-16 — это количество символов * 2
    int size_in_bytes = str.size() * sizeof(char16_t);

    erase_bytes(reinterpret_cast<uint8_t*>(str.data()), size_in_bytes);
    str.clear(); // Безопасно очищаем объект Qt
}

// Инициализация состояния генератора ПСЧ
inline lfsr_rng::STATE fill_state_by_hash(lfsr_hash::u128 hash) {
    lfsr_rng::STATE st;
    for (int i = 0; i < 8; ++i) {
        lfsr_hash::u16 byte_1 = 255 & (hash.first >> (8 * i));
        lfsr_hash::u16 byte_2 = 255 & (hash.second >> (8 * i));
        st[i] = (byte_1 << 8) | byte_2;
    }
    return st;
}

// Безопасная очистка 128-битного хэша по ССЫЛКЕ
inline void clear_lfsr_hash(lfsr_hash::u128 &hash)
{
    erase_bytes(reinterpret_cast<uint8_t *>(&hash), sizeof(hash));
}

// Безопасная очистка внутреннего состояния генератора (массива std::array)
inline void clear_lfsr_rng_state(lfsr_rng::STATE &st)
{
    // Безопасно затираем всё состояние rng, используя sizeof для точного размера
    erase_bytes(reinterpret_cast<uint8_t *>(&st), sizeof(st));
}

inline char xor_val(const QByteArray& data) {
    if (data.isEmpty()) return '\0';

    const char* ptr = data.constData();
    char result = ptr[0];
    const int size = data.size();
    for (int j = 1; j < size; ++j) {
        result ^= ptr[j];
    }
    return result;
}

inline QByteArray xor_bytes(const QByteArray& data_1, const QByteArray& data_2) {
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

inline QByteArray xor_data_by_seed(const QByteArray& data, uint32_t seed) {
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
inline void padd(QByteArray& data) {
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

inline void dpadd(QByteArray& data) {
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

inline uint8_t rotl8(uint8_t value, unsigned int count)
{
    const unsigned int mask = CHAR_BIT*sizeof(value) - 1;
    count &= mask;
    return (value << count) | (value >> ( (-count) & mask ));
}

inline uint8_t rotr8(uint8_t value, unsigned int count)
{
    const unsigned int mask = CHAR_BIT*sizeof(value) - 1;
    count &= mask;
    return (value >> count) | (value << ( (-count) & mask ));
}

inline QString encode_u32_simple_level(lfsr8::u32 sample)
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

inline QString encode_u32_hard_level(lfsr8::u32 sample)
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

inline QByteArray lfsr_hash_to_bytes(lfsr_hash::u128 hash)
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

inline lfsr_hash::u128 bytes_to_lfsr_hash(const QByteArray& input)
{
    constexpr size_t hash_size = sizeof(lfsr_hash::u128); // Ровно 16 байт
    lfsr_hash::u128 hash = {0, 0}; // Инициализируем дефолтными нулями

    // Проверяем, что входной массив содержит достаточно байт.
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

inline lfsr_hash::salt hash_to_salt(lfsr_hash::u128 hash)
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

inline lfsr_hash::salt get_salt(size_t bytesRead, size_t blockSize)
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

}
