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

    // Принудительно делаем буфер уникальным, гарантируя,
    // что мы очищаем единственный экземпляр данных
    b.detach();

    // Передаем указатель на внутренний неконстантный буфер Qt
    erase_bytes(reinterpret_cast<uint8_t*>(b.data()), b.size());
    b.clear(); // Сбрасываем размер в Qt
}

// Функция очистки QString (UTF-16)
inline void erase_string(QString& str) {
    if (str.isEmpty()) return;

    str.detach();

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

inline uint32_t seed_from_bytes_pop_back(QByteArray &data)
{
    uint32_t seed = 0;
    constexpr size_t seed_size = sizeof(uint32_t); // 4 байта

    if (data.size() < static_cast<int>(seed_size)) {
        return seed;
    }

    // 1. Гарантируем монопольное владение буфером перед изменением
    data.detach();

    const int seed_offset = data.size() - static_cast<int>(seed_size);
    const uint8_t *const src_ptr = reinterpret_cast<const uint8_t *>(data.constData())
                                   + seed_offset;

    // 2. Точно восстанавливаем Little-Endian seed, записанный функцией seed_to_bytes,
    // считывая его с конца массива (от seed_offset до конца)
    seed = static_cast<uint32_t>(src_ptr[0]) | (static_cast<uint32_t>(src_ptr[1]) << 8)
           | (static_cast<uint32_t>(src_ptr[2]) << 16) | (static_cast<uint32_t>(src_ptr[3]) << 24);

    // 3. ГАРАНТИРОВАННО выжигаем извлекаемый сид в ОЗУ перед обрезкой массива.
    // Используем системно-защищенный erase_bytes вместо ручного std::memset/цикла.
    uint8_t *tail_ptr = reinterpret_cast<uint8_t *>(data.data()) + seed_offset;
    utils::erase_bytes(tail_ptr, seed_size);

    // 4. Отрезаем хвост за один шаг O(1).
    // Метод resize() одинаков для всех версий Qt. В хвосте кучи остаются только честные нули.
    data.resize(seed_offset);

    return seed;
}

inline QByteArray xor_data_by_seed(const QByteArray &data, uint32_t seed)
{
    QByteArray result;
    const int size = data.size();
    if (size <= 0)
        return result;

    result.resize(size);

    const char *src = data.constData();
    char *dest = result.data();

    // 1. Готовим буфер под внутреннее состояние генератора гаммы
    QByteArray stateBuffer;
    stateBuffer.resize(sizeof(uint32_t) + sizeof(uint32_t)); // 8 байт

    // Записываем seed в первые 4 байта состояния
    std::memcpy(stateBuffer.data(), &seed, sizeof(uint32_t));

    uint32_t counter = 0;
    int processed = 0;

    // Временный буфер для текущего блока гаммы SHA-256 (32 байта)
    QByteArray currentGammaBlock;

    // 2. Потоковое гаммирование блоками по 32 байта
    while (processed < size) {
        // Записываем постоянно увеличивающийся счетчик в оставшиеся 4 байта состояния
        std::memcpy(stateBuffer.data() + sizeof(uint32_t), &counter, sizeof(uint32_t));

        // Генерируем 32 байта криптографически стойкой гаммы на основе SHA-256
        currentGammaBlock = QCryptographicHash::hash(stateBuffer, QCryptographicHash::Sha256);

        const char *gammaPtr = currentGammaBlock.constData();
        int chunk_size = std::min(32, size - processed);

        // Накладываем XOR
        for (int i = 0; i < chunk_size; ++i) {
            dest[processed + i] = src[processed + i] ^ gammaPtr[i];
        }

        processed += chunk_size;
        counter++;
    }

    // 3. Гарантированно выжигаем ключевой материал в RAM перед выходом
    utils::erase_bytes(stateBuffer);
    utils::erase_bytes(currentGammaBlock);
    volatile uint32_t *p_seed = &seed;
    *p_seed = 0;

    return result;
}

template<int block_size>
inline void padd(QByteArray &data)
{
    // Гарантируем монопольное владение буфером
    data.detach();

    const int old_size = data.size();

    // Расчет размера по стандарту ISO/IEC 9797-1
    const int res = (old_size + 1) % block_size;
    const int padding_needed = 1 + (res != 0 ? block_size - res : 0);
    const int new_size = old_size + padding_needed;

    // Метод fill() работает одинаково во всех версиях Qt (и в Qt 5, и в Qt 6).
    // Он сразу выделяет нужный объем памяти и гарантированно заполняет его нулями.
    QByteArray clean_padded_buffer;
    clean_padded_buffer.fill('\0', new_size);

    // Копируем исходные конфиденциальные данные
    std::memcpy(clean_padded_buffer.data(), data.constData(), old_size);

    // Жестко выжигаем старый незануленный буфер в куче перед заменой
    utils::erase_bytes(data);

    // Подменяем буфер и выставляем ISO-маркер 0x80
    data = std::move(clean_padded_buffer);
    data[old_size] = static_cast<char>(0x80);
}

inline void dpadd(QByteArray &data)
{
    if (data.isEmpty()) {
        return;
    }

    data.detach();

    const char *const begin = data.constData();
    const char *ptr = begin + data.size() - 1;

    // Пропускаем нули с конца
    while (ptr >= begin && *ptr == '\0') {
        --ptr;
    }

    if (ptr >= begin && *ptr == static_cast<char>(0x80)) {
        const int real_size = static_cast<int>(ptr - begin);
        const int padding_size = data.size() - real_size;

        // Перед уменьшением размера затираем отсекаемую область памяти (включая 0x80),
        // чтобы расшифрованные данные не оставались в Heap-мусоре.
        uint8_t *padding_start = reinterpret_cast<uint8_t *>(data.data() + real_size);
        utils::erase_bytes(padding_start, padding_size);

        // Стандартный resize() для уменьшения размера работает одинаково во всех версиях Qt
        data.resize(real_size);
    }
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
