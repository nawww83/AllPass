#ifndef UTILS_GLOBAL_H
#define UTILS_GLOBAL_H

#include "global_data.h"
#include "utils.h"

namespace utils_global {

using namespace utils;

inline static void set_global_pin(const PinCode &pin)
{
    using namespace password;
    pin_code = pin;
}

inline static void back_up_pin()
{
    using namespace password;
    if (pin_code.length() != 0)
        old_pin_code = pin_code;
}

inline static void restore_pin()
{
    using namespace password;
    if (old_pin_code.length() != 0)
        pin_code = old_pin_code;
}

inline static bool check_pin(const PinCode &pin)
{
    using namespace password;
    if (pin_code.mPinCode.size() != pin.mPinCode.size()) {
        return false;
    }
    int diff = 0;
    for (std::size_t i = 0; i < pin_code.mPinCode.size(); ++i) {
        // Побитовое ИЛИ накапливает любые различия между элементами
        diff |= (pin_code.mPinCode.at(i) - pin.mPinCode.at(i));
    }
    return diff == 0;
}

// Инициализация ключей
inline static void fill_key_by_hash128(lfsr_hash::u128 hash)
{
    auto x = hash.first;
    auto y = hash.second;

    {
        using password::key;
        // Операция & 0xFFFF (маска) эквивалентна % 65536, но выполняется процессором мгновенно
        key->set_key(x & 0xFFFF, 3);
        key->set_key((x >> 16) & 0xFFFF, 2);
        key->set_key((x >> 32) & 0xFFFF, 1);
        key->set_key((x >> 48) & 0xFFFF, 0);

        key->set_key(y & 0xFFFF, 7);
        key->set_key((y >> 16) & 0xFFFF, 6);
        key->set_key((y >> 32) & 0xFFFF, 5);
        key->set_key((y >> 48) & 0xFFFF, 4);
    }

    // Кроссплатформенное затирание локальной копии hash на GCC/Clang/MSVC
    volatile uint64_t *px = &x;
    volatile uint64_t *py = &y;
    *px = 0;
    *py = 0;
}

inline static void fill_buffer_from_pin(uint8_t (&buffer)[64])
{
    const auto &code = password::pin_code.mPinCode;

    // 1. Упаковываем ПИН-код в массив байт
    QByteArray inputBytes;
    QDataStream writer(&inputBytes, QIODevice::WriteOnly);
    for (int i = 0; i < constants::pin_code_len; ++i) {
        writer << static_cast<char>('0' + code.at(i));
    }

    // 2. Хэшируем с помощью SHA-512 (результат — ровно 64 байта)
    QByteArray hashResult = QCryptographicHash::hash(inputBytes, QCryptographicHash::Sha512);

    // 3. Безопасно копируем 64 байта в целевой массив
    std::copy_n(reinterpret_cast<const uint8_t *>(hashResult.constData()), 64, buffer);
}

inline static lfsr_hash::salt pin_to_salt(const QByteArray &inner_salt)
{
    using namespace lfsr_hash;
    QByteArray inputBuffer;
    QDataStream writer(&inputBuffer, QIODevice::WriteOnly);
    const auto &code = password::pin_code.mPinCode;

    for (int i = 0; i < constants::pin_code_len; ++i) {
        writer << static_cast<char>('0' + code.at(i));
    }
    writer << inner_salt;
    QByteArray hashResult = QCryptographicHash::hash(inputBuffer, QCryptographicHash::Sha256);

    QDataStream reader(hashResult);
    int raw_q;
    u16 raw_s0;
    u16 raw_s1;
    reader >> raw_q >> raw_s0 >> raw_s1;
    int q = 32 + (std::abs(raw_q) % 32);
    return {q, raw_s0, raw_s1};
}

inline static lfsr_hash::u128 pin_to_hash(const QByteArray &inner_salt)
{
    using namespace lfsr_hash;
    uint8_t b_[64];
    fill_buffer_from_pin(b_);
    password::hash_gen.add_salt(pin_to_salt(inner_salt));
    const auto hash = hash128(password::hash_gen, std::as_bytes(std::span(b_)));
    utils::erase_bytes(b_, 64);
    return hash;
}

inline static lfsr_hash::u128 gen_hash_for_pass_gen(const QString &text, uint seed)
{
    password::hash_gen.reset();
    lfsr_hash::u128 hash = utils_global::pin_to_hash(text.toUtf8());
    constexpr size_t blockSize = 64;
    {
        auto bytes = text.toUtf8();
        for (int i = 0; i < sizeof(uint); ++i) {
            bytes.push_back(static_cast<char>(seed % 256));
            seed >>= 8;
        }
        padd<blockSize>(bytes);
        const auto bytesRead = bytes.size();
        {
            using namespace lfsr_hash;
            const salt original_size_salt = utils::get_salt(bytesRead, blockSize);
            const size_t n = bytesRead / blockSize;
            const auto &bytes_span = std::span(reinterpret_cast<const std::byte *>(
                                                   bytes.constData()),
                                               bytes.size());
            password::hash_gen.add_salt(original_size_salt);
            for (size_t i = 0; i < n; ++i) {
                auto chunk = bytes_span.subspan(i * blockSize, blockSize);
                auto inner_hash = hash128(password::hash_gen, chunk);
                hash.first ^= inner_hash.first;
                hash.second ^= inner_hash.second;
            }
        }
        utils::erase_bytes(bytes);
    }
    return hash;
}

inline static lfsr_hash::u128 gen_hash_for_storage(const QString &text)
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

    lfsr_hash::u128 hash_fs = utils_global::pin_to_hash(bytes);

    padd<blockSize>(bytes);
    const auto bytesRead = bytes.size();
    {
        using namespace lfsr_hash;
        const salt original_size_salt = utils::get_salt(bytesRead, blockSize);
        const size_t n = bytesRead / blockSize;
        const auto &bytes_span = std::span(reinterpret_cast<const std::byte *>(bytes.constData()),
                                           bytes.size());
        password::hash_gen.add_salt(original_size_salt);
        for (size_t i = 0; i < n; ++i) {
            auto chunk = bytes_span.subspan(i * blockSize, blockSize);
            auto inner_hash = hash128(password::hash_gen, chunk);
            hash_fs.first ^= inner_hash.first;
            hash_fs.second ^= inner_hash.second;
        }
    }

    utils::erase_bytes(bytes);

    return hash_fs;
}

inline static lfsr_hash::u128 gen_hash_for_encryption(const QString &text)
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
    lfsr_hash::u128 hash_enc = utils_global::pin_to_hash(bytes);

    // 4. Применяем паддинг (теперь resize не вызовет перевыделения памяти, так как есть reserve)
    padd<blockSize>(bytes);
    const auto bytesRead = bytes.size();

    {
        using namespace lfsr_hash;
        const salt original_size_salt = utils::get_salt(bytesRead, blockSize);
        const size_t n = bytesRead / blockSize;
        const auto &bytes_span = std::span(reinterpret_cast<const std::byte *>(bytes.constData()),
                                           bytes.size());

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

inline static lfsr_hash::u128 gen_hash_for_inner_encryption(const QString &text)
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
    lfsr_hash::u128 hash_enc = utils_global::pin_to_hash(bytes);

    // 4. Применяем паддинг (теперь resize не вызовет перевыделения памяти, так как есть reserve)
    padd<blockSize>(bytes);
    const auto bytesRead = bytes.size();

    {
        using namespace lfsr_hash;
        const salt original_size_salt = utils::get_salt(bytesRead, blockSize);
        const size_t n = bytesRead / blockSize;
        const auto &bytes_span = std::span(reinterpret_cast<const std::byte *>(bytes.constData()),
                                           bytes.size());

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

inline static void request_passwords(QFutureWatcher<QVector<lfsr8::u64>> &watcher, int password_len)
{
    const int Nw = (password_len * constants::num_of_passwords) / constants::password_len_per_u64
                   + 1;
    watcher.setFuture(password::worker->gen_n(password::pass_gen, Nw));
    watcher.waitForFinished();

    {
        QMutexLocker locker(&password::pswd_buff->mMutex);

        // Перед записью нового пула, если старый буфер не пуст,
        // принудительно затираем его остатки через volatile
        if (!password::pswd_buff->mPasswords.isEmpty()) {
            volatile lfsr8::u64 *data_ptr = reinterpret_cast<volatile lfsr8::u64 *>(
                password::pswd_buff->mPasswords.data());
            std::fill_n(data_ptr, password::pswd_buff->mPasswords.size(), 0);
        }

        password::pswd_buff->mPasswords = watcher.result();
    }
    qDebug() << "Passwords were requested.";
}

inline static QString try_to_get_password(int len, int level)
{
    auto *buffer = password::pswd_buff();
    QMutexLocker locker(&buffer->mMutex);

    QString pswd;
    if (len <= 0)
        return pswd;

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
        volatile lfsr8::u64 *cell_ptr = reinterpret_cast<volatile lfsr8::u64 *>(
            &buffer->mPasswords.last());
        *cell_ptr = 0;

        buffer->mPasswords.removeLast(); // Теперь Qt может безопасно уменьшить размер

        // Разделение разрядов (побитовые операции эффективны)
        uint32_t high = static_cast<uint32_t>(raw64 >> 32);
        uint32_t low = static_cast<uint32_t>(raw64 & 0xFFFFFFFF);

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
        volatile lfsr8::u64 *p_raw = &raw64;
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
    static constexpr auto allowed{"0123456789abcdefghijklmnopqrstuvwxyz"};
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
    if (buffer_len < 2 * 8) {
        return "";
    }
    for (int i = 0; i < 8; ++i) {
        b_[2 * i] = hash.first >> 8 * i;
        b_[2 * i + 1] = hash.second >> 8 * i;
    }

    const auto &bytes_span = std::span(reinterpret_cast<const std::byte *>(b_), buffer_len);
    password::hash_gen.add_salt(utils::hash_to_salt(hash));
    u128 hash2 = hash128(password::hash_gen, bytes_span);
    QString name;
    for (int i = 0; i < 8; ++i) {
        name.push_back(allowed[(hash2.first >> 8 * i) % 36]);
        name.push_back(allowed[(hash2.second >> 8 * i) % 36]);
    }
    for (int i = 0; i < 8; ++i) {
        b_[16 + 2 * i] = hash2.first >> 8 * i;
        b_[16 + 2 * i + 1] = hash2.second >> 8 * i;
    }
    password::hash_gen.add_salt(utils::hash_to_salt(hash2));
    u128 hash3 = hash128(password::hash_gen, bytes_span);
    for (int i = 0; i < 8; ++i) {
        name.push_back(allowed[(hash3.first >> 8 * i) % 36]);
        name.push_back(allowed[(hash3.second >> 8 * i) % 36]);
    }
    utils::erase_bytes(b_, buffer_len);
    return name;
}

} // namespace utils_global

#endif // UTILS_GLOBAL_H
