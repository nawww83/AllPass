#ifndef UTILS_GLOBAL_H
#define UTILS_GLOBAL_H

#include <QCryptographicHash>
#include <QRandomGenerator>

#include "collatz_cipher.h"
#include "global_data.h"
#include "utils.h"

namespace utils_global {

using namespace utils;

inline void set_global_pin(const PinCode &pin)
{
    using namespace password;

    // Инициализируем сеансовую соль, если она пустая
    if (global_session_salt.isEmpty()) {
        global_session_salt.resize(32);
        QRandomGenerator::securelySeeded().fillRange(reinterpret_cast<quint32 *>(
                                                         global_session_salt.data()),
                                                     global_session_salt.size() / sizeof(quint32));
    }

    // Создаем локальный QByteArray для ASCII-символов
    QByteArray rawPinBytes;
    pin.to_numeric_bytes(rawPinBytes); // Заполняем его символами '0'..'9'

    // Хэшируем для верификации
    QCryptographicHash hasher(QCryptographicHash::Sha256);
    hasher.addData(rawPinBytes);
    hasher.addData(global_session_salt);
    hashed_pin_verify = hasher.result();

    // Шифруем тело ПИН-кода для хранения в RAM
    QString encryptedB64 = CollatzCipher256::encrypt(rawPinBytes, global_session_salt);
    encrypted_raw_pin = encryptedB64.toUtf8();

    // Теперь мы можем честно затереть этот буфер
    utils::erase_bytes(rawPinBytes);
}

inline QByteArray get_global_pin_decrypted()
{
    using namespace password;
    if (encrypted_raw_pin.isEmpty() || global_session_salt.isEmpty()) {
        return QByteArray();
    }

    // Расшифровываем ПИН-код сеансовой солью на долю секунды
    QByteArray decryptedPin = CollatzCipher256::decrypt(QString::fromUtf8(encrypted_raw_pin),
                                                        global_session_salt);

    // Возвращаем сырые байты (вызывающий код обязан очистить их после использования!)
    return decryptedPin;
}

inline void back_up_pin()
{
    using namespace password;

    // Проверяем, что ПИН-код был успешно инициализирован в сессии
    if (!hashed_pin_verify.isEmpty() && !encrypted_raw_pin.isEmpty()) {
        old_hashed_pin_verify = hashed_pin_verify;
        old_encrypted_raw_pin = encrypted_raw_pin;
    }
}

inline void restore_pin()
{
    using namespace password;

    // Проверяем, что в бэкапе есть сохраненные данные
    if (!old_hashed_pin_verify.isEmpty() && !old_encrypted_raw_pin.isEmpty()) {
        hashed_pin_verify = old_hashed_pin_verify;
        encrypted_raw_pin = old_encrypted_raw_pin;
    }
}

// Безопасная проверка введенного ПИН-кода на соответствие хэшу сессии
inline bool check_pin(const PinCode &pin)
{
    using namespace password;
    if (hashed_pin_verify.isEmpty() || global_session_salt.isEmpty())
        return false;

    // 1. Заполняем временный буфер символами
    QByteArray rawPinBytes;
    pin.to_numeric_bytes(rawPinBytes);

    // 2. Считаем хэш проверяемого ПИНа
    QCryptographicHash hasher(QCryptographicHash::Sha256);
    hasher.addData(rawPinBytes);
    hasher.addData(global_session_salt);
    QByteArray calculated_hash = hasher.result();

    // 3. Сразу же уничтожаем открытые символы ПИНа в RAM
    utils::erase_bytes(rawPinBytes);

    // 4. Побайтовое constant-time сравнение хэшей...
    if (calculated_hash.size() != hashed_pin_verify.size()) {
        utils::erase_bytes(calculated_hash);
        return false;
    }
    int diff = 0;
    for (int i = 0; i < calculated_hash.size(); ++i) {
        diff |= (static_cast<uint8_t>(calculated_hash.at(i))
                 ^ static_cast<uint8_t>(hashed_pin_verify.at(i)));
    }
    utils::erase_bytes(calculated_hash);
    return diff == 0;
}

// Инициализация ключей
inline void fill_key_by_hash128(const lfsr_hash::u128 &hash)
{
    auto x = hash.first;
    auto y = hash.second;

    {
        using password::key;
        // Операция & 0xFFFF (маска) эквивалентна % 65536.
        key->set_key(x & 0xFFFF, 3);
        key->set_key((x >> 16) & 0xFFFF, 2);
        key->set_key((x >> 32) & 0xFFFF, 1);
        key->set_key((x >> 48) & 0xFFFF, 0);

        key->set_key(y & 0xFFFF, 7);
        key->set_key((y >> 16) & 0xFFFF, 6);
        key->set_key((y >> 32) & 0xFFFF, 5);
        key->set_key((y >> 48) & 0xFFFF, 4);
    }

    volatile uint64_t *px = &x;
    volatile uint64_t *py = &y;
    *px = 0;
    *py = 0;
}

inline void fill_buffer_from_pin(uint8_t (&buffer)[64])
{
    // 1. Обнуляем целевой буфер перед заполнением для безопасности
    std::memset(buffer, 0, sizeof(buffer));

    // 2. Безопасно расшифровываем оригинальный ПИН-код из сеансового хранилища
    QByteArray decryptedPinBytes = get_global_pin_decrypted();

    if (decryptedPinBytes.isEmpty()) {
        return; // Если ПИН не задан, выходим (буфер останется заполнен нулями)
    }

    // 3. Копируем ПИН-код в ваш массив (буфер)
    // Так как размер буфера 64 байта, а ПИН-код намного короче, используем безопасный размер
    std::size_t bytesToCopy = std::min(static_cast<std::size_t>(decryptedPinBytes.size()),
                                       sizeof(buffer));
    std::memcpy(buffer, decryptedPinBytes.constData(), bytesToCopy);

    // 4. Немедленно уничтожаем временную сырую копию ПИН-кода в оперативной памяти
    utils::erase_bytes(decryptedPinBytes);
}

inline lfsr_hash::salt pin_to_salt(const QByteArray &inputSalt)
{
    // 1. Инициализируем пустую структуру соли по умолчанию
    lfsr_hash::salt result;
    std::memset(&result, 0, sizeof(result));

    // 2. Безопасно расшифровываем оригинальный ПИН-код из сеансового хранилища
    QByteArray decryptedPinBytes = get_global_pin_decrypted();
    if (decryptedPinBytes.isEmpty()) {
        return result;
    }

    // 3. Вычисляем хэш от ПИН-кода и переданной входной соли (как это требовалось вашей логике)
    QCryptographicHash hasher(QCryptographicHash::Sha256);
    hasher.addData(decryptedPinBytes);
    hasher.addData(inputSalt);
    QByteArray hashRes = hasher.result();

    // 4. Копируем результат хэширования в целевую структуру lfsr_hash::salt
    std::size_t bytesToCopy = std::min(static_cast<std::size_t>(hashRes.size()), sizeof(result));
    std::memcpy(&result, hashRes.constData(), bytesToCopy);

    // 5. Немедленно уничтожаем временную сырую копию ПИН-кода и хэша в RAM
    utils::erase_bytes(decryptedPinBytes);
    utils::erase_bytes(hashRes);

    return result;
}

inline lfsr_hash::u128 pin_to_hash(const QByteArray &inner_salt)
{
    using namespace lfsr_hash;
    constexpr size_t blockSize = 64;
    uint8_t b_[blockSize];
    fill_buffer_from_pin(b_);
    password::hash_gen.add_salt(pin_to_salt(inner_salt));
    const auto hash = hash128(password::hash_gen, std::as_bytes(std::span(b_)));
    utils::erase_bytes(b_, blockSize);
    return hash;
}

inline lfsr_hash::u128 gen_hash_for_pass_gen(const QByteArray &textBytes, uint seed)
{
    password::hash_gen.reset();

    // Передаем сырые байты напрямую вместо text.toUtf8()
    lfsr_hash::u128 hash = utils_global::pin_to_hash(textBytes);
    constexpr size_t blockSize = 64;
    {
        const int old_size = textBytes.size();
        const int size_with_seed = old_size + static_cast<int>(sizeof(uint));

        const int res = (size_with_seed + 1) % blockSize;
        const int padding_needed = 1 + (res != 0 ? blockSize - res : 0);
        const int final_size = size_with_seed + padding_needed;

        QByteArray bytes;
        bytes.fill('\0', final_size);
        std::memcpy(bytes.data(), textBytes.constData(), old_size);

        // Вшиваем сид сразу по нужному смещению
        char *data_ptr = bytes.data() + old_size;
        for (size_t i = 0; i < sizeof(uint); ++i) {
            data_ptr[i] = static_cast<char>(seed & 0xFF);
            seed >>= 8;
        }

        bytes[size_with_seed] = static_cast<char>(0x80);

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
        // Гарантированно выжигаем локальный рабочий буфер
        utils::erase_bytes(bytes);
    }
    return hash;
}

inline lfsr_hash::u128 gen_hash_for_storage(const QByteArray &textBytes)
{
    password::hash_gen.reset();
    constexpr size_t blockSize = 72;

    const int old_size = textBytes.size();

    // 1. Рассчитываем итоговый размер с паддингом ISO/IEC 9797-1 заранее
    const int res = (old_size + 1) % blockSize;
    const int padding_needed = 1 + (res != 0 ? blockSize - res : 0);
    const int final_size = old_size + padding_needed;

    // 2. Выделяем память один раз.
    QByteArray bytes;
    bytes.fill('\0', final_size);

    // 3. Копируем мастер-фразу в начало буфера (без realloc!)
    std::memcpy(bytes.data(), textBytes.constData(), old_size);

    // 4. Считаем промежуточный хэш от исходных данных (до паддинга)
    // Чтобы pin_to_hash не вызвал realloc внутри, передаем ему textBytes
    lfsr_hash::u128 hash_fs = utils_global::pin_to_hash(textBytes);

    // 5. Ручной ISO/IEC 9797-1 padd
    bytes[old_size] = static_cast<char>(0x80);

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

inline lfsr_hash::u128 gen_hash_for_encryption(const QByteArray &textBytes)
{
    password::hash_gen.reset();
    constexpr size_t blockSize = 128;

    const int old_size = textBytes.size();
    const int res = (old_size + 1) % blockSize;
    const int padding_needed = 1 + (res != 0 ? blockSize - res : 0);
    const int final_size = old_size + padding_needed;

    QByteArray bytes;
    bytes.fill('\0', final_size);
    std::memcpy(bytes.data(), textBytes.constData(), old_size);

    lfsr_hash::u128 hash_enc = utils_global::pin_to_hash(textBytes);

    bytes[old_size] = static_cast<char>(0x80);

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

    utils::erase_bytes(bytes);
    return hash_enc;
}

inline static lfsr_hash::u128 gen_hash_for_inner_encryption(const QByteArray &textBytes)
{
    password::hash_gen.reset();
    constexpr size_t blockSize = 96;

    const int old_size = textBytes.size();
    const int res = (old_size + 1) % blockSize;
    const int padding_needed = 1 + (res != 0 ? blockSize - res : 0);
    const int final_size = old_size + padding_needed;

    QByteArray bytes;
    bytes.fill('\0', final_size);
    std::memcpy(bytes.data(), textBytes.constData(), old_size);

    lfsr_hash::u128 hash_enc = utils_global::pin_to_hash(textBytes);

    bytes[old_size] = static_cast<char>(0x80);

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
    utils::erase_bytes(bytes);
    return hash_enc;
}

inline void request_passwords(QFutureWatcher<QVector<lfsr8::u64>> &watcher, int password_len)
{
    using namespace password;
    const int Nw = (password_len * constants::num_of_passwords) / constants::password_len_per_u64
                   + 1;
    watcher.setFuture(worker->gen_n(pass_gen, Nw));
    watcher.waitForFinished();
    {
        QMutexLocker locker(&pswd_buff->mMutex);
        // Перед записью нового пула, если старый буфер не пуст,
        // принудительно затираем его остатки через volatile
        if (!pswd_buff->mPasswords.isEmpty()) {
            volatile lfsr8::u64 *data_ptr = reinterpret_cast<volatile lfsr8::u64 *>(
                pswd_buff->mPasswords.data());
            std::fill_n(data_ptr, pswd_buff->mPasswords.size(), 0);
        }
        pswd_buff->mPasswords = watcher.result();
    }
    qDebug() << "Passwords were requested.";
}

inline QString try_to_get_password(int len, int level)
{
    auto *buffer = password::pswd_buff();
    QMutexLocker locker(&buffer->mMutex);

    QString pswd;
    if (len <= 0)
        return pswd;

    // Резервируем память под строку пароля заранее,
    // чтобы избежать перевыделений в куче внутри цикла while
    pswd.reserve(len);

    while (pswd.size() < len) {
        if (buffer->mPasswords.empty()) {
            // Буфер опустел — перед выходом очищаем частично собранную строку,
            // чтобы не возвращать огрызок пароля, и уберечь данные
            utils::erase_string(pswd);
            return pswd;
        }

        // Безопасное извлечение с занулением памяти в векторе
        lfsr8::u64 raw64 = buffer->mPasswords.last();

        // Затираем ячейку прямо в куче вектора mPasswords через volatile
        volatile lfsr8::u64 *cell_ptr = reinterpret_cast<volatile lfsr8::u64 *>(
            &buffer->mPasswords.last());
        *cell_ptr = 0;

        buffer->mPasswords.removeLast();

        // Разделение разрядов
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

        // Стираем локальные копии чисел в стеке
        volatile lfsr8::u64 *p_raw = &raw64;
        *p_raw = 0;
        volatile uint32_t *h_raw = &high;
        *h_raw = 0;
        volatile uint32_t *l_raw = &low;
        *l_raw = 0;
    }

    return pswd;
}

inline QString generate_storage_name(const lfsr_hash::u128 &hash)
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
