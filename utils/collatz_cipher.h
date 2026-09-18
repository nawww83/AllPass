#pragma once

#include <QByteArray>
#include <QCryptographicHash>
#include <QString>
#include "utils.h"
#include <cstdint>
#include <cstring> // std::memcpy
#include <vector>

class CollatzCipher256
{
private:
    static constexpr uint64_t INV_5 = 14757395258967641293ULL;
    static constexpr int ROUNDS = 20; // 20 раундов для полной диффузии 256 бит

    // Структура для удобной работы с 256-битными блоками
    struct Block256
    {
        uint64_t A, B, C, D;
    };

    // Аппаратные циклические сдвиги
    static inline uint64_t rotr64(uint64_t value, unsigned int shift)
    {
        return (value >> shift) | (value << (64 - shift));
    }

    static inline uint64_t rotl64(uint64_t value, unsigned int shift)
    {
        return (value << shift) | (value >> (64 - shift));
    }

    // Прямая функция раунда (Шифрование с константами SipHash)
    static void mixRound(Block256 &block, const Block256 &subkey, int round_num)
    {
        // 1. Подмешиваем раундовый ключ и счетчик раунда
        block.A ^= subkey.A ^ round_num;
        block.B ^= subkey.B;
        block.C ^= subkey.C;
        block.D ^= subkey.D;

        // 2. Коллатц-перенос 5t+1 + индивидуальные сдвиги
        block.A = rotr64(5 * block.A + 1, 11);
        block.B = rotr64(5 * block.B + 1, 21);
        block.C = rotr64(5 * block.C + 1, 31);
        block.D = rotr64(5 * block.D + 1, 41);

        // 3. Диффузия SipHash (Константы: 21, 13, 17, 16)
        // Шаг 1: сдвиг 21
        block.A += block.B;
        block.D ^= block.A;
        block.D = rotl64(block.D, 21);
        // Шаг 2: сдвиг 13
        block.C += block.D;
        block.B ^= block.C;
        block.B = rotl64(block.B, 13);
        // Шаг 3: сдвиг 17
        block.A += block.B;
        block.D ^= block.A;
        block.D = rotl64(block.D, 17);
        // Шаг 4: сдвиг 16
        block.C += block.D;
        block.B ^= block.C;
        block.B = rotl64(block.B, 16);
    }

    // Обратная функция раунда (Дешифрование с константами SipHash)
    static void unmixRound(Block256 &block, const Block256 &subkey, int round_num)
    {
        // 3. Обратная диффузия SipHash (Зеркальный порядок: 16, 17, 13, 21)
        // Обращаем Шаг 4 (сдвиг 16):
        block.B = rotr64(block.B, 16);
        block.B ^= block.C;
        block.C -= block.D;
        // Обращаем Шаг 3 (сдвиг 17):
        block.D = rotr64(block.D, 17);
        block.D ^= block.A;
        block.A -= block.B;
        // Обращаем Шаг 2 (сдвиг 13):
        block.B = rotr64(block.B, 13);
        block.B ^= block.C;
        block.C -= block.D;
        // Обращаем Шаг 1 (сдвиг 21):
        block.D = rotr64(block.D, 21);
        block.D ^= block.A;
        block.A -= block.B;

        // 2. Обратный Коллатц-шаг через модульное обратное INV_5
        block.D = (rotl64(block.D, 41) - 1) * INV_5;
        block.C = (rotl64(block.C, 31) - 1) * INV_5;
        block.B = (rotl64(block.B, 21) - 1) * INV_5;
        block.A = (rotl64(block.A, 11) - 1) * INV_5;

        // 1. Убираем раундовый ключ и счетчик раунда
        block.A ^= subkey.A ^ round_num;
        block.B ^= subkey.B;
        block.C ^= subkey.C;
        block.D ^= subkey.D;
    }

    // Генерация раундовых ключей из мастер-ключа с помощью SHA-256
    static std::vector<Block256> deriveRoundKeys(const QByteArray &keyBytes)
    {
        std::vector<Block256> roundKeys(ROUNDS);
        QByteArray baseHash = QCryptographicHash::hash(keyBytes, QCryptographicHash::Sha256);

        // Используем базовый хэш для генерации уникальных ключей под каждый раунд
        for (int r = 0; r < ROUNDS; ++r) {
            QByteArray r_bytes = QByteArray::number(r);
            QByteArray roundHash = QCryptographicHash::hash(baseHash + r_bytes,
                                                            QCryptographicHash::Sha256);

            std::memcpy(&roundKeys[r].A, roundHash.constData(), 8);
            std::memcpy(&roundKeys[r].B, roundHash.constData() + 8, 8);
            std::memcpy(&roundKeys[r].C, roundHash.constData() + 16, 8);
            std::memcpy(&roundKeys[r].D, roundHash.constData() + 24, 8);
        }
        return roundKeys;
    }

    // Вспомогательный метод для безопасного удаления временных раундовых ключей из RAM
#if defined(Q_OS_WIN)
#include <windows.h>
#endif
    static void secureClearRoundKeys(std::vector<Block256> &roundKeys)
    {
        if (roundKeys.empty())
            return;

        size_t totalBytes = roundKeys.size() * sizeof(Block256);
        void *ptr = roundKeys.data();

#if defined(Q_OS_WIN)
        // Кроссплатформенный стандарт для Windows (гарантирует невырезание)
        SecureZeroMemory(ptr, totalBytes);
#elif defined(__STDC_LIB_EXT1__) || defined(__GLIBC__)
        // Для Linux систем с поддержкой безопасных функций C11 / GLIBC 2.25+
        explicit_bzero(ptr, totalBytes);
#else
        // Жесткий fallback для старых Linux/Unix систем, обманывающий компилятор:
        // Мы заставляем его думать, что указатель используется внешней ассемблерной функцией
        volatile char *p = static_cast<volatile char *>(ptr);
        while (totalBytes--) {
            *p++ = 0;
        }
// Этот барьер запрещает компилятору выбрасывать операции записи до него
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "g"(ptr) : "memory");
#endif
#endif
    }

public:
    static QString encrypt(QByteArray data, const QByteArray &key)
    {
        auto roundKeys = deriveRoundKeys(key);

        // Паддинг PKCS#7 до размера 256 бит (32 байта)
        int paddingRequired = 32 - (data.size() % 32);
        if (paddingRequired == 0)
            paddingRequired = 32;

        // Гарантируем монопольное владение перед изменением, чтобы не затереть чужие разделяемые копии
        data.detach();
        data.append(paddingRequired, static_cast<char>(paddingRequired));

        QByteArray ciphertext;
        ciphertext.resize(data.size());

        // Поблочное шифрование по 32 байта
        for (int i = 0; i < data.size(); i += 32) {
            Block256 block;
            std::memcpy(&block.A, data.constData() + i, 8);
            std::memcpy(&block.B, data.constData() + i + 8, 8);
            std::memcpy(&block.C, data.constData() + i + 16, 8);
            std::memcpy(&block.D, data.constData() + i + 24, 8);

            for (int r = 1; r <= ROUNDS; ++r) {
                mixRound(block, roundKeys[r - 1], r);
            }

            std::memcpy(ciphertext.data() + i, &block.A, 8);
            std::memcpy(ciphertext.data() + i + 8, &block.B, 8);
            std::memcpy(ciphertext.data() + i + 16, &block.C, 8);
            std::memcpy(ciphertext.data() + i + 24, &block.D, 8);
        }

        // =========================================================================
        // КРИТИЧЕСКИ ВАЖНО ДЛЯ БЕЗОПАСНОСТИ RAM:
        // =========================================================================
        // 1. Очищаем раундовые ключи в памяти процесса
        secureClearRoundKeys(roundKeys);

        // 2. Жестко выжигаем локальную копию открытых данных (ПИН/пароль) в RAM,
        // так как деструктор Qt этого сам не сделает.
        utils::erase_bytes(data);
        // =========================================================================

        return QString::fromUtf8(ciphertext.toBase64());
    }

    static QByteArray decrypt(const QString &b64Ciphertext, const QByteArray &key)
    {
        auto roundKeys = deriveRoundKeys(key);
        QByteArray ciphertext = QByteArray::fromBase64(b64Ciphertext.toUtf8());

        if (ciphertext.size() % 32 != 0 || ciphertext.isEmpty()) {
            return QByteArray();
        }

        QByteArray decryptedData;
        decryptedData.resize(ciphertext.size());

        // Поблочное дешифрование по 32 байта
        for (int i = 0; i < ciphertext.size(); i += 32) {
            Block256 block;
            std::memcpy(&block.A, ciphertext.constData() + i, 8);
            std::memcpy(&block.B, ciphertext.constData() + i + 8, 8);
            std::memcpy(&block.C, ciphertext.constData() + i + 16, 8);
            std::memcpy(&block.D, ciphertext.constData() + i + 24, 8);

            for (int r = ROUNDS; r >= 1; --r) {
                unmixRound(block, roundKeys[r - 1], r);
            }

            std::memcpy(decryptedData.data() + i, &block.A, 8);
            std::memcpy(decryptedData.data() + i + 8, &block.B, 8);
            std::memcpy(decryptedData.data() + i + 16, &block.C, 8);
            std::memcpy(decryptedData.data() + i + 24, &block.D, 8);
        }

        // Очищаем раундовые ключи в памяти процесса
        secureClearRoundKeys(roundKeys);

        // Проверка и удаление паддинга PKCS#7
        // 1. Защита от пустой строки (на всякий случай)
        if (decryptedData.isEmpty()) {
            return QByteArray();
        }

        // 2. Читаем значение последнего байта (это предполагаемая длина паддинга)
        int paddingValue = static_cast<uint8_t>(decryptedData.at(decryptedData.size() - 1));

        // 3. Строгая валидация: паддинг для 32-байтного блока обязан быть от 1 до 32,
        // и общий размер данных не может быть меньше этого паддинга
        if (paddingValue < 1 || paddingValue > 32 || decryptedData.size() < paddingValue) {
            utils::erase_bytes(decryptedData); // Выжигаем мусор в RAM ради безопасности
            return QByteArray();
        }

        // 4. Полноценная проверка PKCS#7: ВСЕ N последних байт должны быть равны значению N
        const int size = decryptedData.size();
        bool isValidPadding = true;
        for (int i = size - paddingValue; i < size; ++i) {
            if (static_cast<uint8_t>(decryptedData.at(i)) != paddingValue) {
                isValidPadding = false;
                break;
            }
        }

        // 5. Если хотя бы один байт паддинга не совпал — это 100% неверный ключ или мусор
        if (!isValidPadding) {
            utils::erase_bytes(decryptedData);
            return QByteArray();
        }

        // 6. Только теперь безопасно отсекаем проверенный паддинг
        decryptedData.chop(paddingValue);
        return decryptedData;
    }
};
