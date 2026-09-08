#ifndef GLOBAL_DATA_H
#define GLOBAL_DATA_H

#include <QMutex>
#include <QVector>
#include "../AppCore/worker.h"
#include "constants.h"
#include "key.h"
#include "lfsr_hash.h"
#include "stream_cipher.h"
#include <array>

struct PasswordBuffer
{
    QVector<lfsr8::u64> mPasswords;
    mutable QMutex mMutex;
};

struct PinCode
{
    std::array<int, constants::pin_code_len> mPinCode;
    // 1. Конструктор по умолчанию (все -1)
    PinCode() { mPinCode.fill(-1); }

    // Оставляем дефолтные конструкторы, компилятор сам сделает их максимально быстрыми
    PinCode(const PinCode &other) = default;
    PinCode &operator=(const PinCode &other) = default;
    PinCode(PinCode &&other) = default;
    PinCode &operator=(PinCode &&other) = default;

    // Вспомогательный метод для полной очистки объекта
    void clear()
    {
        // Физически затираем память массива нулями
        utils::erase_bytes(reinterpret_cast<uint8_t *>(mPinCode.data()), sizeof(mPinCode));
        // Возвращаем структуру в дефолтное состояние (-1)
        mPinCode.fill(-1);
    }
    int length() const
    {
        int len = 0;
        for (auto el : mPinCode) {
            len += (el >= 0 && el < 10);
        }
        return len;
    }

    std::array<char, constants::pin_code_len + 1> to_numeric_string() const
    {
        std::array<char, constants::pin_code_len + 1> res;
        res.fill('\0');
        for (size_t i = 0; i < constants::pin_code_len; ++i) {
            if (mPinCode.at(i) >= 0 && mPinCode.at(i) <= 9) {
                res[i] = '0' + mPinCode.at(i);
            } else {
                res[i] = '0'; // дефолтное значение, если пин не полон
            }
        }
        return res;
    }
};

namespace password {
inline lfsr_rng::Generators pass_gen;
inline lfsr_hash::gens hash_gen;
Q_GLOBAL_STATIC(Worker, worker);
Q_GLOBAL_STATIC(key::Key, key);
Q_GLOBAL_STATIC(PasswordBuffer, pswd_buff);
inline PinCode pin_code;
inline PinCode old_pin_code;
} // namespace password

#endif // GLOBAL_DATA_H
