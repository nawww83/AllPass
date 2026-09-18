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

    PinCode() { mPinCode.fill(-1); }

    PinCode(const PinCode &other) = default;
    PinCode &operator=(const PinCode &other) = default;
    PinCode(PinCode &&other) = default;
    PinCode &operator=(PinCode &&other) = default;

    void clear()
    {
        utils::erase_bytes(reinterpret_cast<uint8_t *>(mPinCode.data()), sizeof(mPinCode));
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

    void to_numeric_bytes(QByteArray &output) const
    {
        output.resize(constants::pin_code_len);
        for (int i = 0; i < constants::pin_code_len; ++i) {
            if (mPinCode.at(i) >= 0 && mPinCode.at(i) <= 9) {
                output[i] = static_cast<char>('0' + mPinCode.at(i));
            } else {
                output[i] = '0'; // Дефолтное значение, если ячейка пуста
            }
        }
    }
};

namespace password {
inline lfsr_rng::Generators pass_gen;
inline lfsr_hash::gens hash_gen;
Q_GLOBAL_STATIC(Worker, worker);
Q_GLOBAL_STATIC(key::Key, key);
Q_GLOBAL_STATIC(PasswordBuffer, pswd_buff);

inline QByteArray global_session_salt; // Сеансовая соль (32 байта)
inline QByteArray hashed_pin_verify;   // Хэш для проверки введенного пина в check_pin
inline QByteArray encrypted_raw_pin;   // Сам ПИН-код, зашифрованный сеансовой солью

// Переменные для резервного копирования (бэкапа):
inline QByteArray old_hashed_pin_verify;
inline QByteArray old_encrypted_raw_pin;

} // namespace password

#endif // GLOBAL_DATA_H
