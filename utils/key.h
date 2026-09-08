#ifndef KEY_H
#define KEY_H

#include <QString>
#include <cstdint>
#include <cstring>

#include "utils.h"

namespace key {

/**
 * @brief Класс "Ключ" для хранения хеша мастер-фразы.
 */
class Key
{
    static constexpr int _N = 8;

public:
    Key()
    {
        // Гарантированно обнуляем массив при создании
        clear();
    }

    // Деструктор класса ОБЯЗАН затирать ключ
    ~Key() { clear(); }

    void set_key(uint8_t key_byte, int idx)
    {
        if (idx >= 0 && idx < _N) {
            mKey_bytes[idx] = key_byte;
        }
    }

    int get_key(int idx) const
    {
        if (idx >= 0 && idx < _N) {
            return mKey_bytes[idx];
        }
        return 0;
    }

    // Строковое представление генерируется НА ЛЕТУ только по требованию
    // и нигде не хранится внутри класса как постоянное поле!
    QString get_str_key() const
    {
        QString result;
        for (int i = 0; i < _N; ++i) {
            result += QString("%1 ").arg(mKey_bytes[i], 2, 16, QChar('0'));
        }
        return result.trimmed();
    }

    int N() const { return _N; }

    // Функция безопасной очистки самого класса
    void clear() { utils::erase_bytes(mKey_bytes, _N); }

private:
    // Ключ хранится как плоский массив байт на стеке (внутри объекта)
    uint8_t mKey_bytes[_N];
};
}

#endif // KEY_H
