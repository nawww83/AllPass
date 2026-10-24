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
    // 8 слов по 16 бит = 128 бит (полный хэш мастер-фразы).
    static constexpr int _N = 8;

public:
    Key()
    {
        // Гарантированно обнуляем массив при создании
        clear();
    }

    // Деструктор класса ОБЯЗАН затирать ключ
    ~Key() { clear(); }

    void set_key(uint16_t key_word, int idx)
    {
        if (idx >= 0 && idx < _N) {
            mKey_words[idx] = key_word;
        }
    }

    int get_key(int idx) const
    {
        if (idx >= 0 && idx < _N) {
            return mKey_words[idx];
        }
        return 0;
    }

    // Строковое представление генерируется НА ЛЕТУ только по требованию
    // и нигде не хранится внутри класса как постоянное поле!
    QString get_str_key() const
    {
        QString result;
        for (int i = 0; i < _N; ++i) {
            result += QString("%1 ").arg(mKey_words[i], 4, 16, QChar('0'));
        }
        return result.trimmed();
    }

    int N() const { return _N; }

    // Функция безопасной очистки самого класса
    void clear() { utils::erase_raw_bytes(reinterpret_cast<uint8_t *>(mKey_words), sizeof(mKey_words)); }

private:
    // Ключ хранится как плоский массив 16-битных слов внутри объекта
    uint16_t mKey_words[_N];
};
}

#endif // KEY_H
