#ifndef KEY_H
#define KEY_H

#include <QString>
#include <QVector>

namespace key {

/**
 * @brief Класс "Ключ" для хранения хеша мастер-фразы.
 */
class Key
{
    /**
     * @brief Длина ключа в байтах.
     */
    const int _N = 8;
public:
    Key() {
        mKey_bytes_str.resize(_N);
    }

    /**
     * @brief Установить байт ключа.
     * @param key Байт.
     * @param idx Позиция байта.
     */
    void set_key(int key, int idx) {
        mKey_bytes_str[idx] = QString("%1").arg(QString::number(key, 16), 4, QChar('0'));
        update_key();
    }

    /**
     * @brief Получить строковое представление ключа.
     */
    auto get_str_key() const {
        return mKey;
    }

    /**
     * @brief Получить байт ключа.
     * @param idx Позиция байта.
     * @return Возвращает числовое представление байта.
     */
    int get_key(int idx) const {
        bool ok;
        return mKey_bytes_str[idx].toInt(&ok, 16);
    }

    /**
     * @brief Размер ключа в байтах.
     * @return .
     */
    int N() const {
        return _N;
    }
private:
    /**
     * @brief Строковое представление ключа.
     */
    QString mKey {};

    /**
     * @brief Представление ключа в виде байтов-строк.
     */
    QVector<QString> mKey_bytes_str{};

    /**
     * @brief Обновить ключ байтами строками.
     */
    void update_key() {
        mKey.clear();
        for (auto it=mKey_bytes_str.begin(); it != mKey_bytes_str.end(); it++) {
            mKey.push_back( *it );
            mKey.push_back(" ");
        }
    }
};

}

#endif // KEY_H
