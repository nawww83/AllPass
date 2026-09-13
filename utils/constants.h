#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <QChar>

inline constexpr auto G_VERSION_PREFIX = '#';
inline constexpr auto G_VERSION_LABEL  = "#v3.00";

namespace constants {
    inline const int pin_code_len = 5;         // Длина пин-кода.
    inline const int password_len_step = 5;    // Шаг изменения длины пароля.
    inline const int password_len_per_u32 = 5; // Количество символов, получаемое по 32-битному слову.
    inline const int password_len_per_u64
        = 2 * password_len_per_u32;            // Количество символов на 64-битное слово.
    inline const int num_of_passwords = 16;    // Емкость буфера паролей.

    inline const int login_column_idx    = 0;     // Индексы в основной таблице.
    inline const int pswd_column_idx     = 1;
    inline const int comments_column_idx = 2;
    inline const int date_column_idx     = 3;
}

namespace symbols {
    inline const auto end_message = QChar(0x0003);
    inline const auto empty_item = QChar(0x0008);
    inline const auto row_delimiter = QChar(0x001E);
    inline const auto col_delimiter = QChar(0x001F);
}

namespace const_arr {
// Множители для генерации перестановок: x <- (x * a) mod p, p = 257.
inline const int goods[] =
    {
        3, 5, 6, 7, 10, 12, 14, 19, 20, 24, 27, 28, 33, 37, 38, 39,
        40, 41, 43, 45, 47, 48, 51, 53, 54, 55, 56, 63, 65, 66, 69, 71,
        74, 75, 76, 77, 78, 80, 82, 83, 85, 86, 87, 90, 91, 93, 94, 96,
        97, 101, 102, 103, 105, 106, 107, 108, 109, 110, 112, 115, 119, 125, 126, 127,
        130, 131, 132, 138, 142, 145, 147, 148, 149, 150, 151, 152, 154, 155, 156, 160,
        161, 163, 164, 166, 167, 170, 171, 172, 174, 175, 177, 179, 180, 181, 182, 183,
        186, 188, 191, 192, 194, 201, 202, 203, 204, 206, 209, 210, 212, 214, 216, 217,
        218, 219, 220, 224, 229, 230, 233, 237, 238, 243, 245, 247, 250, 251, 252, 254
    };
}

#endif // CONSTANTS_H
