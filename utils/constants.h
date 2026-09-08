#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <QString>

inline constexpr auto g_version_prefix = '#';
inline constexpr auto VERSION_LABEL = "#v3.00"; // ASCII.

namespace constants {
inline const int pin_code_len = 5;         // Длина пин-кода.
inline const int password_len_step = 5;    // Шаг изменения длины пароля.
inline const int password_len_per_u32 = 5; // Количество символов, получаемое по 32-битному слову.
inline const int password_len_per_u64
    = 2 * password_len_per_u32;         // Количество символов на 64-битное слово.
inline const int num_of_passwords = 16; // Количество паролей в буфере после одного запроса.

inline const int login_column_idx = 0;
inline const int pswd_column_idx = 1;
inline const int comments_column_idx = 2;
inline const int date_column_idx = 3;
}
namespace symbols {
inline const auto end_message = QChar(0x0003);
inline const auto empty_item = QChar(0x0008);
inline const auto row_delimiter = QChar(0x001E);
inline const auto col_delimiter = QChar(0x001F);
}

#endif // CONSTANTS_H
