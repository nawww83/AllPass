#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <QString>

namespace {
    static inline constexpr auto g_version_prefix = '#';
    static inline constexpr auto VERSION_LABEL = "#v1.09"; // ASCII.
    static inline const char* g_asterics {"*************"};
    namespace labels {
        static inline const auto gen_pass_txt = QString::fromUtf8("Добавить запись");
        static inline const auto recover_txt = QString::fromUtf8("\xE2\x86\xB6");
        static inline const auto wait_txt = QString::fromUtf8("Подождите...");
    }
    namespace constants {
        static inline const int pin_code_len = 4; // Длина пин-кода.
        static inline const int pass_len_step = 4; // Количество ascii символов, получаемое по 32-битному коду.
        static inline const int password_len_per_request = 2 * pass_len_step; // Количество символов за один запрос.
        static inline const int num_of_passwords = 16; // Для буфера кодов: кратно запросу.

        static inline const int login_column_idx = 0;
        static inline const int pswd_column_idx = 1;
        static inline const int comments_column_idx = 2;
        static inline const int date_column_idx = 3;
    }
    namespace symbols {
        static inline const auto end_message = QChar(0x0003);
        static inline const auto empty_item = QChar(0x0008);
        static inline const auto row_delimiter = QChar(0x001E);
        static inline const auto col_delimiter = QChar(0x001F);
    }
}

#endif // CONSTANTS_H
