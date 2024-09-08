#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <QString>

namespace {
    static inline constexpr auto g_version_prefix = '#';
    static inline constexpr auto VERSION = "#v1.00";
    static inline const char* g_asterics {"*************"};
    namespace labels {
        static inline const auto gen_pass_txt = QString::fromUtf8("Добавить запись с паролем");
        static inline const auto wait_txt = QString::fromUtf8("Подождите...");
    }
    namespace constants {
        static inline const int pass_len_step = 5;
        static inline const int num_of_passwords = 10;          // in pswd_buff.
        static inline const int password_len_per_request = 2*pass_len_step; // 64 bit = 2*32 = 2*5 ascii94 symbols.
        static inline const int pswd_column_idx = 1;
    }
    namespace symbols {
        static inline const auto end_message = QChar(0x0003);
        static inline const auto empty_item = QChar(0x0008);
        static inline const auto row_delimiter = QChar(0x001E);
        static inline const auto col_delimiter = QChar(0x001F);
    }
}

#endif // CONSTANTS_H