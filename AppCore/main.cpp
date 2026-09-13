#include "utils_global.h"
#include "widget.h"

#include <QApplication>
#include <QSplashScreen>
#include <qcommandlineparser.h>
#include <qmessagebox.h>

#include "constants.h"

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    QSplashScreen splash;
    QFont splashFont;
    splashFont.setBold(true);
    splashFont.setPixelSize(18);
    splash.setFont(splashFont);
    splash.showMessage(QString::fromUtf8("Подождите..."), Qt::AlignCenter, Qt::blue);
    a.processEvents();

    QCommandLineParser parser;
    parser.setApplicationDescription("Менеджер паролей");
    parser.addHelpOption(); // Добавляет стандартные -h и --help

    // Определяем опцию --pin, которая принимает значение
    QCommandLineOption pinOption("pin", "Введите PIN-код (опционально)", "value");
    parser.addOption(pinOption);

    // Разбираем аргументы
    parser.process(a);

    PinCode pin;
    const auto& warning_text = QString::fromUtf8("PIN-код должен быть любым %1-значным числом").arg(constants::pin_code_len);
    // Проверяем, был ли вообще передан ключ --pin
    if (parser.isSet(pinOption)) {
        // Получаем значение как строку
        QString pin_str = parser.value(pinOption);

        // Валидация: проверяем, что в строке ровно столько цифр, сколько нужно, и нет посторонних символов
        bool isNumeric;
        pin_str.toLongLong(&isNumeric);

        if (!isNumeric || pin_str.length() != constants::pin_code_len) {
            // Перед выводом ошибки очищаем временную строку с неверным пином
            utils::erase_string(pin_str);

            QMessageBox mb(QMessageBox::Critical,
                           QString::fromUtf8("Ошибка PIN-кода"),
                           warning_text);
            mb.exec();
            return 1;
        }
        // Заполняем структуру PinCode посимвольно
        for (int i = 0; i < constants::pin_code_len; ++i) {
            // Переводим QChar в число (0-9)
            pin.mPinCode[i] = pin_str.at(i).digitValue();
        }

        // Немедленно затираем исходную строку в куче
        utils::erase_string(pin_str);
    } else {
        // Здесь можно либо показать справку, либо просто продолжить запуск окна
        // parser.showHelp(); // Раскомментируйте, если без пина запускать нельзя
    }

    if (pin.length() == 0) {
        QString current_version = QString(G_VERSION_LABEL).remove(G_VERSION_PREFIX);
        MyDialog<constants::pin_code_len> dialog{QString::fromUtf8("Введите PIN-код (%1)").arg( current_version)};
        const int result = dialog.exec();
        if (result != QDialog::Accepted) {
            return 0;
        }
        pin = dialog.get_secure_pin();
        dialog.clear_pin();
    }

    if (pin.length() != constants::pin_code_len) {
        QMessageBox mb(QMessageBox::Critical,
                       QString::fromUtf8("Ошибка PIN-кода"),
                       warning_text);
        mb.exec();
        return 1;
    }

    splash.show();
    a.processEvents();

    utils_global::set_global_pin(pin);
    pin.clear();

    Widget w;
    w.show();
    splash.finish(&w);
    return a.exec();
}
