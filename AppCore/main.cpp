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

    QString pin;
    // Проверяем, был ли вообще передан ключ --pin
    if (parser.isSet(pinOption)) {
        // Получаем значение как строку
        pin = parser.value(pinOption);
        bool isNumeric;
        pin.toLongLong(&isNumeric);
        if (!isNumeric) {
            QMessageBox mb(QMessageBox::Critical,
                           QString::fromUtf8("Ошибка PIN-кода"),
                           QString::fromUtf8("PIN-код должен быть любым 4-значным числом"));
            mb.exec();
            return 1;
        }
    } else {
        // Здесь можно либо показать справку, либо просто продолжить запуск окна
        // parser.showHelp(); // Раскомментируйте, если без пина запускать нельзя
    }

    if (pin.isEmpty()) {
        MyDialog dialog;
        const int result = dialog.exec();
        if (result != QDialog::Accepted) {
            return 0;
        }
        pin = dialog.get_pin();
        dialog.clear_pin();
    }

    if (pin.size() != constants::pin_code_len) {
        QMessageBox mb(QMessageBox::Critical,
                       QString::fromUtf8("Ошибка PIN-кода"),
                       QString::fromUtf8("PIN-код должен быть любым 4-значным числом"));
        mb.exec();
        return 1;
    }

    splash.show();
    a.processEvents();

    Widget w(std::move(pin));
    w.show();
    splash.finish(&w);
    return a.exec();
}
