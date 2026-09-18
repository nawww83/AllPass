#include "utils_global.h"
#include "widget.h"

#include <QApplication>
#include <QLoggingCategory>
#include <QSplashScreen>
#include <qcommandlineparser.h>
#include <qmessagebox.h>

// #ifdef Q_OS_LINUX
// #include <iostream>
// #endif

#include "constants.h"

// #ifdef Q_OS_LINUX
// void linuxMessageOutput(QtMsgType /*type*/,
//                         const QMessageLogContext & /*context*/,
//                         const QString &msg)
// {
//     // Пишем напрямую в стандартный вывод Linux в обход системного journald
//     std::cout << msg.toStdString() << std::endl;
// }
// #endif

int main(int argc, char *argv[])
{
    // #ifdef Q_OS_LINUX
    //     // Выключаем вообще всю отладку Qt, информацию и предупреждения фреймворка.
    //     // Оставляем включенным ТОЛЬКО дефолтный пользовательский qDebug.
    //     QLoggingCategory::setFilterRules(
    //         QStringLiteral("qt.*=false\n"          // Выключаем абсолютно всё от Qt
    //                        "*.info=false\n"        // Выключаем любые info
    //                        "*.warning=false\n"     // Выключаем любые warning
    //                        "default.debug=true")); // Включаем ваш стандартный qDebug

    //     qInstallMessageHandler(linuxMessageOutput);
    // #endif

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

    // Разбираем стандартные аргументы (--help)
    parser.process(a);

    PinCode pin;
    const auto& warning_text = QString::fromUtf8("PIN-код должен быть любым %1-значным числом").arg(constants::pin_code_len);
    // Ввод ПИН-кода осуществляется через диалоговое окно MyDialog.
    // Это исключает утечку ПИН-кода через историю терминала и системные утилиты типа ps/procfs.
    if (pin.length() == 0) {
        QString current_version = QString(G_VERSION_LABEL).remove(G_VERSION_PREFIX);
        MyDialog<constants::pin_code_len> dialog{
            QString::fromUtf8("Введите PIN-код (%1)").arg(current_version)};

        const int result = dialog.exec();
        if (result != QDialog::Accepted) {
            // Если пользователь нажал Cancel, завершаем работу без утечек
            dialog.clear_pin();
            return 0;
        }

        // Безопасно извлекаем ПИН-код в стековую структуру
        pin = dialog.get_secure_pin();

        // Принудительно затираем внутренности QLineEdit-полей диалога
        // перед тем, как объект dialog выйдет из области видимости
        dialog.clear_pin();
    }

    // Финальная валидация длины структуры ПИН-кода
    if (pin.length() != constants::pin_code_len) {
        QMessageBox mb(QMessageBox::Critical, QString::fromUtf8("Ошибка PIN-кода"), warning_text);
        mb.exec();
        pin.clear(); // Стираем мусор в стеке в случае ошибки
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
