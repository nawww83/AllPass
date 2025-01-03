#include "widget.h"

#include <QApplication>
#include <QSplashScreen>
#include <qmessagebox.h>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    QSplashScreen splash;
    QFont splashFont;
    splashFont.setBold(true);
    splashFont.setPixelSize(18);
    splash.setFont(splashFont);
    splash.showMessage(QString::fromUtf8("Подождите..."), Qt::AlignCenter, QColor::fromString("blue"));
    a.processEvents();

    MyDialog dialog;
    const int result = dialog.exec();
    if (result == QDialog::Accepted) {
        ;
    } else {
        return 0;
    }

    QString pin {dialog.get_pin()};
    dialog.clear_pin();
    if (pin.size() != 4) {
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
