#include "widget.h"

#include <QApplication>
#include <qmessagebox.h>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    MyDialog dialog;
    int result = dialog.exec();

    if (result == QDialog::Accepted) {
        ;
    } else {
        return 0;
    }

    QString pin {dialog.get_pin()};
    dialog.clear_pin();
    if (pin.size() != 4) {
        QMessageBox mb(QMessageBox::Critical, QString::fromUtf8("Ошибка PIN-кода"), QString::fromUtf8("PIN-код должен быть любым 4-значным числом"));
        mb.exec();
        return 1;
    }

    Widget w(std::move(pin));
    w.show();
    return a.exec();
}
