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
        QMessageBox mb(QMessageBox::Critical, "PIN code error", "PIN code must be any 4-digits number");
        mb.exec();
        return 1;
    }

    Widget w(std::move(pin));
    w.show();
    return a.exec();
}
