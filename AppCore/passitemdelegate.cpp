#include <QLineEdit>
#include "passitemdelegate.h"


void PassEditDelegate::setEditorData(QWidget *editor, const QModelIndex &index) const
{
    QVariant value = index.model()->data(index, Qt::UserRole);
    QLineEdit* edit = qobject_cast<QLineEdit *>(editor);
    if (edit) {
        edit->setText(value.toString());
    } else {
        QItemDelegate::setEditorData(editor, index);
    }
}

void PassEditDelegate::setModelData(QWidget *editor, QAbstractItemModel *model, const QModelIndex &index) const
{
    QLineEdit* edit = qobject_cast<QLineEdit *>(editor);
    if (edit) {
        const QString value = edit->text();
        model->setData(index, mAsterics, Qt::DisplayRole);
        model->setData(index, value, Qt::UserRole);
    } else {
        QItemDelegate::setModelData(editor, model, index);
    }
}
