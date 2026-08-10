#include "passitemdelegate.h"
#include "constants.h"
#include <QLineEdit>
#include <QToolTip>
#include <QHelpEvent>
#include <QAbstractItemView>
#include <QPainter>
#include <QTableWidget>

PassEditDelegate::PassEditDelegate(QObject *parent)
    : QStyledItemDelegate(parent)
{
}

void PassEditDelegate::initStyleOption(QStyleOptionViewItem *option, const QModelIndex &index) const
{
    QStyledItemDelegate::initStyleOption(option, index);

    // Маскируем вывод на экран ТОЛЬКО для колонки паролей
    if (index.column() == constants::pswd_column_idx) {
        // Читаем сырой текст из DisplayRole (модель хранит там чистый пароль)
        QString rawPassword = index.data(Qt::DisplayRole).toString();
        option->text = QString(rawPassword.length(), '*');
    }
}

void PassEditDelegate::paint(QPainter *painter,
                             const QStyleOptionViewItem &option,
                             const QModelIndex &index) const
{
    QVariant animData = index.data(roles::AnimationRole);
    QStyleOptionViewItem opt = option;

    // Сначала инициализируем опции и маскируем текст в звёздочки внутри opt.text
    initStyleOption(&opt, index);

    const QTableWidget *table = qobject_cast<const QTableWidget *>(option.widget);
    bool isCellSelected = (table && table->currentIndex().row() == index.row()
                           && table->currentIndex().column() == index.column());

    opt.state &= ~QStyle::State_HasFocus;

    // 1. АНИМАЦИЯ ФОНА
    if (animData.isValid()) {
        QBrush bg = animData.value<QBrush>();
        painter->save();
        painter->fillRect(option.rect, option.palette.base());
        painter->fillRect(option.rect, bg);
        painter->restore();

        opt.state &= ~QStyle::State_Selected;
        opt.backgroundBrush = Qt::transparent;
        opt.palette.setColor(QPalette::Text, opt.palette.color(QPalette::WindowText));
    }
    // 2. ВЫДЕЛЕНИЕ КЛИКОМ
    else if (isCellSelected) {
        painter->save();
        QColor selectColor = option.palette.color(QPalette::Highlight);
        painter->fillRect(option.rect, selectColor);
        painter->restore();

        opt.state &= ~QStyle::State_Selected;
        opt.backgroundBrush = Qt::transparent;
        opt.palette.setColor(QPalette::Text, Qt::white); // Текст (звёздочки) станет белым
    }
    // 3. ОБЫЧНОЕ СОСТОЯНИЕ
    else {
        opt.state &= ~QStyle::State_Selected;
        opt.palette.setColor(QPalette::Text, opt.palette.color(QPalette::WindowText));
    }

    // Передаем opt с уже готовыми звёздочками в базовый отрисовщик
    QStyledItemDelegate::paint(painter, opt, index);
}

QWidget *PassEditDelegate::createEditor(QWidget *parent, const QStyleOptionViewItem &option,
                                        const QModelIndex &index) const
{
    if (index.column() == constants::pswd_column_idx) {
        QLineEdit *editor = new QLineEdit(parent);
        editor->setEchoMode(QLineEdit::Password);
        return editor;
    }
    return QStyledItemDelegate::createEditor(parent, option, index);
}

void PassEditDelegate::setEditorData(QWidget *editor, const QModelIndex &index) const
{
    if (index.column() == constants::pswd_column_idx) {
        // Читаем пароль
        QString value = index.data(Qt::DisplayRole).toString();
        QLineEdit *lineEdit = qobject_cast<QLineEdit *>(editor);
        if (lineEdit) {
            lineEdit->setText(value);
        }
    } else {
        QStyledItemDelegate::setEditorData(editor, index);
    }
}

void PassEditDelegate::setModelData(QWidget *editor,
                                    QAbstractItemModel *model,
                                    const QModelIndex &index) const
{
    if (index.column() == constants::pswd_column_idx) {
        QLineEdit *lineEdit = qobject_cast<QLineEdit *>(editor);
        if (lineEdit) {
            // Сохраняем пароль в обе роли стандартно
            model->setData(index, lineEdit->text(), Qt::EditRole);
            model->setData(index, lineEdit->text(), Qt::DisplayRole);
        }
    } else {
        QStyledItemDelegate::setModelData(editor, model, index);
    }
}

bool PassEditDelegate::helpEvent(QHelpEvent *event,
                                 QAbstractItemView *view,
                                 const QStyleOptionViewItem &option,
                                 const QModelIndex &index)
{
    if (event && event->type() == QEvent::ToolTip) {
        if (index.column() == constants::pswd_column_idx) {
            // Читаем открытый пароль для тултипа
            QString password = index.data(Qt::DisplayRole).toString();

            if (!password.isEmpty()) {
                QWidget *viewport = (view) ? view->viewport() : nullptr;
                QToolTip::showText(event->globalPos(), password, viewport);
                return true;
            }
        }
    }
    return QStyledItemDelegate::helpEvent(event, view, option, index);
}
