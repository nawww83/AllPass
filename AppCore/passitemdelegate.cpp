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

    // Маскируем текст в звездочки только для колонки паролей
    if (index.column() == constants::pswd_column_idx) {
        QString rawPassword = option->text;
        option->text = QString(rawPassword.length(), '*');
    }

    // Больше никаких ручных сбросов флагов фокуса и палитр здесь не требуется!
}

void PassEditDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const {
    QVariant animData = index.data(roles::AnimationRole);
    QStyleOptionViewItem opt = option;

    initStyleOption(&opt, index);

    // Извлекаем таблицу для проверки фокуса
    const QTableWidget* table = qobject_cast<const QTableWidget*>(option.widget);

    // --- ИСПРАВЛЕНИЕ ПОД ЛОГИКУ Qt 6.6.2 ---
    // Проверяем, совпадает ли И СТРОКА, И КОЛОНКА.
    // Фон активируется строго на той ячейке, по которой кликнули!
    bool isCellSelected = (table &&
                           table->currentIndex().row() == index.row() &&
                           table->currentIndex().column() == index.column());
    // ----------------------------------------

    // --- 1. ЛОГИКА АНИМАЦИИ ФОНА ---
    if (animData.isValid()) {
        QBrush bg = animData.value<QBrush>();
        painter->save();
        painter->fillRect(option.rect, option.palette.base());
        painter->fillRect(option.rect, bg);
        painter->restore();

        opt.state &= ~QStyle::State_Selected;
        opt.state &= ~QStyle::State_HasFocus;
        opt.backgroundBrush = Qt::transparent;
        opt.palette.setColor(QPalette::Text, opt.palette.color(QPalette::WindowText));
    }
    // --- 2. ПОДСТВЕЧИВАЕМ ТОЛЬКО ОДНУ ВЫБРАННУЮ ЯЧЕЙКУ ---
    else if (isCellSelected) {
        painter->save();
        QColor selectColor = option.palette.color(QPalette::Highlight);
        painter->fillRect(option.rect, selectColor);
        painter->restore();

        opt.state &= ~QStyle::State_Selected;
        opt.state &= ~QStyle::State_HasFocus;
        opt.backgroundBrush = Qt::transparent;

        // Текст в этой конкретной ячейке делаем белым
        opt.palette.setColor(QPalette::Text, Qt::white);
    }
    // --- 3. ВСЕ ОСТАЛЬНЫЕ НЕВЫБРАННЫЕ ЯЧЕЙКИ СТРОКИ ---
    else {
        opt.state &= ~QStyle::State_HasFocus;
        // Текст в остальных ячейках остается стандартным черным
        opt.palette.setColor(QPalette::Text, opt.palette.color(QPalette::WindowText));
    }

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
        QString value = index.data(Qt::EditRole).toString();
        QLineEdit *lineEdit = qobject_cast<QLineEdit *>(editor);
        if (lineEdit) {
            lineEdit->setText(value);
        }
    } else {
        QStyledItemDelegate::setEditorData(editor, index);
    }
}

void PassEditDelegate::setModelData(QWidget *editor, QAbstractItemModel *model, const QModelIndex &index) const
{
    if (index.column() == constants::pswd_column_idx) {
        QLineEdit *lineEdit = qobject_cast<QLineEdit *>(editor);
        if (lineEdit) {
            model->setData(index, lineEdit->text(), Qt::EditRole);
            model->setData(index, lineEdit->text(), Qt::DisplayRole);
            model->setData(index, lineEdit->text(), Qt::UserRole);
        }
    } else {
        QStyledItemDelegate::setModelData(editor, model, index);
    }
}

bool PassEditDelegate::helpEvent(QHelpEvent *event, QAbstractItemView *view,
                                 const QStyleOptionViewItem &option, const QModelIndex &index)
{
    if (event && event->type() == QEvent::ToolTip) {
        // Извлекаем пароль из UserRole
        QString password = index.data(Qt::UserRole).toString();

        if (!password.isEmpty()) {
            // Явно приводим view к QWidget*, так как QToolTip::showText ожидает именно его
            QWidget* viewport = (view) ? view->viewport() : nullptr;

            // Используем viewport(), чтобы тултип был привязан к области данных, а не к заголовкам
            QToolTip::showText(event->globalPos(), password, viewport);
            return true;
        }
    }
    return QStyledItemDelegate::helpEvent(event, view, option, index);
}

