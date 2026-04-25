#include "passitemdelegate.h"
#include <QLineEdit>
#include <QToolTip>
#include <QHelpEvent>
#include <QAbstractItemView>
#include <QPainter>

PassEditDelegate::PassEditDelegate(QObject *parent)
    : QStyledItemDelegate(parent)
{
}

QWidget *PassEditDelegate::createEditor(QWidget *parent, const QStyleOptionViewItem &option,
                                        const QModelIndex &index) const
{
    QLineEdit *editor = new QLineEdit(parent);
    // Устанавливаем режим пароля, чтобы при вводе были звездочки/точки
    editor->setEchoMode(QLineEdit::Password);
    return editor;
}

void PassEditDelegate::setEditorData(QWidget *editor, const QModelIndex &index) const
{
    // Извлекаем реальный пароль из UserRole
    QString value = index.model()->data(index, Qt::UserRole).toString();
    QLineEdit *edit = qobject_cast<QLineEdit *>(editor);
    if (edit) {
        edit->setText(value);
    }
}

void PassEditDelegate::setModelData(QWidget *editor, QAbstractItemModel *model,
                                    const QModelIndex &index) const
{
    QLineEdit *edit = qobject_cast<QLineEdit *>(editor);
    if (edit) {
        QString value = edit->text();

        // Генерируем строку маски (звездочки) той же длины, что и пароль
        QString masked(value.length(), '*');

        // DisplayRole — то, что видит пользователь в таблице
        model->setData(index, masked, Qt::DisplayRole);
        // UserRole — то, где хранится реальное значение для логики программы
        model->setData(index, value, Qt::UserRole);
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

void PassEditDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const {
    QVariant animData = index.data(roles::AnimationRole);
    QStyleOptionViewItem opt = option;
    initStyleOption(&opt, index);

    if (animData.isValid()) {
        QBrush bg = animData.value<QBrush>();
        painter->save();

        // 1. Принудительно очищаем фон цветом базы (белым),
        // игнорируя синий цвет выделения.
        painter->fillRect(option.rect, option.palette.base());

        // 2. Рисуем нашу оранжевую "сигарету"
        painter->fillRect(option.rect, bg);

        painter->restore();

        // 3. САМЫЙ ВАЖНЫЙ МОМЕНТ:
        // Убираем флаг выделения из опций перед передачей в базовый класс.
        // Это заставит стандартный отрисовщик думать, что ячейка НЕ выделена,
        // и он нарисует текст черным цветом на нашей полоске, не закрашивая её синим.
        opt.state &= ~QStyle::State_Selected;
        opt.state &= ~QStyle::State_HasFocus; // Также убираем пунктирную рамку фокуса
        opt.backgroundBrush = Qt::transparent;
    }

    // 4. Рисуем текст поверх нашей полоски
    QStyledItemDelegate::paint(painter, opt, index);
}
