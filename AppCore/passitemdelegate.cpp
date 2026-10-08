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

    // Сначала маскируем текст в звёздочки внутри opt.text
    initStyleOption(&opt, index);

    const QTableWidget *table = qobject_cast<const QTableWidget *>(option.widget);

    // Проверяем, выделена ли ячейка (активна ли она в таблице)
    bool isCellSelected = (table && table->currentIndex().row() == index.row()
                           && table->currentIndex().column() == index.column());

    // Отключаем стандартный пунктир Qt, чтобы рисовать красивую сплошную рамку
    opt.state &= ~QStyle::State_HasFocus;

    painter->save();

    // 1. ОТРИСОВКА ФОНА (Анимация или Обычный)
    if (animData.isValid()) {
        QBrush bg = animData.value<QBrush>();
        painter->fillRect(option.rect, option.palette.base()); // Базовый белый/системный фон
        painter->fillRect(option.rect, bg);                    // Накладываем оранжевый градиент

        opt.state &= ~QStyle::State_Selected;
        opt.backgroundBrush = Qt::transparent;
    } else if (isCellSelected) {
        // Если анимации нет, но ячейка выбрана — классическая сплошная заливка выделения
        QColor selectColor = option.palette.color(QPalette::Highlight);
        painter->fillRect(option.rect, selectColor);

        opt.state &= ~QStyle::State_Selected;
        opt.backgroundBrush = Qt::transparent;
    }

    // 2. ОТРИСОВКА ВЫДЕЛЕНИЯ КЛИКОМ ПОВЕРХ АНИМАЦИИ
    if (isCellSelected) {
        // Подсвечиваем рамку ячейки фирменным цветом выделения ОС
        QColor highlightColor = option.palette.color(QPalette::Highlight);
        QPen prevPen = painter->pen();

        // Рисуем внутреннюю рамку толщиной 2 пикселя
        painter->setPen(QPen(highlightColor, 2, Qt::SolidLine));
        painter->drawRect(option.rect.adjusted(1, 1, -1, -1));
        painter->setPen(prevPen);

        // Меняем цвет текста (звёздочек) для контраста
        if (animData.isValid()) {
            // Если идет анимация, текст делаем темным/системным, чтобы он читался на оранжевом фоне
            opt.palette.setColor(QPalette::Text, option.palette.color(QPalette::Text));
        } else {
            // Если фона анимации нет и ячейка просто залита синим цветом выделения — текст белый
            opt.palette.setColor(QPalette::Text, Qt::white);
        }
    } else {
        // Обычное состояние текста (не выделено)
        opt.palette.setColor(QPalette::Text, opt.palette.color(QPalette::WindowText));
    }

    painter->restore();

    // Передаем opt с уже готовыми звёздочками и цветами в базовый отрисовщик Qt
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
