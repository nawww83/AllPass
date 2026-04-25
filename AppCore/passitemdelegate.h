#ifndef PASSITEMDELEGATE_H
#define PASSITEMDELEGATE_H

#include <QStyledItemDelegate>

namespace roles {
inline constexpr int AnimationRole = Qt::UserRole + 100;
}

class PassEditDelegate : public QStyledItemDelegate
{
    Q_OBJECT
public:
    explicit PassEditDelegate(QObject *parent = nullptr);

    // Создает виджет для редактирования (QLineEdit в режиме пароля)
    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option,
                          const QModelIndex &index) const override;

    // Передает данные из модели в редактор
    void setEditorData(QWidget *editor, const QModelIndex &index) const override;

    // Сохраняет данные из редактора обратно в модель
    void setModelData(QWidget *editor, QAbstractItemModel *model,
                      const QModelIndex &index) const override;

    bool helpEvent(QHelpEvent *event, QAbstractItemView *view,
                   const QStyleOptionViewItem &option, const QModelIndex &index) override;

    void paint(QPainter *painter, const QStyleOptionViewItem &option,
               const QModelIndex &index) const override;

};

#endif // PASSITEMDELEGATE_H
