#ifndef PASSITEMDELEGATE_H
#define PASSITEMDELEGATE_H

#include <QItemDelegate>

class PassEditDelegate : public QItemDelegate
{
public:
    explicit PassEditDelegate(const char* asterics, QObject* parent = nullptr)
        : mAsterics(asterics)
        , QItemDelegate(parent)
    {}
    void setEditorData(QWidget *editor, const QModelIndex &index) const;

    void setModelData(QWidget *editor, QAbstractItemModel *model, const QModelIndex &index) const;

private:
    const char* mAsterics;
};

#endif // PASSITEMDELEGATE_H
