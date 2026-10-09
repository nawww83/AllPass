#pragma once

#include <QTableWidgetItem>

class CryptoTableItem : public QTableWidgetItem
{
public:
    explicit CryptoTableItem(const QString &text = "");

    ~CryptoTableItem() override;

    // Переопределяем метод чтения данных
    QVariant data(int role) const override;

    // Переопределяем метод записи данных (например, при редактировании пользователем)
    void setData(int role, const QVariant &value) override;

    // ОБЯЗАТЕЛЬНО ДЛЯ СОРТИРОВКИ И КОПИРОВАНИЯ ЯЧЕЕК QT:
    QTableWidgetItem *clone() const override;

private:
    QString m_secretData; // Наше изолированное хранилище пароля в куче

    void setSecretText(const QString &text);
};
