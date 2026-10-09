#include "crypto_table_item.h"
#include "utils.h"

CryptoTableItem::CryptoTableItem(const QString &text)
    : QTableWidgetItem()
{
    // Сразу безопасно записываем текст
    setSecretText(text);
}

CryptoTableItem::~CryptoTableItem()
{
    // Принудительно выжигаем секретные данные при удалении строки/ячейки
    utils::erase_string(m_secretData);
}

QVariant CryptoTableItem::data(int role) const
{
    if (role == Qt::DisplayRole || role == Qt::EditRole) {
        // Возвращаем копию. Благодаря защите, внешние методы (делегат, буфер)
        // не смогут занулить внутренности самого айтема.
        QString returnStr = m_secretData;
        returnStr.detach();
        return QVariant(returnStr);
    }
    return QTableWidgetItem::data(role);
}

void CryptoTableItem::setData(int role, const QVariant &value)
{
    if (role == Qt::DisplayRole || role == Qt::EditRole) {
        QString newText = value.toString();
        setSecretText(newText);
        return;
    }
    QTableWidgetItem::setData(role, value);
}

QTableWidgetItem *CryptoTableItem::clone() const
{
    // Создаем новый защищенный элемент с копией наших данных
    return new CryptoTableItem(m_secretData);
}

void CryptoTableItem::setSecretText(const QString &text)
{
    // Старый секрет выжигаем перед перезаписью
    utils::erase_string(m_secretData);

    m_secretData = text;
    // КРИТИЧЕСКИЙ БАРЬЕР: Разом, намертво изолируем память пароля в куче ячейки
    m_secretData.detach();
}
