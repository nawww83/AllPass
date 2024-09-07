#include "storagemanager.h"
#include "utils.h"
#include "constants.h"

#include <QTableWidget>
#include <QFile>
#include <QMessageBox>
#include <QStringEncoder>

StorageManager::StorageManager() {}

void StorageManager::SaveToStorage(const QTableWidget* const table )
{
    if (mStorageName.isEmpty()) {
        qDebug() << "Empty storage.";
        return;
    }
    if (!mEnc.gamma_gen.is_succes()) {
        qDebug() << "Empty encryption.";
        return;
    }
    if (!mEncInner.gamma_gen.is_succes()) {
        qDebug() << "Empty inner encryption.";
        return;
    }
    if (table->rowCount() < 1) {
        qDebug() << "Empty table.";
        return;
    }
    QFile file(mStorageName);
    if (file.open(QFile::WriteOnly))
    {
        QStringList strList;
        QByteArray out;
        QByteArray encoded_string;
        utils::init_encryption(mEnc);
        const int rc = table->rowCount();
        const int cc = table->columnCount();
        for( int row = 0; row < rc; ++row )
        {
            strList.clear();
            for( int col = 0; col < cc; ++col )
            {
                if (table->item(row, col)) {
                    if (col != constants::pswd_column_idx) {
                        const auto& txt = table->item(row, col)->text();
                        strList << (txt == "" ? symbols::empty_item : txt);
                    } else {
                        strList << table->item(row, col)->data(Qt::UserRole).toString();
                    }
                }
                else {
                    strList << symbols::empty_item;
                }
            }
            auto fromUtf16 = QStringEncoder(QStringEncoder::Utf8);
            QString tmp = strList.join( symbols::row_delimiter );
            tmp.append( (row < table->rowCount() - 1 ? symbols::col_delimiter : symbols::end_message) );
            encoded_string.append(fromUtf16( tmp ));
        }
        utils::padd_256(encoded_string);
        QByteArray encrypted_inner;
        utils::encrypt256_inner(encoded_string, encrypted_inner, mEncInner);
        QByteArray permuted;
        utils::encode_dlog256(encrypted_inner, permuted);
        utils::encrypt(permuted, out, mEnc);
        utils::finalize_encryption(mEnc);
        utils::encode_crc(out);
        out.append(VERSION);
        utils::insert_hash128_256padd(out);
        file.write(out);
        file.close();
        qDebug() << "Table has been saved!";
    } else {
        ;
    }
}

void StorageManager::LoadFromStorage(QTableWidget * const table)
{
    if (mStorageName.isEmpty()) {
        qDebug() << "Empty storage.";
        return;
    }
    if (!mDec.gamma_gen.is_succes()) {
        qDebug() << "Empty decryption.";
        return;
    }
    if (!mDecInner.gamma_gen.is_succes()) {
        qDebug() << "Empty inner decryption.";
        return;
    }
    if (table->rowCount() > 0) {
        qDebug() << "Table is not empty.";
        return;
    }
    QFile file(mStorageName);
    QStringList rowOfData;
    QStringList rowData;
    QByteArray data;
    if (file.open(QFile::ReadOnly))
    {
        data = file.readAll();
        const bool hash_check_is_ok = utils::extract_and_check_hash128_256padd(data);
        if (!hash_check_is_ok) {
            QMessageBox mb;
            mb.critical(nullptr, QString::fromUtf8("LFSR hash128: хранилище повреждено"),
                        QString::fromUtf8("Попробуйте заменить файл: %1 из резервного хранилища").arg(mStorageName));
            mStorageName.clear();
            return;
        }
        QString version;
        while (!data.isEmpty() && data.back() != g_version_prefix) {
            version.push_back(data.back());
            data.removeLast();
        }
        if (!data.isEmpty()) {
            data.removeLast();
        }
        std::reverse(version.begin(), version.end());
        const QString etalon_version = QString(VERSION).remove(g_version_prefix);
        if (version != etalon_version) {
            qDebug() << "Unrecognized version: " << version;
            return;
        }
        if (!utils::decode_crc(data)) {
            qDebug() << "CRC: storage data failure: " << mStorageName;
            QMessageBox mb;
            mb.critical(nullptr, QString::fromUtf8("CRC: хранилище повреждено"),
                        QString::fromUtf8("Попробуйте заменить файл: %1 из резервного хранилища").arg(mStorageName));
            mStorageName.clear();
            return;
        }
        utils::init_decryption(mDec);
        QByteArray decrypted;
        utils::decrypt(data, decrypted, mDec);
        QByteArray depermuted;
        utils::decode_dlog256(decrypted, depermuted);
        QByteArray decrypted_inner;
        utils::decrypt256_inner(depermuted, decrypted_inner, mDecInner);
        utils::dpadd_256(decrypted_inner);
        auto toUtf16 = QStringDecoder(QStringDecoder::Utf8);
        QString decoded_string = toUtf16(decrypted_inner);
        if (decoded_string.isEmpty()) {
            qDebug() << "Unrecognized error while loading.";
            return;
        }
        decoded_string.removeLast(); // 0x0003 = symbols::end_message.
        rowOfData = decoded_string.split(symbols::col_delimiter);
        utils::finalize_decryption(mDec);
        file.close();
    } else {
        // qDebug() << "Storage cannot be opened.";
        return;
    }
    if (rowOfData.isEmpty()) {
        qDebug() << "Empty row data.";
        return;
    }
    for (int row = 0; row < rowOfData.size(); row++)
    {
        rowData = rowOfData.at(row).split(symbols::row_delimiter);
        if (rowData.size() == table->columnCount()) {
            table->insertRow(row);
        } else {
            qDebug() << "Unrecognized column size: " << table->columnCount() << " vs " << rowData.size();
            break;
        }
        for (int col = 0; col < rowData.size(); col++)
        {
            const QString& row_str = rowData.at(col);
            QTableWidgetItem *item = new QTableWidgetItem();
            if (col == constants::pswd_column_idx) {
                item->setData(Qt::DisplayRole, g_asterics);
                item->setData(Qt::UserRole, row_str.at(0) == symbols::empty_item ? "" : row_str);
            } else {
                item->setText(row_str.at(0) == symbols::empty_item ? "" : row_str);
            }
            table->setItem(row, col, item);
        }
    }
    table->resizeColumnToContents(constants::pswd_column_idx);
    qDebug() << "Table has been loaded!";
}

void StorageManager::SetName(const QString &name)
{
    mStorageName = name;
}

QString StorageManager::Name() const
{
    return mStorageName;
}

void StorageManager::SetEncGammaGenerator(const lfsr_rng::Generators &generator)
{
    mEnc.gamma_gen = generator;
}

void StorageManager::SetDecGammaGenerator(const lfsr_rng::Generators &generator)
{
    mDec.gamma_gen = generator;
}

void StorageManager::SetEncInnerGammaGenerator(const lfsr_rng::Generators &generator)
{
    mEncInner.gamma_gen = generator;
}

void StorageManager::SetDecInnerGammaGenerator(const lfsr_rng::Generators &generator)
{
    mDecInner.gamma_gen = generator;
}
