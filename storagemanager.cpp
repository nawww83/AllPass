#include "storagemanager.h"
#include "utils.h"
#include "constants.h"

#include <QTableWidget>
#include <QFile>
#include <QMessageBox>
#include <QStringEncoder>

namespace api_v1 {

static void encode_crc(QByteArray& data) {
    int i;
    char x;
    char crc1 = '\0';
    for (auto b : std::as_const(data)) {
        crc1 ^= b;
    }
    data.push_back(crc1);
    char crc2 = '\0';
    i = 1;
    x = 0;
    for (auto b : std::as_const(data)) {
        x = (i % 2 == 0) ? (x % 2) + 1 : x++;
        char mul = (i % 2 == 0) ? x : 0;
        crc2 = crc2 ^ (i % 2 == 0 ? mul*b : '\0');
        i++;
    }
    data.push_back(crc2);
    char crc3 = '\0';
    i = 1;
    x = 0;
    for (auto b : std::as_const(data)) {
        x = (i % 3 != 0) ? (x % 3) + 1 : x++;
        char mul = (i % 3 != 0) ? x : 0;
        crc3 = crc3 ^ (i % 3 != 0 ? mul*b : '\0');
        i++;
    }
    data.push_back(crc3);
    char crc5 = '\0';
    i = 1;
    x = 0;
    for (auto b : std::as_const(data)) {
        x = (i % 5 == 0) ? (x % 5) + 1 : x++;
        char mul = (i % 5 == 0) ? x : 0;
        crc5 = crc5 ^ (i % 5 == 0 ? mul*b : '\0');
        i++;
    }
    data.push_back(crc5);
}

static bool decode_crc(QByteArray& data) {
    if (data.size() < 4) {
        return false;
    }
    int i;
    char x;
    char crc5 = data.back();
    data.removeLast();
    i = 1;
    x = 0;
    for (auto b : std::as_const(data)) {
        x = (i % 5 == 0) ? (x % 5) + 1 : x++;
        char mul = (i % 5 == 0) ? x : 0;
        crc5 = crc5 ^ (i % 5 == 0 ? mul*b : '\0');
        i++;
    }
    char crc3 = data.back();
    data.removeLast();
    i = 1;
    x = 0;
    for (auto b : std::as_const(data)) {
        x = (i % 3 != 0) ? (x % 3) + 1 : x++;
        char mul = (i % 3 != 0) ? x : 0;
        crc3 = crc3 ^ (i % 3 != 0 ? mul*b : '\0');
        i++;
    }
    char crc2 = data.back();
    data.removeLast();
    i = 1;
    x = 0;
    for (auto b : std::as_const(data)) {
        x = (i % 2 == 0) ? (x % 2) + 1 : x++;
        char mul = (i % 2 == 0) ? x : 0;
        crc2 = crc2 ^ (i % 2 == 0 ? mul*b : '\0');
        i++;
    }
    char crc1 = data.back();
    data.removeLast();
    for (auto b : std::as_const(data)) {
        crc1 ^= b;
    }
    if (crc5 != '\0' || crc3 != '\0' || crc2 != '\0' || crc1 != '\0')
    {
        return false;
    }
    return true;
}

static void init_encryption(Encryption& enc) {
    using namespace password;
    enc.aligner64 = 0;
    const int sum_of_pin = pin_code[0] + pin_code[1] + pin_code[2] + pin_code[3] + 16;
    #pragma optimize( "", off )
    for (int i = 0; i < sum_of_pin; ++i) {
        enc.gamma_gen.next_u64();
    }
    #pragma optimize( "", on )
    enc.gamma = 0;
}

static void finalize_encryption(Encryption& enc) {
    #pragma optimize( "", off )
    if (enc.aligner64 % sizeof(lfsr_rng::u64) != 0) {
        enc.gamma_gen.next_u64();
    }
    enc.gamma = 0;
    #pragma optimize( "", on )
}

static void encrypt256_inner(const QByteArray& in, QByteArray& out, Encryption& enc) {
    if (in.size() % 256 != 0) {
        qDebug() << "Encryption error: data size is not a 256*k bytes";
        return;
    }
    for (auto it = in.begin(); it != in.end(); it++) {
        if (enc.aligner64 % sizeof(lfsr_rng::u64) == 0) {
            enc.gamma = enc.gamma_gen.next_u64();
        }
        uint8_t b = *it;
        out.push_back(char(b) ^ char(enc.gamma));
        enc.gamma >>= 8;
        ++enc.aligner64;
    }
}

static void decrypt256_inner(const QByteArray& in, QByteArray& out, Encryption& enc) {
    if (in.size() % 256 != 0) {
        qDebug() << "Decryption error: data size is not a 256*k bytes";
        return;
    }
    for (auto it = in.begin(); it != in.end(); it++) {
        if (enc.aligner64 % sizeof(lfsr_rng::u64) == 0) {
            enc.gamma = enc.gamma_gen.next_u64();
        }
        uint8_t b = *it;
        out.push_back(char(b) ^ char(enc.gamma));
        enc.gamma >>= 8;
        ++enc.aligner64;
    }
}

static void encrypt(const QByteArray& in, QByteArray& out, Encryption& enc) {
    for (auto it = in.begin(); it != in.end(); it++) {
        if (enc.aligner64 % sizeof(lfsr_rng::u64) == 0) {
            enc.gamma = enc.gamma_gen.next_u64();
        }
        uint8_t b = *it;
        const int rot = enc.gamma % 8;
        b = utils::rotr8(b, rot);
        out.push_back(char(b) ^ char(enc.gamma));
        enc.gamma >>= 8;
        ++enc.aligner64;
    }
}

static void init_decryption(Encryption& enc) {
    using namespace password;
    enc.aligner64 = 0;
    const int sum_of_pin = pin_code[0] + pin_code[1] + pin_code[2] + pin_code[3] + 16;
    #pragma optimize( "", off )
    for (int i = 0; i < sum_of_pin; ++i) {
        enc.gamma_gen.next_u64();
    }
    #pragma optimize( "", on )
    enc.gamma = 0;
}

static void finalize_decryption(Encryption& enc) {
    #pragma optimize( "", off )
    if (enc.aligner64 % sizeof(lfsr_rng::u64) != 0) {
        enc.gamma_gen.next_u64();
    }
    enc.gamma = 0;
    #pragma optimize( "", on )
}

static void decrypt(const QByteArray& in, QByteArray& out, Encryption& enc) {
    for (auto it = in.begin(); it != in.end(); it++) {
        if (enc.aligner64 % sizeof(lfsr_rng::u64) == 0) {
            enc.gamma = enc.gamma_gen.next_u64();
        }
        const int rot = enc.gamma % 8;
        uint8_t b = *it ^ char(enc.gamma);
        b = utils::rotl8(b, rot);
        out.push_back(char(b));
        enc.gamma >>= 8;
        ++enc.aligner64;
    }
}

inline static void padd_256(QByteArray& data) {
    constexpr int p = 257;  // prime, modulo.
    const int n = data.size();
    const int r =  n % (p - 1) != 0 ? (p - 1) - n % (p - 1) : 0;
    int counter = 0;
    while (counter++ < r) {
        data.push_back('\0');
    }
}

static void dpadd_256(QByteArray& data) {
    if (data.isEmpty()) {
        return;
    }
    while (!data.isEmpty() && data.back() == '\0') {
        data.removeLast();
    }
}

static void encode_dlog256(const QByteArray& in, QByteArray& out) {
    constexpr int p = 257;  // prime, modulo.
    const int n = in.size();
    out.resize(n);
    const int ch = n / (p - 1);
    for (int i=0; i<ch; ++i) {
        int x = 1;
        char xor_val = in[i*(p-1)];
        for (int j=1; j<p-1; ++j) {
            xor_val ^= in[i*(p-1) + j];
        }
        const int a = const_arr::goods[((int)xor_val + 128) % std::ssize(const_arr::goods)];
        {
            int counter = 0;
            while (counter++ < (p-1)) {
                out[i*(p-1) + x - 1] = in[i*(p-1) + counter - 1];
                x *= a;
                x %= p;
            }
        }
    }
}

static void decode_dlog256(const QByteArray& in, QByteArray& out) {
    constexpr int p = 257;  // prime, modulo.
    const int n = in.size();
    if (n % (p - 1) != 0) {
        qDebug() << "Decode dlog256 error\n";
        return;
    }
    out.resize(n);
    const int ch = n / (p - 1);
    for (int i=0; i<ch; ++i) {
        int x = 1;
        char xor_val = in[i*(p-1)];
        for (int j=1; j<p-1; ++j) {
            xor_val ^= in[i*(p-1) + j];
        }
        const int a = const_arr::goods[((int)xor_val + 128) % std::ssize(const_arr::goods)];
        {
            int counter = 0;
            while (counter++ < (p-1)) {
                out[i*(p-1) + counter - 1] = in[i*(p-1) + x - 1];
                x *= a;
                x %= p;
            }
        }
    }
}

static void insert_hash128_256padd(QByteArray& bytes) {
    lfsr_hash::u128 hash = {0, 0};
    constexpr size_t blockSize = 256;
    {
        {
            const auto bytesRead = bytes.size();
            const size_t r = bytesRead % blockSize;
            bytes.resize(bytesRead + (r > 0 ? blockSize - r : 0), '\0'); // Zero padding.
        }
        const auto bytesRead = bytes.size();
        {
            using namespace lfsr_hash;
            const salt& original_size_salt = utils::get_salt(bytesRead, blockSize);
            const size_t n = bytesRead / blockSize;
            for (size_t i=0; i<n; ++i) {
                u128 inner_hash = hash128<blockSize>(password::hash_gen,
                                                     reinterpret_cast<const uint8_t*>(bytes.data() + i*blockSize), original_size_salt);
                hash.first ^= inner_hash.first;
                hash.second ^= inner_hash.second;
            }
        }
    }
    while (hash.first) {
        bytes.append(char(hash.first));
        hash.first >>= 8;
    }
    while (hash.second) {
        bytes.append(char(hash.second));
        hash.second >>= 8;
    }
}

static bool extract_and_check_hash128_256padd(QByteArray& bytes) {
    if (bytes.size() < 16) {
        qDebug() << "Small size while hash128 extracting: " << bytes.size();
        return false;
    }
    lfsr_hash::u128 extracted_hash = {0, 0};
    for (int i=0; i<8; ++i) {
        extracted_hash.second |= lfsr8::u64(uint8_t(bytes.back())) << (7-i)*8;
        bytes.removeLast();
    }
    for (int i=0; i<8; ++i) {
        extracted_hash.first |= lfsr8::u64(uint8_t(bytes.back())) << (7-i)*8;
        bytes.removeLast();
    }
    lfsr_hash::u128 hash = {0, 0};
    constexpr size_t blockSize = 256;
    {
        const auto bytesRead = bytes.size();
        {
            using namespace lfsr_hash;
            const salt& original_size_salt = utils::get_salt(bytesRead, blockSize);
            const size_t n = bytesRead / blockSize;
            for (size_t i=0; i<n; ++i) {
                u128 inner_hash = hash128<blockSize>(password::hash_gen,
                                                     reinterpret_cast<const uint8_t*>(bytes.data() + i*blockSize), original_size_salt);
                hash.first ^= inner_hash.first;
                hash.second ^= inner_hash.second;
            }
        }
    }
    while (!bytes.isEmpty() && bytes.back() == '\0') {
        bytes.removeLast();
    }
    return extracted_hash == hash;
}


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
        init_encryption(mEnc);
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
        encode_crc(encoded_string);
        padd_256(encoded_string);
        QByteArray encrypted_inner;
        encrypt256_inner(encoded_string, encrypted_inner, mEncInner);
        QByteArray permuted;
        encode_dlog256(encrypted_inner, permuted);
        encrypt(permuted, out, mEnc);
        finalize_encryption(mEnc);
        out.append(VERSION);
        insert_hash128_256padd(out);
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
        const bool hash_check_is_ok = extract_and_check_hash128_256padd(data);
        if (!hash_check_is_ok) {
            QMessageBox mb;
            mb.critical(nullptr, QString::fromUtf8("LFSR hash128: хранилище повреждено"),
                        QString::fromUtf8("Попробуйте заменить файл: %1 из резервной копии.").arg(mStorageName));
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
        init_decryption(mDec);
        QByteArray decrypted;
        decrypt(data, decrypted, mDec);
        QByteArray depermuted;
        decode_dlog256(decrypted, depermuted);
        QByteArray decrypted_inner;
        decrypt256_inner(depermuted, decrypted_inner, mDecInner);
        dpadd_256(decrypted_inner);
        if (!decode_crc(decrypted_inner)) {
            qDebug() << "CRC: storage data failure: " << mStorageName;
            QMessageBox mb;
            mb.critical(nullptr, QString::fromUtf8("CRC: хранилище повреждено"),
                        QString::fromUtf8("Попробуйте заменить файл: %1 из резервной копии.").arg(mStorageName));
            mStorageName.clear();
            return;
        }
        auto toUtf16 = QStringDecoder(QStringDecoder::Utf8);
        QString decoded_string = toUtf16(decrypted_inner);
        if (decoded_string.isEmpty()) {
            qDebug() << "Unrecognized error while loading.";
            return;
        }
        decoded_string.removeLast(); // 0x0003 = symbols::end_message.
        rowOfData = decoded_string.split(symbols::col_delimiter);
        finalize_decryption(mDec);
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
    {
        QMessageBox mb;
        mb.information(nullptr, QString::fromUtf8("Успех"),
                QString::fromUtf8("Данные хранилища загружены в таблицу."));
    }
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

}
