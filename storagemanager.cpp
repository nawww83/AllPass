#include "storagemanager.h"
#include "utils.h"
#include "constants.h"

#include <QTableWidget>
#include <QFile>
#include <QMessageBox>
#include <QStringEncoder>
#include <QSet>

static const QSet<QString> g_supported_as_version_1 {
                                                    QString("v1.00")
                            };

namespace api_v1 {

static void encode_crc(QByteArray& data) {
    int i;
    char sequence;
    char crc1 = '\0';
    for (auto b : std::as_const(data)) {
        crc1 ^= b;
    }
    data.push_back(crc1);
    char crc2 = '\0';
    i = 1;
    sequence = 0;
    for (auto b : std::as_const(data)) {
        sequence = (i % 2 == 0) ? (sequence % 2) + 1 : sequence++;
        char mul = (i % 2 == 0) ? sequence : 0;
        crc2 = crc2 ^ (i % 2 == 0 ? mul*b : '\0');
        i++;
    }
    data.push_back(crc2);
    char crc3 = '\0';
    i = 1;
    sequence = 0;
    for (auto b : std::as_const(data)) {
        sequence = (i % 3 != 0) ? (sequence % 3) + 1 : sequence++;
        char mul = (i % 3 != 0) ? sequence : 0;
        crc3 = crc3 ^ (i % 3 != 0 ? mul*b : '\0');
        i++;
    }
    data.push_back(crc3);
    char crc5 = '\0';
    i = 1;
    sequence = 0;
    for (auto b : std::as_const(data)) {
        sequence = (i % 5 == 0) ? (sequence % 5) + 1 : sequence++;
        char mul = (i % 5 == 0) ? sequence : 0;
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
    char sequence;
    char crc5 = data.back();
    data.removeLast();
    i = 1;
    sequence = 0;
    for (auto b : std::as_const(data)) {
        sequence = (i % 5 == 0) ? (sequence % 5) + 1 : sequence++;
        char mul = (i % 5 == 0) ? sequence : 0;
        crc5 = crc5 ^ (i % 5 == 0 ? mul*b : '\0');
        i++;
    }
    char crc3 = data.back();
    data.removeLast();
    i = 1;
    sequence = 0;
    for (auto b : std::as_const(data)) {
        sequence = (i % 3 != 0) ? (sequence % 3) + 1 : sequence++;
        char mul = (i % 3 != 0) ? sequence : 0;
        crc3 = crc3 ^ (i % 3 != 0 ? mul*b : '\0');
        i++;
    }
    char crc2 = data.back();
    data.removeLast();
    i = 1;
    sequence = 0;
    for (auto b : std::as_const(data)) {
        sequence = (i % 2 == 0) ? (sequence % 2) + 1 : sequence++;
        char mul = (i % 2 == 0) ? sequence : 0;
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
    enc.aligner64 = 0;
    const auto& code = password::pin_code->mPinCode;
    const int sum_of_pin = code[0] + code[1] + code[2] + code[3] + 16;
    #pragma optimize( "", off )
        for (int i = 0; i < sum_of_pin; ++i) {
            enc.gamma_gen.next_u64();
        }
        enc.gamma = 0;
    #pragma optimize( "", on )
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

static void decrypt256_inner(const QByteArray& in, QByteArray& out, Encryption& dec) {
    if (in.size() % 256 != 0) {
        qDebug() << "Decryption error: data size is not a 256*k bytes";
        return;
    }
    for (auto it = in.begin(); it != in.end(); it++) {
        if (dec.aligner64 % sizeof(lfsr_rng::u64) == 0) {
            dec.gamma = dec.gamma_gen.next_u64();
        }
        uint8_t b = *it;
        out.push_back(char(b) ^ char(dec.gamma));
        dec.gamma >>= 8;
        ++dec.aligner64;
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

static void init_decryption(Encryption& dec) {
    dec.aligner64 = 0;
    const auto& code = password::pin_code->mPinCode;
    const int sum_of_pin = code[0] + code[1] + code[2] + code[3] + 16;
    #pragma optimize( "", off )
        for (int i = 0; i < sum_of_pin; ++i) {
            dec.gamma_gen.next_u64();
        }
        dec.gamma = 0;
    #pragma optimize( "", on )
}

static void finalize_decryption(Encryption& dec) {
    #pragma optimize( "", off )
        if (dec.aligner64 % sizeof(lfsr_rng::u64) != 0) {
            dec.gamma_gen.next_u64();
        }
        dec.gamma = 0;
    #pragma optimize( "", on )
}

static void decrypt(const QByteArray& in, QByteArray& out, Encryption& dec) {
    for (auto it = in.begin(); it != in.end(); it++) {
        if (dec.aligner64 % sizeof(lfsr_rng::u64) == 0) {
            dec.gamma = dec.gamma_gen.next_u64();
        }
        const int rot = dec.gamma % 8;
        uint8_t b = *it ^ char(dec.gamma);
        b = utils::rotl8(b, rot);
        out.push_back(char(b));
        dec.gamma >>= 8;
        ++dec.aligner64;
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

static void insert_hash128_128padd(QByteArray& bytes) {
    lfsr_hash::u128 hash = {0, 0};
    constexpr size_t blockSize = 128;
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

static bool extract_and_check_hash128_128padd(QByteArray& bytes) {
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
    constexpr size_t blockSize = 128;
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
}


StorageManager::StorageManager() {}

template <int version>
QByteArray do_encode(QByteArray& encoded_string, Encryption& enc, Encryption& enc_inner) {
    QByteArray out;
    #define my_encode \
    init_encryption(enc); \
    encode_crc(encoded_string); \
    padd_256(encoded_string); \
    QByteArray encrypted_inner; \
    encrypt256_inner(encoded_string, encrypted_inner, enc_inner); \
    QByteArray permuted; \
    encode_dlog256(encrypted_inner, permuted); \
    encrypt(permuted, out, enc); \
    finalize_encryption(enc); \
    insert_hash128_128padd(out);

    if constexpr (version == 1) {
        using namespace api_v1;
        my_encode;
    }
    return out;
}

template <int version>
QByteArray do_decode(QByteArray& data, QString& storage_name, Encryption& dec, Encryption& dec_inner) {
    QByteArray decoded_data;
    #define my_decode \
    if (!extract_and_check_hash128_128padd(data)) { \
        QMessageBox mb; \
        mb.critical(nullptr, QString::fromUtf8("LFSR hash128: хранилище повреждено"), \
                    QString::fromUtf8("Попробуйте заменить файл: %1 из резервной копии.").arg(storage_name)); \
        storage_name.clear(); \
        return {}; \
    } \
    init_decryption(dec); \
    QByteArray decrypted; \
    decrypt(data, decrypted, dec); \
    QByteArray depermuted; \
    decode_dlog256(decrypted, depermuted); \
    decrypt256_inner(depermuted, decoded_data, dec_inner); \
    dpadd_256(decoded_data); \
    finalize_decryption(dec); \
    if (!decode_crc(decoded_data)) { \
        qDebug() << "CRC: storage data failure: " << storage_name; \
        QMessageBox mb; \
        mb.critical(nullptr, QString::fromUtf8("CRC: хранилище повреждено"), \
                    QString::fromUtf8("Попробуйте заменить файл: %1 из резервной копии.").arg(storage_name)); \
        storage_name.clear(); \
        return {}; \
    }

    if constexpr (version == 1) {
        using namespace api_v1;
        my_decode;
    }
    return decoded_data;
}

void StorageManager::SaveToStorage(const QTableWidget* const ro_table )
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
    if (ro_table->rowCount() < 1) {
        qDebug() << "Empty table.";
        return;
    }
    QByteArray packed_data_bytes;
    auto fromUtf16 = QStringEncoder(QStringEncoder::Utf8);
    for( int row = 0; row < ro_table->rowCount(); ++row )
    {
        QStringList data_rows;
        for( int col = 0; col < ro_table->columnCount(); ++col )
        {
            if (ro_table->item(row, col)) {
                if (col != constants::pswd_column_idx) {
                    const auto& txt = ro_table->item(row, col)->text();
                    data_rows << (txt == "" ? symbols::empty_item : txt);
                } else {
                    data_rows << ro_table->item(row, col)->data(Qt::UserRole).toString();
                }
            } else {
                data_rows << symbols::empty_item;
            }
        }
        QString packed_data_str = data_rows.join( symbols::row_delimiter );
        packed_data_str.append( (row < ro_table->rowCount() - 1 ? symbols::col_delimiter : symbols::end_message) );
        packed_data_bytes.append( fromUtf16( packed_data_str ) );
    }
    QFile file(mStorageName);
    if (file.open(QFile::WriteOnly))
    {
        const QString current_version = QString(VERSION_LABEL).remove(g_version_prefix);
        if (g_supported_as_version_1.contains(current_version)) {
            QByteArray encoded_data_bytes = do_encode<1>(packed_data_bytes, mEnc, mEncInner);
            encoded_data_bytes.append(VERSION_LABEL);
            file.write(encoded_data_bytes);
            file.close();
            qDebug() << "Table has been saved!";
        }
    } else {
        ;
    }
}

void StorageManager::LoadFromStorage(QTableWidget * const wr_table)
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
    if (wr_table->rowCount() > 0) {
        qDebug() << "Table is not empty.";
        return;
    }
    QFile file(mStorageName);
    QByteArray decoded_data_bytes;
    if (file.open(QFile::ReadOnly))
    {
        QByteArray raw_data = file.readAll();
        file.close();
        QString read_version;
        while (!raw_data.isEmpty() && raw_data.back() != g_version_prefix) {
            read_version.push_back(raw_data.back());
            raw_data.removeLast();
        }
        if (!raw_data.isEmpty()) {
            raw_data.removeLast();
        }
        std::reverse(read_version.begin(), read_version.end());
        if (g_supported_as_version_1.contains(read_version)) {
            decoded_data_bytes = do_decode<1>(raw_data, mStorageName, mDec, mDecInner);
        } else {
            mStorageName.clear();
            QMessageBox mb;
            mb.critical(nullptr, QString::fromUtf8("Ошибка формата."),
                                QString::fromUtf8("Неизвестная версия формата."));
            return;
        }
    } else {
        // qDebug() << "Storage cannot be opened.";
        return;
    }
    auto toUtf16 = QStringDecoder(QStringDecoder::Utf8);
    QString decoded_data_str = toUtf16(decoded_data_bytes);
    if (decoded_data_str.isEmpty()) {
        qDebug() << "Unrecognized error while loading.";
        return;
    }
    decoded_data_str.removeLast();
    QStringList data_rows;
    data_rows = decoded_data_str.split(symbols::col_delimiter);
    if (data_rows.isEmpty()) {
        qDebug() << "Empty row data.";
        return;
    }
    QStringList data_items;
    for (int row = 0; row < data_rows.size(); row++)
    {
        data_items = data_rows.at(row).split(symbols::row_delimiter);
        if (data_items.size() == wr_table->columnCount()) {
            wr_table->insertRow(row);
        } else {
            qDebug() << "Unrecognized column size: " << wr_table->columnCount() << " vs " << data_items.size();
            break;
        }
        for (int col = 0; col < data_items.size(); col++)
        {
            const QString& row_str = data_items.at(col);
            QTableWidgetItem *item = new QTableWidgetItem();
            if (col == constants::pswd_column_idx) {
                item->setData(Qt::DisplayRole, g_asterics);
                item->setData(Qt::UserRole, row_str.at(0) == symbols::empty_item ? "" : row_str);
            } else {
                item->setText(row_str.at(0) == symbols::empty_item ? "" : row_str);
            }
            wr_table->setItem(row, col, item);
        }
    }
    wr_table->resizeColumnToContents(constants::pswd_column_idx);
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
