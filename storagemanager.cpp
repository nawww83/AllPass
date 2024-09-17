#include "storagemanager.h"
#include "utils.h"
#include "constants.h"

#ifdef __unix__                    /* __unix__ is usually defined by compilers targeting Unix systems */
    #define OS_Windows 0
#elif defined(_WIN32) || defined(WIN32)     /* _Win32 is usually defined by compilers targeting 32 or   64 bit Windows systems */
    #define OS_Windows 1
    #include <windows.h>
#endif

#include <QTableWidget>
#include <QFile>
#include <QMessageBox>
#include <QStringEncoder>
#include <QSet>

static const QSet<QString> g_supported_as_version_1 {
                        QString("v1.00"),
                        QString("v1.01")
                    };

#ifdef OS_Windows
    static void do_hidden(wchar_t* fileLPCWSTR) {
        int attr = GetFileAttributes(fileLPCWSTR);
        if ((attr & FILE_ATTRIBUTE_HIDDEN) == 0) {
            SetFileAttributes(fileLPCWSTR, attr | FILE_ATTRIBUTE_HIDDEN);
        }
    }
#endif

namespace api_v1 {

template <int basic_modulo, int swap_modulo, bool initial_swap>
static char core_crc(const QByteArray& data, int initial_crc='\0') {
    char crc = initial_crc;
    const int N = data.size() + 1;
    bool current_swap = initial_swap;
    int sequence = 13; // Нечетное, фаза. Влияет на кодовое расстояние.
    for (int i=1; i<N; i++) {
        const bool doit = current_swap ? i % basic_modulo != 0 : i % basic_modulo == 0;
        sequence = doit ? (sequence % basic_modulo) + ((sequence % basic_modulo) % 2) + 1 : sequence + 2;
        char mul = doit ? sequence : 0; // sequence в mul всегда нечетный: покрытие базиса.
        crc ^= mul * data.at(i-1);
        if constexpr (swap_modulo > 0) {
            current_swap ^= i % swap_modulo == 0;
        }
    }
    return crc;
};

static QByteArray encode_249_crc_7(const QByteArray& data) {
    QByteArray out_crc;
    {
        char crc1 = '\0';
        for (const auto b : std::as_const(data)) {
            crc1 ^= b;
        }
        out_crc.push_back(crc1);
        char crc2 = core_crc<11, 16, false>(data);
        out_crc.push_back(crc2);
        char crc8 = core_crc<41, 205, false>(data);
        out_crc.push_back(crc8);
        char crc16 = core_crc<17, 7, false>(data);
        out_crc.push_back(crc16);
    }
    {
        char crc2 = core_crc<11, 16, true>(data);
        out_crc.push_back(crc2);
        char crc8 = core_crc<41, 205, true>(data);
        out_crc.push_back(crc8);
        char crc16 = core_crc<17, 7, true>(data);
        out_crc.push_back(crc16);
    }
    return out_crc;
}

static bool decode_249_crc_7(const QByteArray& data, QByteArray& crc) {
    if (crc.size() != 7) {
        return false;
    }
    {
        char crc16 = core_crc<17, 7, true>(data, crc.back());
        crc.removeLast();
        char crc8 = core_crc<41, 205, true>(data, crc.back());
        crc.removeLast();
        char crc2 = core_crc<11, 16, true>(data, crc.back());
        crc.removeLast();
        if (crc16 != '\0' || crc8 != '\0' || crc2 != '\0')
        {
            return false;
        }
    }
    {
        char crc16 = core_crc<17, 7, false>(data, crc.back());
        crc.removeLast();
        char crc8 = core_crc<41, 205, false>(data, crc.back());
        crc.removeLast();
        char crc2 = core_crc<11, 16, false>(data, crc.back());
        crc.removeLast();
        char crc1 = crc.back();
        crc.removeLast();
        for (const auto b : std::as_const(data)) {
            crc1 ^= b;
        }
        if (crc16 != '\0' || crc8 != '\0' || crc2 != '\0' || crc1 != '\0')
        {
            return false;
        }
    }
    return true;
}

static void init_encryption(Encryption& enc, const QByteArray& salt = {}) {
    enc.aligner64 = 0;
    const int steps = 256 + (int)utils::xor_val(salt);
    for (int i = 0; i < steps; ++i) {
        enc.gamma_gen.next_u64();
        enc.counter++;
    }
    enc.gamma = 0;
}

static void finalize_encryption(Encryption& enc) {
    while (enc.counter != 0) {
        enc.gamma_gen.back_u64();
        enc.counter--;
    }
    enc.gamma = 0;
    enc.aligner64 = 0;
}

static void encrypt256_inner(const QByteArray& in, QByteArray& out, Encryption& enc) {
    if (in.size() % 256 != 0) {
        qDebug() << "Encryption error: data size is not a 256*k bytes";
        return;
    }
    for (auto it = in.begin(); it != in.end(); it++) {
        if (enc.aligner64 % sizeof(lfsr_rng::u64) == 0) {
            enc.gamma = enc.gamma_gen.next_u64();
            enc.counter++;
        }
        uint8_t b = *it;
        out.push_back(char(b) ^ char(enc.gamma));
        enc.gamma >>= CHAR_BIT;
        ++enc.aligner64;
    }
}

static void decrypt256_inner(const QByteArray& in, QByteArray& out, Encryption& dec) {
    if (in.size() % 256 != 0) {
        qDebug() << "Inner decryption error: data size is not a 256*k bytes";
        return;
    }
    for (auto it = in.begin(); it != in.end(); it++) {
        if (dec.aligner64 % sizeof(lfsr_rng::u64) == 0) {
            dec.gamma = dec.gamma_gen.next_u64();
            dec.counter++;
        }
        uint8_t b = *it;
        out.push_back(char(b) ^ char(dec.gamma));
        dec.gamma >>= CHAR_BIT;
        ++dec.aligner64;
    }
}

static void encrypt(const QByteArray& in, QByteArray& out, Encryption& enc) {
    for (auto it = in.begin(); it != in.end(); it++) {
        if (enc.aligner64 % sizeof(lfsr_rng::u64) == 0) {
            enc.gamma = enc.gamma_gen.next_u64();
            enc.counter++;
        }
        uint8_t b = *it;
        const int rot = enc.gamma % CHAR_BIT;
        b = utils::rotr8(b, rot);
        out.push_back(char(b) ^ char(enc.gamma));
        enc.gamma >>= CHAR_BIT;
        ++enc.aligner64;
    }
}

static void decrypt(const QByteArray& in, QByteArray& out, Encryption& dec) {
    for (auto it = in.begin(); it != in.end(); it++) {
        if (dec.aligner64 % sizeof(lfsr_rng::u64) == 0) {
            dec.gamma = dec.gamma_gen.next_u64();
            dec.counter++;
        }
        const int rot = dec.gamma % CHAR_BIT;
        uint8_t b = *it ^ char(dec.gamma);
        b = utils::rotl8(b, rot);
        out.push_back(char(b));
        dec.gamma >>= CHAR_BIT;
        ++dec.aligner64;
    }
}

static void encode_dlog256(const QByteArray& in, QByteArray& out) {
    constexpr int p = 257;  // prime, modulo.
    const int n = in.size();
    out.resize(n);
    const int ch = n / (p - 1);
    for (int i=0; i<ch; ++i) {
        char xor_val = in[i*(p-1)];
        for (int j=1; j<p-1; ++j) {
            xor_val ^= in[i*(p-1) + j];
        }
        const int a = const_arr::goods[((int)xor_val - std::numeric_limits<char>::min()) % std::ssize(const_arr::goods)];
        int x = a;
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
        char xor_val = in[i*(p-1)];
        for (int j=1; j<p-1; ++j) {
            xor_val ^= in[i*(p-1) + j];
        }
        const int a = const_arr::goods[((int)xor_val - std::numeric_limits<char>::min()) % std::ssize(const_arr::goods)];
        int x = a;
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

static void insert_hash128(QByteArray& bytes) {
    if (bytes.size() % 128 != 0) {
        qDebug() << "Insert hash128 error: input size is not a 128*k bytes: " << bytes.size();
        return;
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
    const int num_of_bytes = sizeof(hash.first);
    for (int i=0; i<num_of_bytes; ++i) {
        bytes.append(char(hash.first));
        hash.first >>= CHAR_BIT;
    }
    for (int i=0; i<num_of_bytes; ++i) {
        bytes.append(char(hash.second));
        hash.second >>= CHAR_BIT;
    }
}

static bool extract_and_check_hash128(QByteArray& bytes) {
    if (bytes.size() % 16 != 0) {
        qDebug() << "Extract hash128 error: input size is not a 16*k bytes: " << bytes.size();
        return false;
    }
    lfsr_hash::u128 extracted_hash = {0, 0};
    const int num_of_bytes = sizeof(extracted_hash.first);
    if (bytes.size() < 2*num_of_bytes) {
        qDebug() << "Small size while hash128 extracting: " << bytes.size();
        return false;
    }
    for (int i=0; i<num_of_bytes; ++i) {
        extracted_hash.second |= lfsr8::u64(uint8_t(bytes.back())) << (num_of_bytes-1-i)*CHAR_BIT;
        bytes.removeLast();
    }
    for (int i=0; i<num_of_bytes; ++i) {
        extracted_hash.first |= lfsr8::u64(uint8_t(bytes.back())) << (num_of_bytes-1-i)*CHAR_BIT;
        bytes.removeLast();
    }
    lfsr_hash::u128 calculated_hash = {0, 0};
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
                calculated_hash.first ^= inner_hash.first;
                calculated_hash.second ^= inner_hash.second;
            }
        }
    }
    return extracted_hash == calculated_hash;
}
}


StorageManager::StorageManager() {}

template <int version>
QByteArray do_encode(QByteArray& encoded_string, Encryption& enc, Encryption& enc_inner) {
    QByteArray out;
    #define my_encode \
    init_encryption(enc); \
    constexpr int K = 249; \
    constexpr int R = 7; \
    utils::padd<K>(encoded_string); \
    const int N = encoded_string.length(); \
    const int Q = N / K; \
    QByteArray crc; \
    const auto it = encoded_string.cbegin(); \
    for (int q=0; q<Q; ++q) { QByteArray in(it + q*K, K); crc.append(encode_249_crc_7(in)); } \
    encoded_string.append(crc); \
    if (encoded_string.length() % (K + R) != 0) { \
        qDebug() << "CRC encode failure: output size is not a 256*k: " << encoded_string.size(); \
        finalize_encryption(enc); \
        return {}; \
    } \
    init_encryption(enc_inner, crc); \
    QByteArray encrypted_inner; \
    encrypt256_inner(encoded_string, encrypted_inner, enc_inner); \
    QByteArray permuted; \
    encode_dlog256(encrypted_inner, permuted); \
    insert_hash128(permuted); \
    permuted.append(crc); \
    encrypt(permuted, out, enc); \
    finalize_encryption(enc); \
    finalize_encryption(enc_inner);

    if constexpr (version == 1) {
        using namespace api_v1;
        my_encode;
    }
    return out;
}

template <int version>
QByteArray do_decode(QByteArray& data, Encryption& dec, Encryption& dec_inner) {
    QByteArray decoded_data;
    #define my_decode \
    constexpr int K = 249; \
    constexpr int R = 7; \
    constexpr int hash_size = 16; \
    init_encryption(dec); \
    QByteArray decrypted; \
    decrypt(data, decrypted, dec); \
    const int Q = (decrypted.size() - hash_size) / (K + 2*R); \
    const int Res = (decrypted.size() - hash_size) % (K + 2*R); \
    if (Res != 0) { \
        qDebug() << "CRC decode failure: input size is not a 263*k: " << decrypted.size(); \
        finalize_encryption(dec); \
        return {}; \
    } \
    QByteArray crc; \
    for (int q=0; q<Q; ++q) { \
        for (int i=0; i<R; ++i) {crc.push_back(decrypted.back()); decrypted.removeLast();}; \
    } \
    std::reverse(crc.begin(), crc.end()); \
    if (!extract_and_check_hash128(decrypted)) { \
        finalize_encryption(dec); \
        return {}; \
    } \
    QByteArray depermuted; \
    decode_dlog256(decrypted, depermuted); \
    init_encryption(dec_inner, crc); \
    decrypt256_inner(depermuted, decoded_data, dec_inner); \
    QByteArray crc_copy; \
    for (int q=0; q<Q; ++q) { \
        for (int i=0; i<R; ++i) {crc_copy.push_back(decoded_data.back()); decoded_data.removeLast();}; \
    } \
    std::reverse(crc_copy.begin(), crc_copy.end()); \
    if (crc != crc_copy) { \
        qDebug() << "CRC decode failure: crc != crc_copy."; \
        finalize_encryption(dec); \
        finalize_encryption(dec_inner); \
        return {}; \
    } \
    auto it = decoded_data.cbegin(); \
    auto it_crc = crc_copy.cbegin(); \
    for (int q=0; q<Q; ++q) { \
        const QByteArray in(it + q*K, K); \
        QByteArray crc_(it_crc + q*R, R); \
        if (!decode_249_crc_7(in, crc_)) { \
            qDebug() << "CRC: storage data failure, q: " << q; \
            finalize_encryption(dec); \
            finalize_encryption(dec_inner); \
            return {}; \
        } \
    } \
    utils::dpadd(decoded_data); \
    finalize_encryption(dec); \
    finalize_encryption(dec_inner);

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
    QByteArray encoded_data_bytes;
    QFile file(mStorageName);
    const QString& current_version = QString(VERSION_LABEL).remove(g_version_prefix);
    if (g_supported_as_version_1.contains(current_version)) {
        encoded_data_bytes = do_encode<1>(packed_data_bytes, mEnc, mEncInner);
    }
    if (encoded_data_bytes.isEmpty()) {
        return;
    }
    encoded_data_bytes.append(VERSION_LABEL);
    utils::padd<128>(encoded_data_bytes);
    if (file.open(QFile::WriteOnly))
    {
        file.write(encoded_data_bytes);
        file.close();
        QFile file_backup(mStorageNameBackUp);
        if (file_backup.open(QFile::WriteOnly)) {
            file_backup.write(encoded_data_bytes);
            file_backup.close();
            #ifdef OS_Windows
                do_hidden(file_backup.fileName().toStdWString().data());
            #endif
            qDebug() << "Make backup: " << mStorageNameBackUp;
        }
    } else {
        QFile file_backup(mStorageNameBackUp);
        if (file_backup.open(QFile::WriteOnly)) {
            file_backup.write(encoded_data_bytes);
            file_backup.close();
            #ifdef OS_Windows
                do_hidden(file_backup.fileName().toStdWString().data());
            #endif
            qDebug() << "Make backup only: " << mStorageNameBackUp;
        } else {
            QMessageBox mb;
            mb.critical(nullptr, QString::fromUtf8("Ошибка сохранения."),
                        QString::fromUtf8("Файловая ошибка сохранения таблицы в хранилище."));
        }
    }
}

Loading_Errors StorageManager::LoadFromStorage(QTableWidget * const wr_table, bool from_backup)
{
    const QString file_name = from_backup ? mStorageNameBackUp : mStorageName;
    if (file_name.isEmpty()) {
        qDebug() << "Empty storage.";
        return Loading_Errors::EMPTY_STORAGE;
    }
    if (!mDec.gamma_gen.is_succes()) {
        qDebug() << "Empty decryption.";
        return Loading_Errors::EMPTY_ENCRYPTION;
    }
    if (!mDecInner.gamma_gen.is_succes()) {
        qDebug() << "Empty inner decryption.";
        return Loading_Errors::EMPTY_ENCRYPTION;
    }
    if (wr_table->rowCount() > 0) {
        qDebug() << "Table is not empty.";
        return Loading_Errors::TABLE_IS_NOT_EMPTY;
    }
    QFile file(file_name);
    QByteArray decoded_data_bytes;
    if (file.open(QFile::ReadOnly))
    {
        QByteArray raw_data = file.readAll();
        file.close();
        utils::dpadd(raw_data);
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
            decoded_data_bytes = do_decode<1>(raw_data, mDec, mDecInner);
            if (decoded_data_bytes.isEmpty()) {
                return Loading_Errors::CRC_FAILURE;
            }
        } else {
            return Loading_Errors::UNKNOWN_FORMAT;
        }
    } else {
        // qDebug() << "Storage cannot be opened.";
        if (file.exists()) {
            return Loading_Errors::CANNOT_BE_OPENED;
        } else {
            return Loading_Errors::NEW_STORAGE;
        }
    }
    auto toUtf16 = QStringDecoder(QStringDecoder::Utf8);
    QString decoded_data_str = toUtf16(decoded_data_bytes);
    if (decoded_data_str.isEmpty()) {
        qDebug() << "Unrecognized error while loading.";
        return Loading_Errors::UNRECOGNIZED;
    }
    decoded_data_str.removeLast();
    QStringList data_rows;
    data_rows = decoded_data_str.split(symbols::col_delimiter);
    if (data_rows.isEmpty()) {
        qDebug() << "Empty row data.";
        return Loading_Errors::EMPTY_TABLE;
    }
    QStringList data_items;
    for (int row = 0; row < data_rows.size(); row++)
    {
        data_items = data_rows.at(row).split(symbols::row_delimiter);
        if (data_items.size() == wr_table->columnCount()) {
            wr_table->insertRow(row);
        } else {
            qDebug() << "Unrecognized column size: " << wr_table->columnCount() << " vs " << data_items.size();
            return Loading_Errors::UNRECOGNIZED;
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
    qDebug() << "Table has been loaded!";
    return Loading_Errors::OK;
}

void StorageManager::SetName(const QString &name)
{
    mStorageName = name;
    mStorageNameBackUp = QString::fromUtf8(".") + name;
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
