#ifndef STORAGEMANAGER_H
#define STORAGEMANAGER_H

#include "stream_cipher.h"
#include <QString>

class QTableWidget;

struct Encryption
{
    lfsr_rng::Generators gamma_gen;
    int aligner64 = 0;
    long long counter = 0;
    lfsr_rng::u64 gamma = 0;
};

enum class Loading_Errors {
    OK = 0,
    UNRECOGNIZED,
    EMPTY_STORAGE,
    EMPTY_ENCRYPTION,
    TABLE_IS_NOT_EMPTY,
    UNKNOWN_FORMAT,
    CANNOT_BE_OPENED,
    EMPTY_TABLE,
    CRC_FAILURE,
    NEW_STORAGE
};

class StorageManager
{
public:
    StorageManager();

    void SaveToStorage(const QTableWidget * const ro_table);

    Loading_Errors LoadFromStorage(QTableWidget * const wr_table, bool from_backup = false);

    void SetName(const QString& name);

    QString Name() const;

    void SetEncGammaGenerator(const lfsr_rng::Generators& generator);

    void SetDecGammaGenerator(const lfsr_rng::Generators& generator);

    void SetEncInnerGammaGenerator(const lfsr_rng::Generators& generator);

    void SetDecInnerGammaGenerator(const lfsr_rng::Generators& generator);

private:
    QString mStorageName;

    QString mStorageNameBackUp;

    Encryption mEnc;
    Encryption mDec;
    Encryption mEncInner;
    Encryption mDecInner;
};

#endif // STORAGEMANAGER_H
