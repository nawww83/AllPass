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

enum class FileTypes {
    NORMAL = 0,
    BACKUP,
    TEMPORARY
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

    void SaveToStorage(const QTableWidget * const ro_table, bool save_to_tmp = false);

    Loading_Errors LoadFromStorage(QTableWidget * const wr_table, FileTypes type = FileTypes::NORMAL);

    void RemoveTmpFile();

    bool FileIsExist() const;

    bool BackupFileIsExist() const;

    bool TmpFileIsExist() const;

    bool WasUpdated() const;

    bool IsSuccess() const;

    bool IsTryToLoadFromTmp() const;

    void BeforeUpdate();

    void AfterUpdate();

    void SetName(const QString& name);

    void SetTmpName(const QString& name);

    QString Name() const;

    QString NameTmp() const;

    void SetTryToLoadFromTmp(bool value = true);

    void SetEncGammaGenerator(const lfsr_rng::Generators& generator);

    void SetDecGammaGenerator(const lfsr_rng::Generators& generator);

    void SetEncInnerGammaGenerator(const lfsr_rng::Generators& generator);

    void SetDecInnerGammaGenerator(const lfsr_rng::Generators& generator);

private:
    QString mStorageName;

    QString mStorageNameBackUp;

    QString mStorageNameTmp;

    Encryption mEnc;
    Encryption mDec;
    Encryption mEncInner;
    Encryption mDecInner;

    int mSetCounter;
    bool mWasUpdated;

    bool mTryToLoadFromTmp = false;
};

#endif // STORAGEMANAGER_H
