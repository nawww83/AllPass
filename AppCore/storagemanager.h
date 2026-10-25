#ifndef STORAGEMANAGER_H
#define STORAGEMANAGER_H

#include <QString>
#include "stream_cipher.h"
#include <memory> // Необходим для std::shared_ptr

class QTableWidget;

struct Encryption
{
    std::shared_ptr<lfsr_rng::Generators> gamma_gen;
    uint64_t aligner64 = 0;
    uint64_t counter = 0;
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

    bool SaveToStorage(const QTableWidget * const ro_table, bool save_to_tmp = false);

    Loading_Errors LoadFromStorage(QTableWidget * const wr_table, FileTypes type = FileTypes::NORMAL);

    void RemoveTmpFile();

    // Проверяет идентичность mStorageName и mStorageNameBackUp,
    // при несовпадении или отсутствии копии перезаписывает ее.
    bool SyncBackupStorage();

    bool FileIsExist() const;

    // Проверка существования хранилища по имени, без изменения состояния.
    bool FileIsExist(const QString& name) const;

    // Проверка существования скрытой резервной копии по имени хранилища.
    bool BackupFileIsExist(const QString& name) const;

    bool BackupFileIsExist() const;

    bool TmpFileIsExist() const;

    bool WasUpdated() const;

    bool IsSuccess() const;

    bool IsTryToLoadFromTmp() const;

    void BeforeUpdate();

    void AfterUpdate();

    void SetName(const QString& name);

    // Режим хэширования: true — совместимость со старыми базами (v3.00/v3.01).
    void SetLegacyHash(bool legacy);
    bool IsLegacyHash() const;

    // Метка версии, которая будет записана в файл (без символа '#').
    void SetVersionLabel(const QString& label);
    QString VersionLabel() const;

    // Читает метку версии из хвоста файла хранилища (если основного файла
    // нет — из скрытой резервной копии). Файл не расшифровывается.
    QString ReadVersionLabel(const QString& name) const;

    // Есть ли рядом копия "<name>.<версия>.bak" — след автоконвертации.
    // Нужно, чтобы отличить устаревший USB-ключ от действительно нового
    // хранилища, когда файла под старым именем уже нет.
    bool ConvertedBackupExists(const QString& name) const;

    // Переименовывает основное хранилище и его скрытую копию (например,
    // legacy-имя -> fixed-имя после конвертации). Существующие файлы не
    // перезаписываются; при сбое частичного переноса выполняется откат.
    bool RenameStorage(const QString& new_name);

    // Однократно переводит открытую старую базу (v3.00/v3.01) в текущий
    // формат, перезаписывая её файл на месте: имя файла не меняется, но
    // содержимое шифруется уже исправленными ключами. Перед записью рядом
    // сохраняется копия старого файла "<имя>.<версия>.bak". При сбое записи
    // состояние и файлы откатываются, метод возвращает false.
    bool ConvertToCurrentFormat(const QTableWidget * const table,
                                std::shared_ptr<lfsr_rng::Generators> enc,
                                std::shared_ptr<lfsr_rng::Generators> dec,
                                std::shared_ptr<lfsr_rng::Generators> enc_inner,
                                std::shared_ptr<lfsr_rng::Generators> dec_inner);

    void SetTmpName(const QString& name);

    QString Name() const;

    QString NameTmp() const;

    void SetTryToLoadFromTmp(bool value = true);

    void SetEncGammaGenerator(const std::shared_ptr<lfsr_rng::Generators> &generator);

    void SetDecGammaGenerator(const std::shared_ptr<lfsr_rng::Generators> &generator);

    void SetEncInnerGammaGenerator(const std::shared_ptr<lfsr_rng::Generators> &generator);

    void SetDecInnerGammaGenerator(const std::shared_ptr<lfsr_rng::Generators> &generator);

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

    // Режим хэширования и версия формата текущего хранилища.
    bool mLegacyHash = false;
    QString mVersionLabel;
};

#endif // STORAGEMANAGER_H
