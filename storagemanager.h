#ifndef STORAGEMANAGER_H
#define STORAGEMANAGER_H

#include "stream_cipher.h"
#include <QString>

class QTableWidget;

struct Encryption
{
    lfsr_rng::Generators gamma_gen;
    int aligner64 = 0;
    lfsr_rng::u64 gamma = 0;
};

namespace api_v1 {

class StorageManager
{
public:
    StorageManager();

    void SaveToStorage(const QTableWidget * const table);

    void LoadFromStorage(QTableWidget * const table);

    void SetName(const QString& name);

    QString Name() const;

    void SetEncGammaGenerator(const lfsr_rng::Generators& generator);

    void SetDecGammaGenerator(const lfsr_rng::Generators& generator);

    void SetEncInnerGammaGenerator(const lfsr_rng::Generators& generator);

    void SetDecInnerGammaGenerator(const lfsr_rng::Generators& generator);

private:
    QString mStorageName;

    Encryption mEnc;
    Encryption mDec;
    Encryption mEncInner;
    Encryption mDecInner;
};

}

#endif // STORAGEMANAGER_H
