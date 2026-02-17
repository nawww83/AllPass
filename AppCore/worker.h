#ifndef WORKER_H
#define WORKER_H

#include <QObject>
#include <QFuture>

#include "stream_cipher.h"

class Worker : public QObject
{
public:
    QFuture<lfsr_rng::Generators> seed(lfsr_rng::STATE);
    QFuture<QVector<lfsr8::u64> > gen_n(lfsr_rng::Generators g, int n);
    QFuture<lfsr8::u64 > check_period(lfsr_rng::Generators &g, lfsr8::u64& ref);
private:
    ;
};

#endif // WORKER_H
