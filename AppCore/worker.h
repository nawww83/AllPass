#ifndef WORKER_H
#define WORKER_H

#include <QFuture>
#include <QObject>
#include <QVector>
#include <memory> // Добавлено для std::shared_ptr

#include "stream_cipher.h"

class Worker : public QObject
{
public:
    // Возвращаем shared_ptr на генератор, чтобы избежать его копирования
    QFuture<std::shared_ptr<lfsr_rng::Generators>> seed(lfsr_rng::STATE st);

    // Принимаем shared_ptr на генератор
    QFuture<QVector<lfsr8::u64>> gen_n(std::shared_ptr<lfsr_rng::Generators> g, int n);
};

#endif // WORKER_H
