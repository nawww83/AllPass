#include "worker.h"
#include <QtConcurrent/QtConcurrent>
#include <QPair>


QFuture<lfsr_rng::Generators> Worker::seed(lfsr_rng::STATE st) {
    auto f = [](lfsr_rng::STATE st) {
        lfsr_rng::Generators g;
        g.seed(st);
        return g;
    };
    return QtConcurrent::run(f, st);
}

QFuture<QVector<lfsr8::u64> > Worker::gen_n(lfsr_rng::Generators& g, int n)
{
    auto f = [&g](int n) {
        QVector<lfsr8::u64> v{};
        v.reserve(n);
        for (int i=0; i<n; ++i) {
            v.push_back( g.next_u64() );
        }
        QThread::msleep(20);
        return v;
    };
    return QtConcurrent::run(f, n);
}
