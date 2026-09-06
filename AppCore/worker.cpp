#include "worker.h"
#include <QtConcurrent/QtConcurrent>
#include <QPair>
#include <utils.h>

QFuture<lfsr_rng::Generators> Worker::seed(lfsr_rng::STATE st) {
    auto f = [](lfsr_rng::STATE st) {
        lfsr_rng::Generators g;
        g.seed(st);

        // Очищаем исходный стейт-параметр в стеке потока, так как g его уже скопировал
        utils::clear_lfsr_rng_state(st);
        return g;
    };
    return QtConcurrent::run(f, st);
}

QFuture<QVector<lfsr8::u64>> Worker::gen_n(lfsr_rng::Generators g, int n)
{
    auto f = [g](int n) mutable {
        QVector<lfsr8::u64> v;
        if (n > 0) {
            v.reserve(n);
            for (int i = 0; i < n; ++i) {
                v.push_back(g.next_u64());
            }
        }
        g.clear();

        return v;
    };
    return QtConcurrent::run(f, n);
}
