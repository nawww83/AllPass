#include "worker.h"
#include <QtConcurrent/qtconcurrentrun.h>
#include <utils.h>

QFuture<std::shared_ptr<lfsr_rng::Generators>> Worker::seed(lfsr_rng::STATE st)
{
    // Делаем копию состояния для потока, так как оригинал затрем
    lfsr_rng::STATE threadState = st;
    utils::clear_lfsr_rng_state(st); // Сразу зануляем мастер-ключ в главном потоке

    // Передаем состояние в поток по значению
    auto f = [threadState]() mutable {
        // Выделяем генератор в куче внутри shared_ptr
        auto g = std::make_shared<lfsr_rng::Generators>();
        g->seed(threadState);

        // Зануляем временное состояние в куче фонового потока
        utils::clear_lfsr_rng_state(threadState);
        return g;
    };

    return QtConcurrent::run(f);
}

QFuture<QVector<lfsr8::u64>> Worker::gen_n(std::shared_ptr<lfsr_rng::Generators> g, int n)
{
    // Фоновому потоку передается shared_ptr (копируется только указатель и счетчик ссылок)
    auto f = [g, n]() {
        QVector<lfsr8::u64> v;
        if (n > 0 && g && g->is_succes()) {
            v.reserve(n);
            for (int i = 0; i < n; ++i) {
                v.push_back(g->next_u64());
            }
        }
        return v;
    };

    return QtConcurrent::run(f);
}
