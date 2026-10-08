#include "worker.h"
#include <QtConcurrent/qtconcurrentrun.h>
#include <utils.h>

struct SafeState
{
    lfsr_rng::STATE state;

    // Обычный конструктор
    explicit SafeState(const lfsr_rng::STATE &st)
        : state(st)
    {}

    // Явный конструктор копирования (нужен для недр QtConcurrent)
    SafeState(const SafeState &other)
        : state(other.state)
    {}

    // Очищает память при уничтожении любой копии
    ~SafeState() { utils::clear_lfsr_rng_state(state); }
};

struct SafeGenerators
{
    lfsr_rng::Generators generators;

    // Обычный конструктор
    explicit SafeGenerators(const lfsr_rng::Generators &g)
        : generators(g)
    {}

    // Явный конструктор копирования для внутренних нужд QtConcurrent
    SafeGenerators(const SafeGenerators &other)
        : generators(other.generators)
    {}

    // Гарантированная зачистка при уничтожении любой промежуточной копии
    ~SafeGenerators() { generators.clear(); }
};

QFuture<lfsr_rng::Generators> Worker::seed(lfsr_rng::STATE st) {
    SafeState safe(st);
    utils::clear_lfsr_rng_state(st);
    auto f = [](SafeState wrappedState) {
        lfsr_rng::Generators g;
        g.seed(wrappedState.state);
        return g;
    };

    return QtConcurrent::run(f, safe);
}

QFuture<QVector<lfsr8::u64>> Worker::gen_n(lfsr_rng::Generators g, int n)
{
    // 1. Упаковываем состояние в защитную капсулу
    SafeGenerators safe(g);

    // 2. Сразу очищаем оригинал в стеке текущего (главного) потока
    g.clear();

    // Лямбда принимает SafeGenerators по значению.
    auto f = [](SafeGenerators safeG, int n) {
        QVector<lfsr8::u64> v;
        if (n > 0) {
            v.reserve(n);
            for (int i = 0; i < n; ++i) {
                v.push_back(safeG.generators.next_u64());
            }
        }
        return v;
    };

    // Передаем капсулу и число генераций.
    // Когда QtConcurrent удалит задачу из кучи, деструктор очистит и ту внутреннюю копию.
    return QtConcurrent::run(f, safe, n);
}
