#pragma once

// Мост между старым (v3) и новым (v4) хэшем AllPass.
//
// v4 — самостоятельный движок с собственной финализацией; v3 оставлен
// отдельной копией (lfsr_v3.h / lfsr_hash_v3.h), чтобы читать хранилища
// v3.00/v3.01/v3.02 бит-в-бит. Здесь собраны только те адаптеры, которые
// нужны общему коду приложения.

#include "lfsr_hash.h"
#include "lfsr_hash_v3.h"

#include <cstdint>
#include <limits>
#include <span>

/// Режим хэширования, с которым открыто/создаётся хранилище.
enum class HashMode
{
    V3Legacy, // v3.00/v3.01: старый SIMD-путь без приведения входа по модулю p
    V3Fixed,  // v3.02: исправленный v3
    V4        // v4.00: новый движок, нелинейный фолд и единая финализация
};

inline bool is_v3(HashMode mode)
{
    return mode != HashMode::V4;
}

namespace lfsr_hash
{
    /**
     * @brief Привести показатель соли к инъективному виду.
     * @details `pin_to_salt`/`get_salt`/`hash_to_salt` кладут в `q`
     * произвольное число. В v4 `add_salt` не нормализует показатель, поэтому
     * `gcd(q, порядок группы) > 1` склеил бы состояния. Поднимаем q до
     * ближайшего значения, взаимно простого со всеми четырьмя порядками.
     */
    inline salt normalize_salt(salt s)
    {
        std::int64_t q = s.q;
        if (q <= 0)
            q = 1;

        constexpr std::int64_t q_max = std::numeric_limits<int>::max();
        while (q <= q_max && !salt_is_injective(static_cast<int>(q)))
            ++q;
        if (q > q_max)
            q = 1; // практически недостижимо: рядом всегда есть подходящее q

        s.q = static_cast<int>(q);
        return s;
    }

    /**
     * @brief Хэшировать очередной кусок, сохраняя состояние между вызовами.
     * @details Старый API AllPass (`hash128(gens&, span)`) использовал `gens`
     * как накопитель: каждый вызов продолжал цепочку. В v4 состояние живёт
     * внутри `hasher`, поэтому копируем его туда и возвращаем обратно после
     * `finish()`. Это сохраняет структуру вызовов без изменения формата.
     */
    inline u128 hash128(gens &g, std::span<const std::byte> data)
    {
        hasher h;
        h.set_state(g);
        h.update(data);
        u128 result = h.finish();
        g = h.state();
        return result;
    }
} // namespace lfsr_hash

namespace lfsr_hash_v3
{
    /// v3 сам нормализует q в fixed-режиме; в legacy-режиме нужен исходный q.
    inline salt normalize_salt(salt s)
    {
        return s;
    }
} // namespace lfsr_hash_v3
