#pragma once

/**
 * @author Новиков А.В., nawww83@gmail.com.
 *
 * Генератор LFSR в поле GF(p^m) с числом ячеек m = [1, 8] и простым модулем p = [2, 256*256).
 * Реализован код для SSE4.1 архитектуры x86_64.
 * Реализованы:
 *  - Генератор общего назначения:
 *     - p = [2, 256) для m = [5, 8],
 *     - p = [2, 256*256) для m = [1, 4].
 *  - Сдвоенный генератор с фиксированным m = 4, p = [2, 256). Фактически, это два независимых генератора,
 *  реализованных на одном регистре 128-бит в коде SSE4.1.
*/

#include <cstdint>
#include <array>
#include <type_traits>
#include <cmath>

#if defined(__x86_64__) || defined(_M_X64)
#define USE_SSE
#endif

#ifdef USE_SSE
#include <immintrin.h>
#include <smmintrin.h>
#endif

namespace lfsr8
{
using u64 = uint64_t;
using u32 = uint32_t;
using u16 = uint16_t;
using u16x8 = std::array<u16, 8>;
using u32x4 = std::array<u32, 4>;

template <int m>
class MType
{
public:
    typedef typename std::conditional<(m <= 4), u32, u16>::type SAMPLE;
    typedef typename std::conditional<(m <= 4), u32x4, u16x8>::type STATE;
};

template <int p, int m>
class LFSR
{
    using STATE = typename MType<m>::STATE;
    using SAMPLE = typename MType<m>::SAMPLE;

public:
    constexpr LFSR(STATE K) : m_K(K)
    {
        static_assert(m <= 8 && m > 0, "m must be 1..8");
        m_calculate_inverse_of_K();
    }

    /**
         * @brief Максимальный период генератора.
         */
    static const unsigned long T_MAX = std::pow(p, m) - 1;

    void set_state(STATE state) { m_state = state; }
    void set_unit_state()
    {
        m_state.fill(0);
        m_state[0] = 1;
    }
    /**
         * Установить коэффициенты порождающего полинома g(x).
         */
    void set_K(STATE K)
    {
        m_K = K;
        m_calculate_inverse_of_K();
    }
    STATE get_state() const { return m_state; }
    SAMPLE get_cell(int idx) const { return m_state[idx]; }

    /**
         * @brief Является ли заданное состояние текущим состоянием генератора.
         * @param state Заданное состояние.
         * @return Да/нет.
         */
    bool is_state(STATE state) const
    {
#ifdef USE_SSE
        bool result = true;
        for (int i = 0; i < m; ++i)
        {
            result &= (m_state[i] == state[i]);
        }
        return result;
#else
        return (state == m_state);
#endif
    }

private:
    alignas(16) STATE m_state{};
    alignas(16) STATE m_K{};
    alignas(16) STATE m_inv_K{};

    // Векторная редукция для m=8 (u16)
    [[nodiscard]] __attribute__((always_inline)) inline __m128i fast_reduce_u16(__m128i v_n) const
    {
        const uint16_t inv_p = (uint16_t)((1ULL << 16) / p);
        const __m128i v_inv_p = _mm_set1_epi16(inv_p);
        const __m128i v_p = _mm_set1_epi16(p);
        __m128i q = _mm_mulhi_epu16(v_n, v_inv_p);
        __m128i res = _mm_sub_epi16(v_n, _mm_mullo_epi16(q, v_p));
        __m128i mask = _mm_cmpgt_epi16(res, _mm_sub_epi16(v_p, _mm_set1_epi16(1)));
        return _mm_sub_epi16(res, _mm_and_si128(mask, v_p));
    }

public:
    void next(SAMPLE input = 0)
    {
        if constexpr (m > 4)
        { // Путь SSE (оптимально для 8 элементов)
#if defined(__x86_64__) || defined(_M_X64)
            __m128i a = _mm_set1_epi16(m_state[m - 1]);
            __m128i b = _mm_load_si128((const __m128i *)&m_K);
            __m128i c = _mm_load_si128((const __m128i *)&m_state);
            c = _mm_slli_si128(c, 2);
            __m128i inp = _mm_andnot_si128(_mm_slli_si128(_mm_set1_epi16(-1), 2), _mm_set1_epi16(input));
            c = _mm_add_epi16(c, _mm_mullo_epi16(a, b));
            c = _mm_add_epi16(c, inp);
            _mm_store_si128((__m128i *)&m_state, fast_reduce_u16(c));
#endif
        }
        else
        { // Скалярный путь (рекордные 7 тактов на i7-8565U для m=4)
            const SAMPLE m_v = m_state[m - 1];
            for (int i = m - 1; i > 0; i--)
                m_state[i] = (m_state[i - 1] + m_v * m_K[i]) % (SAMPLE)p;
            m_state[0] = (input + m_v * m_K[0]) % (SAMPLE)p;
        }
    }

    void back(SAMPLE input = 0)
    {
        if constexpr (m > 4)
        {
#if defined(__x86_64__) || defined(_M_X64)
            __m128i m1 = _mm_slli_si128(_mm_set1_epi16(-1), 2);
            __m128i a = _mm_mullo_epi16(_mm_add_epi16(_mm_sub_epi16(_mm_andnot_si128(m1, _mm_set1_epi16(m_state[0])),
                                                                    _mm_andnot_si128(m1, _mm_set1_epi16(input))),
                                                      _mm_set1_epi16(p)),
                                        _mm_load_si128((const __m128i *)&m_inv_K));
            a = _mm_add_epi16(a, _mm_slli_si128(a, 2));
            a = _mm_add_epi16(a, _mm_slli_si128(a, 4));
            a = _mm_add_epi16(a, _mm_slli_si128(a, 8));
            a = fast_reduce_u16(a);
            __m128i mask = _mm_andnot_si128(_mm_slli_si128(_mm_set_epi16(0, 0, 0, 0, 0, 0, 0, -1), 2 * (m - 1)), _mm_set1_epi16(-1));
            __m128i d = _mm_and_si128(mask, _mm_srli_si128(_mm_load_si128((__m128i *)&m_state), 2));
            __m128i k = _mm_add_epi16(_mm_and_si128(mask, _mm_srli_si128(_mm_load_si128((__m128i *)&m_K), 2)), _mm_slli_si128(_mm_set_epi16(0, 0, 0, 0, 0, 0, 0, -1), 2 * (m - 1)));
            _mm_store_si128((__m128i *)&m_state, fast_reduce_u16(_mm_add_epi16(_mm_sub_epi16(d, _mm_mullo_epi16(a, k)), _mm_set1_epi16((SAMPLE)(p * p)))));
#endif
        }
        else
        {
            const SAMPLE m_v = (m_inv_K[0] * (m_state[0] - input + (SAMPLE)p)) % (SAMPLE)p;
            for (int i = 0; i < m - 1; i++)
                m_state[i] = (m_state[i + 1] - m_v * m_K[i + 1] + (SAMPLE)p * (SAMPLE)p) % (SAMPLE)p;
            m_state[m - 1] = m_v;
        }
    }

    void mult_by(STATE other)
    {
        const STATE old = m_state;
        m_state.fill(0);
        std::array<uint32_t, 16> s{};
        for (int i = 0; i < m; ++i)
        {
            uint32_t vi = old[i];
            for (int j = 0; j < m; ++j)
                s[i + j] += vi * (uint32_t)other[j];
        }
        for (int i = 2 * m - 2; i >= 0; --i)
            next(s[i] % (uint32_t)p);
    }

    void square() { mult_by(m_state); } // Учитывая замеры i7-8565U, простой Multiply эффективнее Square

    /**
         * @brief Возвести текущее состояние генератора в степень.
         * @param q Показатель степени.
         */
    void power_by(unsigned long q)
    {
        unsigned long x = q;
        LFSR<p, m> lfsr{m_K};
        lfsr.set_unit_state();
        for (; x != 0;)
        {
            if ((x & 1) == 1)
                lfsr.mult_by(get_state());
            square();
            x /= 2;
        }
        set_state(lfsr.get_state());
    }

    /**
         * @brief Возвести состояние в степень.
         * @param state Состояние x^t.
         * @param K Коэффициенты порождающего полинома g(x).
         * @param q Показатель степени.
         * @return Состояние x^(qt).
         */
    static STATE power_by(STATE state, STATE K, unsigned long q)
    {
        LFSR<p, m> lfsr{K};
        lfsr.set_state(state);
        lfsr.power_by(q);
        return lfsr.get_state();
    }

    /**
         * @brief Вычислить обратное состояние.
         * @param state Состояние x^t.
         * @param K Коэффициенты порождающего полинома g(x).
         * @return Состояние, 1/x^t.
         */
    static STATE inverse_of(STATE state, STATE K)
    {
        return power_by(state, K, T_MAX - 1);
    }

    /**
         * @brief Насытить генератор.
         * @param q Количество тактов.
         */
    void saturate(int q = m)
    {
        for (int i = 0; i < q; ++i)
        {
            next();
        }
    }

private:
    void m_calculate_inverse_of_K()
    {
        SAMPLE inv = 1;
        while ((m_K[0] * inv) % p != 1)
            inv++;
        m_inv_K.fill(inv);
    }
};

template <int p>
class LFSR_paired_2x4
{
    static_assert(p < 256 && p > 1);
    alignas(16) u16x8 m_state{};
    alignas(16) u16x8 m_K{};
    alignas(16) u16x8 m_inv_K{};

    /**
         * @brief Вычисляются обратные (по умножению) коэффициенты.
         */
    void m_calculate_inverse_of_K()
    {
        const auto g0 = m_K[0];
        const auto g4 = m_K[4];

        u16 inv0 = 1, inv4 = 1;
        const u16 modulo = static_cast<u16>(p);
        bool ok0 = false, ok4 = false;

        // Линейный поиск (эффективен для p < 256)
        for (;;)
        {
            if (!ok0 && (g0 * inv0) % modulo == 1)
                ok0 = true;
            if (!ok4 && (g4 * inv4) % modulo == 1)
                ok4 = true;
            if (ok0 && ok4)
                break;
            if (!ok0)
                inv0++;
            if (!ok4)
                inv4++;
        }

        // ХАРДКОР: Заполняем m_inv_K так, чтобы SSE back() мог умножать векторно
        // Половина для первого LFSR (0-3), половина для второго (4-7)
        for (int i = 0; i < 4; ++i)
        {
            m_inv_K[i] = inv0;     // Реплицируем inv0 в младшую часть
            m_inv_K[i + 4] = inv4; // Реплицируем inv4 в старшую часть
        }
    }

    // Векторная редукция (Barrett) для 8 элементов u16
    [[nodiscard]] __attribute__((always_inline)) inline __m128i fast_reduce_u16(__m128i v_n) const
    {
        const uint16_t inv_p = (uint16_t)((1ULL << 16) / p);
        const __m128i v_inv_p = _mm_set1_epi16(inv_p);
        const __m128i v_p = _mm_set1_epi16(p);
        __m128i q = _mm_mulhi_epu16(v_n, v_inv_p);
        __m128i res = _mm_sub_epi16(v_n, _mm_mullo_epi16(q, v_p));
        __m128i mask = _mm_cmpgt_epi16(res, _mm_sub_epi16(v_p, _mm_set1_epi16(1)));
        return _mm_sub_epi16(res, _mm_and_si128(mask, v_p));
    }

public:
    constexpr LFSR_paired_2x4(u16x8 K) : m_K(K) { m_calculate_inverse_of_K(); }

    void next(u16 input = 0)
    {
#ifdef USE_SSE
        __m128i s_v = _mm_load_si128((__m128i *)&m_state);
        // Извлекаем m_state[3] и m_state[7]
        __m128i a = _mm_set1_epi16(m_state[3]);
        __m128i b = _mm_set1_epi16(m_state[3] ^ m_state[7]);
        a = _mm_xor_si128(a, _mm_slli_si128(b, 8)); // Комбинируем управляющие сигналы

        __m128i k_v = _mm_load_si128((__m128i *)&m_K);
        __m128i c = _mm_mullo_epi16(a, k_v);

        const __m128i mask = _mm_set_epi16(-1, -1, -1, 0, -1, -1, -1, 0);
        __m128i inp = _mm_andnot_si128(mask, _mm_set1_epi16(input));

        __m128i d = _mm_add_epi16(_mm_add_epi16(c, _mm_and_si128(mask, _mm_slli_si128(s_v, 2))), inp);
        _mm_store_si128((__m128i *)&m_state, fast_reduce_u16(d));
#else
        // Сохраняем значения "выходных" ячеек
        const u16 v3 = m_state[3];
        const u16 v7 = m_state[7];

        // Сдвиг и обратная связь для обеих половин (0-3 и 4-7)
        for (int i = 3; i > 0; i--)
        {
            // Левая половина
            m_state[i] = (m_state[i - 1] + v3 * m_K[i]) % static_cast<u16>(p);
            // Правая половина
            m_state[i + 4] = (m_state[i + 3] + v7 * m_K[i + 4]) % static_cast<u16>(p);
        }

        // Входные значения для обеих половин
        m_state[0] = (input + v3 * m_K[0]) % static_cast<u16>(p);
        m_state[4] = (input + v7 * m_K[4]) % static_cast<u16>(p);
#endif
    }

    void next(u16 inp1, u16 inp2)
    {
#ifdef USE_SSE
        // 1. Формируем управляющий сигнал для двух LFSR одновременно
        __m128i v3 = _mm_set1_epi16(m_state[3]);
        __m128i v7_xor_v3 = _mm_set1_epi16(m_state[3] ^ m_state[7]);
        // a будет содержать v3 в младших 8 байтах и v7 в старших
        __m128i a = _mm_xor_si128(v3, _mm_slli_si128(v7_xor_v3, 8));

        // 2. Умножаем на коэффициенты K
        __m128i c = _mm_mullo_epi16(a, _mm_load_si128((const __m128i *)&m_K[0]));

        // 3. Формируем вектор входов [0, 0, 0, inp2, 0, 0, 0, inp1]
        // Используем _mm_insert_epi16 для максимальной скорости на Intel
        __m128i v_inp = _mm_setzero_si128();
        v_inp = _mm_insert_epi16(v_inp, inp1, 0);
        v_inp = _mm_insert_epi16(v_inp, inp2, 4);

        // 4. Сдвигаем текущее состояние и накладываем маску (обнуляем ячейки 0 и 4)
        const __m128i mask = _mm_set_epi16(-1, -1, -1, 0, -1, -1, -1, 0);
        __m128i d = _mm_and_si128(mask, _mm_slli_si128(_mm_load_si128((__m128i *)&m_state[0]), 2));

        // 5. Суммируем всё и применяем быструю редукцию
        __m128i res = _mm_add_epi16(_mm_add_epi16(c, d), v_inp);
        _mm_store_si128((__m128i *)&m_state[0], fast_reduce_u16(res));

#else // Скалярная версия (уже была нами оптимизирована)
        u16 v3 = m_state[3], v7 = m_state[7];
        for (int i = 7; i > 4; i--)
        {
            m_state[i] = (m_state[i - 1] + v7 * m_K[i]) % (u16)p;
            m_state[i - 4] = (m_state[i - 5] + v3 * m_K[i - 4]) % (u16)p;
        }
        m_state[0] = (inp1 + v3 * m_K[0]) % (u16)p;
        m_state[4] = (inp2 + v7 * m_K[4]) % (u16)p;
#endif
    }

    void back(u16 inp1, u16 inp2)
    {
#ifdef USE_SSE
        __m128i m1 = _mm_slli_si128(_mm_set1_epi16(-1), 2);
        const __m128i m2 = _mm_set_epi16(-1, -1, -1, 0, -1, -1, -1, -1);
        __m128i input = _mm_or_si128(_mm_andnot_si128(m1, _mm_set1_epi16(inp1)), _mm_andnot_si128(m2, _mm_set1_epi16(inp2)));

        __m128i st = _mm_or_si128(_mm_andnot_si128(m1, _mm_set1_epi16(m_state[0])), _mm_andnot_si128(m2, _mm_set1_epi16(m_state[4])));
        __m128i a = _mm_mullo_epi16(_mm_add_epi16(_mm_sub_epi16(st, input), _mm_set1_epi16(p)), _mm_load_si128((__m128i *)&m_inv_K));

        // Развертка свертки для восстановления m_v
        a = _mm_add_epi16(a, _mm_slli_si128(a, 2));
        a = _mm_add_epi16(a, _mm_slli_si128(a, 4));
        a = fast_reduce_u16(a);

        const __m128i mask = _mm_set_epi16(0, -1, -1, -1, 0, -1, -1, -1);
        __m128i d = _mm_and_si128(mask, _mm_srli_si128(_mm_load_si128((__m128i *)&m_state), 2));
        __m128i k_v = _mm_add_epi16(_mm_and_si128(mask, _mm_srli_si128(_mm_load_si128((__m128i *)&m_K), 2)), _mm_set_epi16(-1, 0, 0, 0, -1, 0, 0, 0));

        __m128i res = _mm_add_epi16(_mm_sub_epi16(d, _mm_mullo_epi16(a, k_v)), _mm_set1_epi16((u16)(p * p)));
        _mm_store_si128((__m128i *)&m_state, fast_reduce_u16(res));
#else
        // Вычисляем управляющие значения для восстановления состояния
        const u16 v1 = (m_inv_K[0] * (m_state[0] - inp1 + static_cast<u16>(p))) % static_cast<u16>(p);
        const u16 v2 = (m_inv_K[4] * (m_state[4] - inp2 + static_cast<u16>(p))) % static_cast<u16>(p);

        // Восстанавливаем предыдущие значения ячеек
        for (int i = 0; i < 3; i++)
        {
            // Левая половина: (текущая - вклад_v + p^2) % p
            m_state[i] = (m_state[i + 1] - v1 * m_K[i + 1] + static_cast<u16>(p * p)) % static_cast<u16>(p);
            // Правая половина
            m_state[i + 4] = (m_state[i + 5] - v2 * m_K[i + 5] + static_cast<u16>(p * p)) % static_cast<u16>(p);
        }

        // Записываем восстановленные m_v в последние ячейки
        m_state[3] = v1;
        m_state[7] = v2;
#endif
    }

    auto get_state() const
    {
        return m_state;
    }

    /**
         * @brief Совпадает ли заданное состояние с текущей нижней частью состояния.
         * @param state Заданное состояние.
         * @return Да/нет.
         */
    bool is_state_low(u16x8 state) const
    {
        bool result = true;
        for (int i = 0; i < 4; ++i)
        {
            result &= (m_state[i] == state[i]);
        }
        return result;
    }

    /**
         * @brief Совпадает ли заданное состояние с текущей верхней частью состояния.
         * @param state Заданное состояние.
         * @return Да/нет.
         */
    bool is_state_high(u16x8 state) const
    {
        bool result = true;
        for (int i = 0; i < 4; ++i)
        {
            result &= (m_state[i + 4] == state[i + 4]);
        }
        return result;
    }

    void set_state(u16x8 state)
    {
        m_state = state;
    }

    void set_unit_state()
    {
        m_state = {1, 0, 0, 0, 1, 0, 0, 0};
    }

    void set_K(u16x8 K)
    {
        m_K = K;
        m_calculate_inverse_of_K();
    }
};

}
