#pragma once

/**
 * @author Новиков А.В.
 *
 * Генератор псевдослучайных чисел с периодом около 2^155 по отношению к 16-битному отсчету.
*/

#include "lfsr_hash/lfsr.h"

#include <utility>
#include <cmath>
#include <numeric>
#include <array>

namespace lfsr_rng {

using u16 = lfsr8::u16;
using u32 = lfsr8::u32;
using u64 = lfsr8::u64;
using u128 = std::pair<lfsr8::u64, lfsr8::u64>;

// Простые числа: поля Галуа GF(p^m).
static constexpr std::array<int, 4> p {19, 17, 17, 13};
// Длина сдвоенных LFSR-генераторов. Один генератор имеет длину m/2.
static constexpr int m = 8;

using LFSR_pair_1 = lfsr8::LFSR_paired_2x4<p[0]>;
using LFSR_pair_2 = lfsr8::LFSR_paired_2x4<p[1]>;
using LFSR_pair_3 = lfsr8::LFSR_paired_2x4<p[2]>;
using LFSR_pair_4 = lfsr8::LFSR_paired_2x4<p[3]>;
using STATE = lfsr8::u16x8;

// Коэффициенты LFSR-генераторов, дающие максимальный свободный (немодулированный) период.
static constexpr STATE K1 = {9, 5, 2, 0, 4, 2, 2, 6};    // p=19
static constexpr STATE K2 = {3, 4, 2, 1, 6, 1, 2, 1};    // p=17
static constexpr STATE K3 = {3, 2, 3, 4, 6, 2, 0, 7};    // p=17
static constexpr STATE K4 = {2, 3, 1, 1, 2, 0, 1, 7};    // p=13

// Периоды модулирующей "пилы": выбраны так, что периоды T = p^4 - 1 не делятся на соответствующие периоды нацело.
static constexpr std::array<int, 4> primes {7, 11, 11, 11};


// Дубликаты простых периодов для упрощения реализации.
static constexpr std::array<int, 8> primes_duplicates {7, 7, 11, 11, 11, 11, 11, 11};

static_assert((primes[0] == primes_duplicates[0]) && (primes[0] == primes_duplicates[1]));
static_assert((primes[1] == primes_duplicates[2]) && (primes[1] == primes_duplicates[3]));
static_assert((primes[2] == primes_duplicates[4]) && (primes[2] == primes_duplicates[5]));
static_assert((primes[3] == primes_duplicates[6]) && (primes[3] == primes_duplicates[7]));

inline STATE operator^(const STATE& x, const STATE& y) {
    STATE st;
    for (int i=0; i<m; ++i) {
        st[i] = x[i] ^ y[i];
    }
    return st;
}

inline void operator^=(STATE& x, const STATE& y) {
    for (int i=0; i<m; ++i) {
        x[i] ^= y[i];
    }
}


inline STATE operator%(const STATE& x, u32 p) {
    STATE st;
    for (int i=0; i<m; ++i) {
        st[i] = x[i] % p;
    }
    return st;
}

inline void operator%=(STATE& x, u32 p) {
    for (int i=0; i<m; ++i) {
        x[i] %= p;
    }
}

template <size_t N>
inline void sawtooth(std::array<u16, N>& v, const std::array<int, N>& p) {
    size_t i = 0;
    for (auto& el : v) {
        el++;
        el %= p[i];
        i++;
    }
}

template <size_t N>
inline void increment(std::array<u32, N>& v) {
    for (auto& el : v) {
        el++;
    }
}

/**
 * @brief Вычисляет НОК сравнительно небольших чисел.
 * @param v Массив чисел.
 * @return НОК чисел массива.
 */
template <size_t N>
inline int my_lcm(const std::array<int, N>& v) {
    int lcm_res = v[0];
    for (size_t i=1; i<N; ++i) {
        lcm_res = std::lcm(lcm_res, v[i]);
    }
    return lcm_res;
}

/**
 * @brief Набор из 4-х генераторных пар типа LFSR.
 */
struct Generators {
private:
    LFSR_pair_1 gp1;
    LFSR_pair_2 gp2;
    LFSR_pair_3 gp3;
    LFSR_pair_4 gp4;
    /**
     * @brief Счетчики периодов.
     */
    std::array<u32, 8> Tc{};

    /**
     * @brief Вычисленные периоды.
     */
    std::array<u32, 8> Tref{};

    /**
     * @brief Рабочие состояния генераторов "пилы".
     */
    std::array<u16, 8> ii_saw{};

    /**
     * @brief Вычисленные начальные состояния генераторов "пилы".
     */
    std::array<u16, 8> ii0_saw{};

    /**
     * @brief Признак того, что итоговый генератор инициализирован заданным seed.
     */
    int is_finded;

public:

    /**
     * @brief Конструктор.
     */
    constexpr Generators(): gp1(K1), gp2(K2),  gp3(K3), gp4(K4),
        is_finded(0)
    {}

    /**
     * @brief Признак успешной инициализации генератора заданным seed.
     * @return
     */
    bool is_succes() const {
        return (is_finded != 0);
    }

    /**
     * @brief Признак того, что состояние младшей половины генераторной пары совпадает с переданным.
     * @param st Переданное состояние.
     * @param idx Идентификатор LFSR генераторной пары.
     * @return Признак равенства.
     */
    bool is_state_low(STATE st, int idx) {
        switch (idx) {
        case 0:
            return gp1.is_state_low(st);
            break;
        case 1:
            return gp2.is_state_low(st);
            break;
        case 2:
            return gp3.is_state_low(st);
            break;
        case 3:
            return gp4.is_state_low(st);
            break;
        default:
            break;
        }
        return false;
    }

    /**
     * @brief Признак того, что состояние старшей половины генераторной пары совпадает с переданным.
     * @param st Переданное состояние.
     * @param idx Идентификатор LFSR генераторной пары.
     * @return Признак равенства.
     */
    bool is_state_high(STATE st, int idx) {
        switch (idx) {
        case 0:
            return gp1.is_state_high(st);
            break;
        case 1:
            return gp2.is_state_high(st);
            break;
        case 2:
            return gp3.is_state_high(st);
            break;
        case 3:
            return gp4.is_state_high(st);
            break;
        default:
            break;
        }
        return false;
    }

    /**
     * @brief Установить начальное состояние генератора.
     * @param st Переданный "сид".
     */
    void seed(STATE st) {
        // Некоторая "соль".
        std::array<u16, 4> h {1, 2, 2, 3};
        // Распределить начальное состояние по всем LFSR-генераторам.
        STATE tmp[4]  {st, st, st, st};
        for (int i=0; i<h.size(); ++i) {
            for (auto& el : tmp[i]) {
                el >>= i*4;
                el %= 16;
                h[i] ^= el;
            }
        }
        gp1.set_state(tmp[0]);
        gp2.set_state(tmp[1]);
        gp3.set_state(tmp[2]);
        gp4.set_state(tmp[3]);
        // Насытить генераторы.
        for (int i=0; i<my_lcm<4>(primes); ++i) {
            gp1.next(h[0]);
            gp2.next(h[1]);
            gp3.next(h[2]);
            gp4.next(h[3]);
            sawtooth<4>(h, primes);
        }
        // Сохранить состояния генераторов в качестве опорных (начальных).
        const std::array<STATE, 4> refs {gp1.get_state(), gp2.get_state(), gp3.get_state(), gp4.get_state()};
        /**
         * @brief Протестировать начальные состояния генераторов "пилы".
         * @return Признак успеха, целое число.
         */
        auto test251 = [&refs, this](u16 i01, u16 i02, u16 i03, u16 i04) -> int {
            Tc = {1, 1, 1, 1, 1, 1, 1, 1};   // Счетчики.
            Tref = {0, 0, 0, 0, 0, 0, 0, 0}; // Найденные периоды.
            std::array<u32, 4> Tmax; // Наибольший свободный период.
            Tmax[0] = std::pow((long)p[0], m/2) - 1;
            Tmax[1] = std::pow((long)p[1], m/2) - 1;
            Tmax[2] = std::pow((long)p[2], m/2) - 1;
            Tmax[3] = std::pow((long)p[3], m/2) - 1;
            // Установить генераторы в опорное состояние.
            gp1.set_state(refs[0]);
            gp2.set_state(refs[1]);
            gp3.set_state(refs[2]);
            gp4.set_state(refs[3]);
            std::array<u16, 4> i {i01, i02, i03, i04};
            while (true) {
                gp1.next(i[0]);
                gp2.next(i[1]);
                gp3.next(i[2]);
                gp4.next(i[3]);
                // Остаток от деления mod(p^4 - 1 , q) не равен нулю => мы проходим все индексы i in [0, q),
                // когда LFSR генератор находится в одном и том же опорном состоянии.
                // Получаем набор случайных периодов T[i] так, что их сумма неслучайна и равна q*T0, где q - период "пилы".
                // Модуляция пилообразным кодом.
                sawtooth(i, primes);
                // Но ключевой момент рандомизации периодоы:
                // мы будем проходить почти все i, кроме одного => устанавливаем ограничение на суммарный период T[j] = sum_of(All i except last one) < q*T0.
                for (int j=0; j<4; ++j)
                    Tref[2*j] = !(is_state_low(refs[j], j)) ? Tref[2*j] : (Tc[2*j] < primes_duplicates[2*j]*Tmax[j] ? Tc[2*j] : Tref[2*j]);
                for (int j=0; j<4; ++j)
                    Tref[2*j+1] = !(is_state_high(refs[j], j)) ? Tref[2*j+1] : (Tc[2*j+1] < primes_duplicates[2*j+1]*Tmax[j] ? Tc[2*j+1] : Tref[2*j+1]);
                increment(Tc);
                // Проверяем не вышли ли все счетчики за грани допустимого диапазона.
                bool is_enough = true;
                for (int j=0; j<8; ++j)
                    is_enough &= (Tc[j] >= primes_duplicates[j]*Tmax[j/2]);
                if (is_enough) {
                    break;
                }
            }
            // Проверяем НОД найденных периодов T[j].
            const auto gcd1 = std::gcd(std::gcd(Tref[0], Tref[1]), std::gcd(Tref[2], Tref[3]));
            const auto gcd2 = std::gcd(std::gcd(Tref[4], Tref[5]), std::gcd(Tref[6], Tref[7]));
            auto gcd = std::gcd(gcd1, gcd2);
            // Устанавливаем ограничение на НОД. По статистике оно зачастую выполняется. Изредка бывает тест не проходит,
            // тогда мы запускаем test251() еще раз: в этом случае с большой вероятностью единичный НОД будет достигнут.
            bool is_ok = (gcd < 2);
            for (int j=0; j<8; ++j)
                is_ok &= (Tref[j] > Tmax[j/2]);
            return is_ok ? 1 : 0;
        };
        is_finded = 0;
        for (u16 i1=1; i1<primes[0]; ++i1) {
            for (u16 i2=1; i2<primes[1]; ++i2) {
                for (u16 i3=1; i3<primes[2]; ++i3) {
                    for (u16 i4=1; i4<primes[3]; ++i4) {
                        is_finded = test251(i1, i2, i3, i4);
                        if (is_finded != 0) {
                            ii0_saw = {i1, i1, i2, i2, i3, i3, i4, i4};
                            break;
                        }
                    } // i4
                    if (is_finded != 0) {
                        break;
                    }
                } // i3
                if (is_finded != 0) {
                    break;
                }
            } // i2
            if (is_finded != 0) {
                break;
            }
        } // i1
        // Инициализируем генераторы.
        ii_saw = ii0_saw;
        Tc = {1, 1, 1, 1, 1, 1, 1, 1};
        gp1.set_state(refs[0]);
        gp2.set_state(refs[1]);
        gp3.set_state(refs[2]);
        gp4.set_state(refs[3]);
    }

    /**
     * @brief Генерирует 64-битное случайное число.
     * @return Случайное целое беззнаковое 64-битное число.
     */
    u64 next_u64() {
        u64 x = 0;
        for (int i=0; i<4; ++i) {
            gp1.next(ii_saw[0], ii_saw[1]);
            gp2.next(ii_saw[2], ii_saw[3]);
            gp3.next(ii_saw[4], ii_saw[5]);
            gp4.next(ii_saw[6], ii_saw[7]);
            sawtooth(ii_saw, primes_duplicates);
            // Сбрасываем счетчик и генератор "пилы", если период LFSR был достигнут.
            for (int j=0; j<8; ++j) {
                ii_saw[j] = (Tc[j] != Tref[j]) ? ii_saw[j] : ii0_saw[j];
                Tc[j] = (Tc[j] != Tref[j]) ? Tc[j] : 0;
            }
            increment(Tc);
            //
            STATE mSt = gp1.get_state();
            mSt ^= gp2.get_state();
            mSt ^= gp3.get_state();
            mSt ^= gp4.get_state();
            mSt %= 16;
            for (int j=0; j<4; ++j) {
                x <<= 4;
                x |= mSt[j] ^ mSt[j+4];
            }
        }
        return x;
    }
};

}
