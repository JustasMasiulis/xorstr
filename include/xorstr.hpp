#pragma once
#include <cstdint>
#include <type_traits>
#ifndef JM_FORCEINLINE
#ifdef _MSC_VER
#define JM_FORCEINLINE __forceinline
#else
#define JM_FORCEINLINE __attribute__((always_inline))
#endif // _MSC_VER
#endif // !JM_FORCEINLINE

#include <immintrin.h>


#pragma once
#include <cstddef>

#define CRBN_STRING_EXPAND_10(n, x)                                    \
    jmd_::c_at<n##0>(x), jmd_::c_at<n##1>(x), jmd_::c_at<n##2>(x),     \
        jmd_::c_at<n##3>(x), jmd_::c_at<n##4>(x), jmd_::c_at<n##5>(x), \
        jmd_::c_at<n##6>(x), jmd_::c_at<n##7>(x), jmd_::c_at<n##8>(x), \
        jmd_::c_at<n##9>(x)

#define CRBN_STRING_EXPAND_50(x)                                  \
    CRBN_STRING_EXPAND_10(, x), CRBN_STRING_EXPAND_10(1, x),      \
        CRBN_STRING_EXPAND_10(2, x), CRBN_STRING_EXPAND_10(3, x), \
        CRBN_STRING_EXPAND_10(4, x)

#define CRBN_STR(s)                                      \
    ::jm::detail::string_builder<jm::detail::tstring_<>, \
                                 CRBN_STRING_EXPAND_50(s)>::type

namespace jmd_ {

    template<std::size_t Idx, std::size_t M>
    constexpr char c_at(const char (&str)[M]) noexcept
    {
        static_assert(M <= 50, "serializable member name too large.");
        return (Idx < M) ? str[Idx] : 0;
    }

} // namespace jmd_

namespace jm {

    namespace detail {

        template<typename, char...>
        struct string_builder;

        template<typename T>
        struct string_builder<T> {
            using type = T;
        };

        template<template<char...> class S, char... Hs, char C, char... Cs>
        struct string_builder<S<Hs...>, C, Cs...>
            : std::conditional<C == '\0',
                               string_builder<S<Hs...>>,
                               string_builder<S<Hs..., C>, Cs...>>::type {};

        template<char... Cs>
        struct tstring_ {
            constexpr static std::size_t size          = sizeof...(Cs);
            constexpr static char        str[size + 1] = { Cs..., '\0' };
        };


        JM_FORCEINLINE constexpr std::uint64_t rng_seed() noexcept
        {
            std::uint64_t shifted = 0ull;
            for (int i = 0; i < 8; ++i) {
                shifted <<= 8;
                shifted |= __TIME__[i];
            }
            return shifted;
        }

#pragma warning(push)
#pragma warning(disable : 4307)
        template<std::uint64_t S>
        JM_FORCEINLINE constexpr std::uint32_t pcg32() noexcept
        {
            constexpr auto seed       = rng_seed();
            constexpr auto oldstate   = S * 6364136223846793005ull + (seed | 1);
            std::uint32_t  xorshifted = static_cast<std::uint32_t>(
                ((oldstate >> 18u) ^ oldstate) >> 27u);
            std::uint32_t rot = oldstate >> 59u;
            return (xorshifted >> rot) | (xorshifted << ((1u + ~rot) & 31));
        }
#pragma warning(pop)

        template<class T>
        struct string_storage {
            using storage_t = std::uint64_t[T::size * sizeof(T) / 8 + 1];
            mutable storage_t storage;

            constexpr string_storage() : storage{ 0 }
            {
                for (std::size_t i = 0; i < T::size; ++i)
                    storage[i / 8] |=
                        (std::uint64_t(T::str[i]) << ((i % 8) * 8));
            }
        };

    } // namespace detail

    template<class T>
    struct xorstr {
        static_assert(sizeof(T) == 1,
                      "support for wide strings not implemented");
        static_assert(
            T::size <= 32,
            "support for strings longer than 32 characters not implemented");
        mutable std::uint64_t _storage[4];

        template<std::size_t S>
        constexpr static std::uint64_t key8()
        {
            return (static_cast<std::uint64_t>(detail::pcg32<S>()) << 32) |
                   detail::pcg32<S + 85>();
        }

        template<std::size_t N>
        JM_FORCEINLINE constexpr void
        _xorcpy(const detail::string_storage<T>& store)
        {
            if constexpr (N != 4) {
                constexpr auto key = key8<N>();
                _storage[N]        = store.storage[N] ^ key;
                _xorcpy<N + 1>(store);
            }
        }
        JM_FORCEINLINE constexpr xorstr() noexcept : _storage{ 0 }
        {
            constexpr detail::string_storage<T> str;
            _xorcpy<0>(str);
        }

        template<std::size_t N>
        JM_FORCEINLINE void _crypt() noexcept
        {
            constexpr std::uint64_t keys[] = {
                key8<0>(), key8<1>(), key8<2>(), key8<3>()
            };
            *reinterpret_cast<__m256i*>(&_storage) =
                _mm256_xor_si256(*reinterpret_cast<__m256i*>(&_storage),
                                 *reinterpret_cast<const __m256i*>(&keys));
        }

        constexpr std::size_t size() const noexcept { return N - 1; }

        JM_FORCEINLINE void crypt() noexcept { _crypt<0>(); }

        const T* get() const noexcept { return _storage; }

        JM_FORCEINLINE const char* crypt_get() noexcept
        {
            crypt();
            return reinterpret_cast<const char*>(_storage);
        }
    };

#define xorstr(str)                         \
    []() {                                  \
        using STR_T = CRBN_STR(str);        \
        constexpr ::jm::xorstr<STR_T> xstr; \
        return xstr;                        \
    }()

} // namespace jm
