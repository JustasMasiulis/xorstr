#pragma once
#include <immintrin.h>
#include <cstdint>
#include <type_traits>

#define xorstr(str) ::jm::xor_string<XORSTR_STR(str)>()

#ifndef XORSTR_FORCEINLINE
#ifdef _MSC_VER
#define XORSTR_FORCEINLINE __forceinline
#else
#define XORSTR_FORCEINLINE __attribute__((always_inline))
#endif
#endif

#if defined(__clang__)
#define XORSTR_CLANG_VOLATILE volatile
#define XORSTR_VOLATILE volatile
#elif defined(__GNUC__)
#define XORSTR_CLANG_VOLATILE
#define XORSTR_VOLATILE volatile
#else
#define XORSTR_CLANG_VOLATILE
#define XORSTR_VOLATILE
#endif

#define XORSTR_STRING_EXPAND_10(n, x)                         \
    jm::detail::c_at<n##0>(x), jm::detail::c_at<n##1>(x),     \
        jm::detail::c_at<n##2>(x), jm::detail::c_at<n##3>(x), \
        jm::detail::c_at<n##4>(x), jm::detail::c_at<n##5>(x), \
        jm::detail::c_at<n##6>(x), jm::detail::c_at<n##7>(x), \
        jm::detail::c_at<n##8>(x), jm::detail::c_at<n##9>(x)

#define XORSTR_STRING_EXPAND_100(x)                                   \
    XORSTR_STRING_EXPAND_10(, x), XORSTR_STRING_EXPAND_10(1, x),      \
        XORSTR_STRING_EXPAND_10(2, x), XORSTR_STRING_EXPAND_10(3, x), \
        XORSTR_STRING_EXPAND_10(4, x), XORSTR_STRING_EXPAND_10(5, x), \
        XORSTR_STRING_EXPAND_10(6, x), XORSTR_STRING_EXPAND_10(7, x), \
        XORSTR_STRING_EXPAND_10(8, x), XORSTR_STRING_EXPAND_10(9, x)

#define XORSTR_STR(s)                                     \
    ::jm::detail::string_builder<                         \
        std::decay_t<decltype(*s)>,                       \
        jm::detail::tstring_<std::decay_t<decltype(*s)>>, \
        XORSTR_STRING_EXPAND_100(s)>::type

// disable constant overflow warnings
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4309)
#pragma warning(disable : 4307)
#endif

namespace jm {

    namespace detail {

        template<std::size_t I, std::size_t M, class T>
        constexpr T c_at(const T (&str)[M]) noexcept
        {
            static_assert(M <= 99, "string too large.");
            return (I < M) ? str[I] : 0;
        }

        template<class T, class B, T...>
        struct string_builder;

        template<class T, class B>
        struct string_builder<T, B> {
            using type = B;
        };

        template<class T, template<class, T...> class S, T... Hs, T C, T... Cs>
        struct string_builder<T, S<T, Hs...>, C, Cs...>
            : std::conditional<C == T(0),
                               string_builder<T, S<T, Hs...>>,
                               string_builder<T, S<T, Hs..., C>, Cs...>>::type {
        };

        template<class T, T... Cs>
        struct tstring_ {
            using value_type                           = T;
            constexpr static std::size_t size          = sizeof...(Cs);
            constexpr static value_type  str[size + 1] = { Cs..., '\0' };

            constexpr static std::size_t size_in_bytes() noexcept
            {
                return (size + 1) * sizeof(value_type);
            }
        };

        constexpr std::uint64_t rng_seed() noexcept
        {
            std::uint64_t shifted = 0ull;
            for (int i = 0; i < 8; ++i) {
                shifted <<= 8;
                shifted |= __TIME__[i];
            }
            return shifted;
        }

        template<std::uint64_t S>
        constexpr std::uint32_t pcg32() noexcept
        {
            constexpr auto seed       = rng_seed();
            constexpr auto oldstate   = S * 6364136223846793005ull + (seed | 1);
            std::uint32_t  xorshifted = static_cast<std::uint32_t>(
                ((oldstate >> 18u) ^ oldstate) >> 27u);
            std::uint32_t rot = oldstate >> 59u;
            return (xorshifted >> rot) | (xorshifted << ((1u + ~rot) & 31));
        }

        template<std::size_t S>
        constexpr std::uint64_t key8()
        {
            return (static_cast<std::uint64_t>(detail::pcg32<S>()) << 32) |
                   detail::pcg32<S + 85>();
        }

        template<class T>
        constexpr std::size_t buffer_size()
        {
            constexpr auto x = T::size_in_bytes() / 16;
            return x * 2 + ((T::size_in_bytes() - x * 16) % 16 != 0) * 2;
        }

        template<class T>
        struct string_storage {
            std::uint64_t storage[buffer_size<T>()];

            template<std::size_t N = 0>
            XORSTR_FORCEINLINE constexpr void _xorcpy()
            {
                if constexpr (N != detail::buffer_size<T>()) {
                    constexpr auto key = key8<N>();
                    storage[N] ^= key;
                    _xorcpy<N + 1>();
                }
            }

            XORSTR_FORCEINLINE constexpr string_storage() : storage{ 0 }
            {
                for (std::size_t i = 0; i < T::size; ++i)
                    storage[i / 8] |=
                        (std::uint64_t(T::str[i]) << ((i % 8) * 8));

                _xorcpy<0>();
            }
        };

    } // namespace detail

    template<class T>
    struct xor_string {
        XORSTR_VOLATILE std::uint64_t _storage[detail::buffer_size<T>()];

        template<std::size_t N>
        XORSTR_FORCEINLINE void _crypt() noexcept
        {
            if constexpr (detail::buffer_size<T>() > N) {
                if constexpr ((detail::buffer_size<T>() - N) >= 4) {
                    XORSTR_CLANG_VOLATILE std::uint64_t keys[4];
                    keys[0] = detail::key8<N + 0>();
                    keys[1] = detail::key8<N + 1>();
                    keys[2] = detail::key8<N + 2>();
                    keys[3] = detail::key8<N + 3>();

                    *(__m256i*)(&_storage[N]) = _mm256_xor_si256(
                        *(__m256i*)(&_storage[N]), *(const __m256i*)(&keys));
                    _crypt<N + 4>();
                }
                else {
                    XORSTR_VOLATILE std::uint64_t keys[2];
                    keys[0] = detail::key8<N + 0>();
                    keys[1] = detail::key8<N + 1>();

                    *(__m128i*)(&_storage[N]) = _mm_xor_si128(
                        *(__m128i*)(&_storage[N]), *(const __m128i*)(&keys));
                    _crypt<N + 2>();
                }
            }
        }

        template<std::size_t N>
        XORSTR_FORCEINLINE constexpr static std::uint64_t _at()
        {
            return std::integral_constant<
                std::uint64_t,
                detail::string_storage<T>{}.storage[N]>::value;
        }

    public:
        XORSTR_FORCEINLINE xor_string() noexcept
        {
            if constexpr (detail::buffer_size<T>() > 0) {
                _storage[0] = _at<0>();
                _storage[1] = _at<1>();
            }
            if constexpr (detail::buffer_size<T>() > 2) {
                _storage[2] = _at<2>();
                _storage[3] = _at<3>();
            }
            if constexpr (detail::buffer_size<T>() > 4) {
                _storage[4] = _at<4>();
                _storage[5] = _at<5>();
            }
            if constexpr (detail::buffer_size<T>() > 6) {
                _storage[6] = _at<6>();
                _storage[7] = _at<7>();
            }
            if constexpr (detail::buffer_size<T>() > 8) {
                _storage[8] = _at<8>();
                _storage[9] = _at<9>();
            }
            if constexpr (detail::buffer_size<T>() > 10) {
                _storage[10] = _at<10>();
                _storage[11] = _at<11>();
            }
            if constexpr (detail::buffer_size<T>() > 12) {
                _storage[12] = _at<12>();
                _storage[13] = _at<13>();
            }
            if constexpr (detail::buffer_size<T>() > 14) {
                _storage[14] = _at<14>();
                _storage[15] = _at<15>();
            }
        }

        constexpr std::size_t size() const noexcept { return T::size - 1; }

        XORSTR_FORCEINLINE void crypt() noexcept { _crypt<0>(); }

        XORSTR_FORCEINLINE const T* get() const noexcept { return _storage; }

        XORSTR_FORCEINLINE const char* crypt_get() noexcept
        {
            crypt();
            return (const char*)(_storage);
        }
    };

} // namespace jm

#ifdef _MSC_VER
#pragma warning(pop)
#endif
