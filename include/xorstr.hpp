#pragma once
#include <immintrin.h>
#include <cstdint>
#include <type_traits>

#define xorstr(str) ::jm::xor_string<XORSTR_STR(str)>()

#ifdef _MSC_VER
#define XORSTR_FORCEINLINE __forceinline
#else
#define XORSTR_FORCEINLINE __attribute__((always_inline))
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

// these compile time strings were required for an earlier version.
// might not be necessary for current version
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

        // clang and gcc try really hard to place the constants in data
        // sections. to counter that there was a need to create an intermediate
        // constexpr string and then copy it into a non constexpr container with
        // volatile storage so that the constants would be placed directly into
        // code.
        template<class T>
        struct string_storage {
            std::uint64_t storage[buffer_size<T>()];

            template<std::size_t N = 0>
            XORSTR_FORCEINLINE constexpr void _xor()
            {
                if constexpr (N != detail::buffer_size<T>()) {
                    constexpr auto key = key8<N>();
                    storage[N] ^= key;
                    _xor<N + 1>();
                }
            }

            XORSTR_FORCEINLINE constexpr string_storage() : storage{ 0 }
            {
                // puts the string into 64 bit integer blocks in a constexpr
                // fashion
                for (std::size_t i = 0; i < T::size; ++i)
                    storage[i / (8 / sizeof(typename T::value_type))] |=
                        (std::uint64_t(T::str[i])
                         << ((i % (8 / sizeof(typename T::value_type))) * 8 *
                             sizeof(typename T::value_type)));
                // applies the xor encryption
                _xor<0>();
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
                    // assignments are separate on purpose. Do not replace with
                    // = { ... }
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
            // forces compile time evaluation of storage for access
            return std::integral_constant<
                std::uint64_t,
                detail::string_storage<T>{}.storage[N]>::value;
        }

        // loop generates vectorized code which places constants in data dir
        template<std::size_t N>
        void _copy() noexcept
        {
            if constexpr (detail::buffer_size<T>() > N) {
                _storage[N]     = _at<N>();
                _storage[N + 1] = _at<N + 1>();
                _copy<N + 2>();
            }
        }

    public:
        XORSTR_FORCEINLINE xor_string() noexcept { _copy<0>(); }

        constexpr std::size_t size() const noexcept { return T::size - 1; }

        XORSTR_FORCEINLINE void crypt() noexcept { _crypt<0>(); }

        XORSTR_FORCEINLINE const typename T::value_type* get() const noexcept
        {
            return _storage;
        }

        XORSTR_FORCEINLINE const typename T::value_type* crypt_get() noexcept
        {
            crypt();
            return (const typename T::value_type*)(_storage);
        }
    };

} // namespace jm

#ifdef _MSC_VER
#pragma warning(pop)
#endif
