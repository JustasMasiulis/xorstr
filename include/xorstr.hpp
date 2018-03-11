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

namespace jm {

    namespace detail {

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
            constexpr auto seed     = rng_seed();
            std::uint64_t  oldstate = S * 6364136223846793005ull + (seed | 1);
            std::uint32_t  xorshifted =
                static_cast<std::uint32_t>(((oldstate >> 18u) ^ oldstate) >> 27u);
            std::uint32_t rot = oldstate >> 59u;
            return (xorshifted >> rot) | (xorshifted << ((1u + ~rot) & 31));
        }
#pragma warning(pop)

    } // namespace detail

    template<class T, std::size_t N>
    struct xorstr {
        static_assert(sizeof(T) == 1, "support for wide strings not implemented");
        alignas(8) mutable T _storage[N];

        template<std::size_t S>
        constexpr static std::uint8_t key()
        {
            return static_cast<std::uint8_t>(detail::pcg32<S>());
        }
        template<std::size_t S>
        constexpr static std::uint16_t key2()
        {
            return static_cast<std::uint16_t>(detail::pcg32<S>());
        }
        template<std::size_t S>
        constexpr static std::uint32_t key4()
        {
            return static_cast<std::uint32_t>(detail::pcg32<S>());
        }
        template<std::size_t S>
        constexpr static std::uint64_t key8()
        {
            return (static_cast<std::uint64_t>(detail::pcg32<S>()) << 32) |
                   detail::pcg32<S + N>();
        }

        template<std::size_t N2>
        constexpr static JM_FORCEINLINE void _xorcpy(char* __restrict store,
                                                     const char* __restrict str)
        {
            if constexpr (N2 * sizeof(T) / 8 > 0) {
                constexpr auto k = key8<N2>();
                store[7] = str[7] ^ static_cast<T>(k >> (64 - sizeof(T) * 8));
                store[6] = str[6] ^ static_cast<T>(k >> (56 - sizeof(T) * 8));
                store[5] = str[5] ^ static_cast<T>(k >> (48 - sizeof(T) * 8));
                store[4] = str[4] ^ static_cast<T>(k >> (40 - sizeof(T) * 8));
                store[3] = str[3] ^ static_cast<T>(k >> (32 - sizeof(T) * 8));
                store[2] = str[2] ^ static_cast<T>(k >> (24 - sizeof(T) * 8));
                store[1] = str[1] ^ static_cast<T>(k >> (16 - sizeof(T) * 8));
                store[0] = str[0] ^ static_cast<T>(k >> (8 - sizeof(T) * 8));
                _xorcpy<N2 - 8>(store + 8, str + 8);
            }
            else if constexpr (N2 / 4 > 0) {
                constexpr auto k = key4<N2>();

                store[3] = str[3] ^ static_cast<T>(k >> (32 - sizeof(T) * 8));
                store[2] = str[2] ^ static_cast<T>(k >> (24 - sizeof(T) * 8));
                store[1] = str[1] ^ static_cast<T>(k >> (16 - sizeof(T) * 8));
                store[0] = str[0] ^ static_cast<T>(k >> (8 - sizeof(T) * 8));

                _xorcpy<N2 - 4>(store + 4, str + 4);
            }
            else if constexpr (N2 / 2 > 0) {
                constexpr auto k = key2<N2>();

                store[1] = str[1] ^ static_cast<T>(k >> (16 - sizeof(T) * 8));
                store[0] = str[0] ^ static_cast<T>(k >> (8 - sizeof(T) * 8));
                _xorcpy<N2 - 2>(store + 2, str + 2);
            }
            else if constexpr (N2 > 0) {
                store[0] = str[0] ^ key<N2>();
                _xorcpy<N2 - 1>(store + 1, str + 1);
            }
        }
        JM_FORCEINLINE constexpr xorstr(const T* __restrict str) noexcept
            : _storage{ 0 }
        {
            _xorcpy<N>(_storage, str);
        }

        template<std::size_t N2>
        JM_FORCEINLINE static void _crypt(char* __restrict str) noexcept
        {
            if constexpr (N2 / 8 > 0) {
                *reinterpret_cast<volatile std::uint64_t*>(str) ^= key8<N2>();
                _crypt<N2 - 8>(str + 8);
            }
            else if constexpr (N2 / 4 > 0) {
                *reinterpret_cast<volatile std::uint32_t*>(str) ^= key4<N2>();
                _crypt<N2 - 4>(str + 4);
            }
            else if constexpr (N2 / 2 > 0) {
                *reinterpret_cast<volatile std::uint16_t*>(str) ^= key2<N2>();
                _crypt<N2 - 2>(str + 2);
            }
            else if constexpr (N2 > 0) {
                *(str) ^= key<N2>();
                _crypt<N2 - 1>(str + 1);
            }
        }

        constexpr std::size_t size() const noexcept { return N - 1; }

        JM_FORCEINLINE void crypt() const noexcept { _crypt<N>(_storage); }

        const T* get() const noexcept { return _storage; }

        JM_FORCEINLINE const T* crypt_get() const noexcept
        {
            crypt();
            return const_cast<const char*>(_storage);
        }
    };

#define xorstr(str)                                                           \
    []() {                                                                    \
        using XOR_T = std::decay_t<decltype(*str)>;                           \
        constexpr ::jm::xorstr<XOR_T, sizeof(str) / sizeof(XOR_T)> xstr(str); \
        return xstr;                                                          \
    }()

} // namespace jm
