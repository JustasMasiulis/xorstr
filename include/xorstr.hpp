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

JM_FORCEINLINE constexpr std::uint64_t rng_seed() noexcept
{
    std::uint64_t shifted = 0ull;
    for (int i = 0; i < 8; ++i) {
        shifted <<= 8;
        shifted |= __TIME__[i];
    }
    return shifted;
}

template<std::size_t S>
JM_FORCEINLINE constexpr std::uint32_t pcg32() noexcept
{
    constexpr auto seed       = rng_seed();
    std::uint64_t  oldstate   = S * 6364136223846793005ull + (seed | 1);
    std::uint32_t  xorshifted = ((oldstate >> 18u) ^ oldstate) >> 27u;
    std::uint32_t  rot        = oldstate >> 59u;
    return (xorshifted >> rot) | (xorshifted << ((-rot) & 31));
}

template<class T, std::size_t N>
struct xorstr {
    static_assert(N != 0 && N < 32, "");
    alignas(alignof(void*)) mutable T _storage[N];

    template<std::size_t S>
    constexpr static std::uint8_t key()
    {
        return static_cast<std::uint8_t>(pcg32<S>());
    }
    template<std::size_t S>
    constexpr static std::uint16_t key2()
    {
        return static_cast<std::uint16_t>(pcg32<S>());
    }
    template<std::size_t S>
    constexpr static std::uint32_t key4()
    {
        return static_cast<std::uint32_t>(pcg32<S>());
    }
    template<std::size_t S>
    constexpr static std::uint64_t key8()
    {
        return static_cast<std::uint64_t>(pcg32<S>()) * pcg32<S + N>();
    }

    template<std::size_t N2>
    JM_FORCEINLINE void _xorcpy(char* __restrict store,
                               const char* __restrict str) const noexcept
    {
        if constexpr (N2 / 8) {
            *reinterpret_cast<std::uint64_t*>(store) =
                *reinterpret_cast<const std::uint64_t*>(str) ^ key8<N2>();
            _xorcpy<N2 - 8>(store + 8, str + 8);
        }
        else if constexpr (N2 / 4) {
            *reinterpret_cast<std::uint32_t*>(store) =
                *reinterpret_cast<const std::uint32_t*>(str) ^ key4<N2>();
            _xorcpy<N2 - 4>(store + 4, str + 4);
        }
        else if constexpr (N2 / 2) {
            *reinterpret_cast<std::uint16_t*>(store) =
                *reinterpret_cast<const std::uint16_t*>(str) ^ key2<N2>();
            _xorcpy<N2 - 2>(store + 2, str + 2);
        }
        else if constexpr (N2) {
            *(store) = *(str) ^ key<N2>();
            _xorcpy<N2 - 1>(store + 1, str + 1);
        }
    }
    JM_FORCEINLINE constexpr xorstr(const T (&str)[N]) noexcept : _storage{ 0 }
    {
        _xorcpy<N>(_storage, str);
    }

    template<std::size_t N2>
    JM_FORCEINLINE void _crypt(volatile char* __restrict str) const noexcept
    {
        if constexpr (N2 / 8) {
            *reinterpret_cast<volatile std::uint64_t*>(str) ^= key8<N2>();
            _crypt<N2 - 8>(str + 8);
        }
        else if constexpr (N2 / 4) {
            *reinterpret_cast<volatile std::uint32_t*>(str) ^= key4<N2>();
            _crypt<N2 - 4>(str + 4);
        }
        else if constexpr (N2 / 2) {
            *reinterpret_cast<volatile std::uint16_t*>(str) ^= key2<N2>();
            _crypt<N2 - 2>(str + 2);
        }
        else if constexpr (N2) {
            *(str) ^= key<N2>();
            _crypt<N2 - 1>(str + 1);
        }
    }

    constexpr std::size_t size() { return N - 1; }

    JM_FORCEINLINE void crypt() const noexcept { _crypt<N>(_storage); }

    constexpr const T* get() const noexcept { return _storage; }

    JM_FORCEINLINE const T* crypt_get() const noexcept
    {
        crypt();
        return const_cast<const char*>(_storage);
    }
};

template<class T, std::size_t N>
JM_FORCEINLINE constexpr auto make_xorstr(const T (&str)[N])
{
    return xorstr<T, N>(str);
}
