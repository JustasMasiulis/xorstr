/*
 * Copyright 2017 - 2018 Justas Masiulis
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef JM_XORSTR_HPP
#define JM_XORSTR_HPP

#include <immintrin.h>
#include <cstdint>
#include <cstddef>
#include <utility>

#define xorstr(str)                                              \
    ::jm::make_xorstr(                                           \
        []() {                                                   \
            struct {                                             \
                const std::decay_t<decltype(*str)>* value = str; \
            } a;                                                 \
            return a;                                            \
        }(),                                                     \
        std::make_index_sequence<sizeof(str)>{},                 \
        std::make_index_sequence<::jm::detail::_buffer_size<sizeof(str)>()>{})
#define xorstr_(str) xorstr(str).crypt_get()

#ifdef _MSC_VER
#define XORSTR_FORCEINLINE __forceinline
#else
#define XORSTR_FORCEINLINE __attribute__((always_inline))
#endif

// you can define this macro to get possibly faster code on gcc/clang
// at the expense of constants being put into data section.
#if !defined(XORSTR_ALLOW_DATA)
// MSVC - no volatile
// GCC and clang - volatile everywhere
#if defined(__clang__) || defined(__GNUC__)
#define XORSTR_VOLATILE volatile
#endif

#endif
#ifndef XORSTR_VOLATILE
#define XORSTR_VOLATILE
#endif

namespace jm {

    namespace detail {

        template<std::size_t S>
        struct unsigned_;

        template<>
        struct unsigned_<1> {
            using type = std::uint8_t;
        };
        template<>
        struct unsigned_<2> {
            using type = std::uint16_t;
        };
        template<>
        struct unsigned_<4> {
            using type = std::uint32_t;
        };

        template<auto C, auto...>
        struct pack_value_type {
            using type = decltype(C);
        };

        template<auto... Cs>
        struct tstring_ {
            using value_type                  = typename pack_value_type<Cs...>::type;
            constexpr static std::size_t size = sizeof...(Cs);
            constexpr static value_type  str[size] = { Cs... };
        };

        template<std::uint32_t Seed>
        constexpr std::uint32_t key4() noexcept
        {
            std::uint32_t value = Seed;
            for(char c : __TIME__)
                value = static_cast<std::uint32_t>((value ^ c) * 16777619ull);
            return value;
        }

        template<std::size_t S>
        constexpr std::uint64_t key8()
        {
            constexpr auto first_part  = key4<2166136261 + S>();
            constexpr auto second_part = key4<first_part>();
            return (static_cast<std::uint64_t>(first_part) << 32) | second_part;
        }

        template<std::size_t Size>
        constexpr std::size_t _buffer_size()
        {
            return ((Size / 16) + (Size % 16 != 0)) * 2;
        }

        template<class T>
        constexpr std::size_t buffer_size()
        {
            return _buffer_size<sizeof(T::str)>();
        }

        template<std::size_t Size>
        constexpr std::size_t _buffer_align()
        {
#ifndef JM_XORSTR_DISABLE_AVX_INTRINSICS
            return ((Size > 16) ? 32 : 16);
#else
            return 16;
#endif
        }

        template<class T>
        constexpr std::size_t buffer_align()
        {
            return _buffer_align<sizeof(T::str)>();
        }

        template<std::uint64_t... Keys>
        class key_list {
            template<std::size_t Index, std::uint64_t Key>
            XORSTR_FORCEINLINE static void
            _assign_single(XORSTR_VOLATILE std::uint64_t* buffer)
            {
                buffer[Index] = Key;
            }

        public:
            template<std::size_t... Indices>
            XORSTR_FORCEINLINE static void assign(XORSTR_VOLATILE std::uint64_t* buffer,
                                                  std::index_sequence<Indices...>)
            {
                (_assign_single<Indices, Keys>(buffer), ...);
            }
        };

        template<class T, class K>
        struct string_storage;

        // clang and gcc try really hard to place the constants in data
        // sections. to counter that there was a need to create an intermediate
        // constexpr string and then copy it into a non constexpr container with
        // volatile storage so that the constants would be placed directly into
        // code.
        template<class T, std::uint64_t... Keys>
        struct string_storage<T, key_list<Keys...>> {
            std::uint64_t storage[buffer_size<T>()] = { Keys... };

            XORSTR_FORCEINLINE constexpr string_storage() noexcept : storage{ 0 }
            {
                using cast_type =
                    typename unsigned_<sizeof(typename T::value_type)>::type;
                constexpr auto value_size = sizeof(typename T::value_type);
                // puts the string into 64 bit integer blocks in a constexpr
                // fashion
                for(std::size_t i = 0; i < T::size; ++i)
                    storage[i / (8 / value_size)] ^=
                        (std::uint64_t{ static_cast<cast_type>(T::str[i]) }
                         << ((i % (8 / value_size)) * 8 * value_size));
            }
        };

    } // namespace detail

    template<class T, class K>
    struct xor_string {
        constexpr static std::size_t storage_size  = detail::buffer_size<T>();
        constexpr static std::size_t storage_align = detail::buffer_align<T>();

        alignas(storage_align) XORSTR_VOLATILE std::uint64_t _storage[storage_size];

        template<std::size_t N>
        XORSTR_FORCEINLINE void _crypt(XORSTR_VOLATILE std::uint64_t* keys) noexcept
        {
            if constexpr(detail::buffer_size<T>() > N) {
#ifndef JM_XORSTR_DISABLE_AVX_INTRINSICS
                if constexpr((detail::buffer_size<T>() - N) >= 4) {
                    _mm256_store_si256(
                        (__m256i*)(&_storage[N]),
                        _mm256_xor_si256(
                            _mm256_load_si256((const __m256i*)(&_storage[N])),
                            _mm256_load_si256((const __m256i*)(keys + N))));
                    _crypt<N + 4>(keys);
                }
                else
#endif
                {
                    _mm_store_si128(
                        (__m128i*)(&_storage[N]),
                        _mm_xor_si128(_mm_load_si128((const __m128i*)(&_storage[N])),
                                      _mm_load_si128((const __m128i*)(keys + N))));
                    _crypt<N + 2>(keys);
                }
            }
        }

        template<std::size_t N>
        XORSTR_FORCEINLINE constexpr void _copy_single() noexcept
        {
            // forces compile time evaluation of storage for access
            constexpr std::uint64_t val = detail::string_storage<T, K>{}.storage[N];
            _storage[N]                 = val;
        }

        // loop generates vectorized code which places constants in data dir
        template<std::size_t... Indices>
        XORSTR_FORCEINLINE void _copy(std::index_sequence<Indices...>) noexcept
        {
            (_copy_single<Indices>(), ...);
        }

    public:
        using value_type    = typename T::value_type;
        using size_type     = std::size_t;
        using pointer       = value_type*;
        using const_pointer = const pointer;

        XORSTR_FORCEINLINE xor_string() noexcept
        {
            _copy(std::make_index_sequence<storage_size>{});
        }

        XORSTR_FORCEINLINE constexpr size_type size() const noexcept
        {
            return T::size - 1;
        }

        XORSTR_FORCEINLINE void crypt() noexcept
        {
            alignas(storage_align) XORSTR_VOLATILE std::uint64_t keys[storage_size];
            K::assign(keys, std::make_index_sequence<detail::buffer_size<T>()>{});
            _crypt<0>(keys);
        }

        XORSTR_FORCEINLINE const_pointer get() const noexcept
        {
            // C casts are used because buffer may or may not be volatile
            return (const_pointer)(_storage);
        }

        XORSTR_FORCEINLINE const_pointer crypt_get() noexcept
        {
            crypt();
            // C casts are used because buffer may or may not be volatile
            return (const_pointer)(_storage);
        }
    };

    template<class Tstr, std::size_t... StringIndices, std::size_t... KeyIndices>
    XORSTR_FORCEINLINE constexpr xor_string<
        detail::tstring_<Tstr().value[StringIndices]...>,
        detail::key_list<detail::key8<KeyIndices>()...>>
    make_xorstr(Tstr,
                std::index_sequence<StringIndices...>,
                std::index_sequence<KeyIndices...>) noexcept
    {
        return {};
    }

} // namespace jm

#endif // include guard

