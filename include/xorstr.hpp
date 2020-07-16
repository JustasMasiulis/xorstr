/*
 * Copyright 2017 - 2020 Justas Masiulis
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

#define xorstr(str)                                             \
    ::jm::make_xorstr(                                          \
        []() { return str; },                                   \
        std::make_index_sequence<sizeof(str) / sizeof(*str)>{}, \
        std::make_index_sequence<::jm::detail::_buffer_size<sizeof(str)>()>{})
#define xorstr_(str) xorstr(str).crypt_get()

#ifdef _MSC_VER
#define XORSTR_FORCEINLINE __forceinline
#else
#define XORSTR_FORCEINLINE __attribute__((always_inline)) inline
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

        template<std::size_t Size>
        XORSTR_FORCEINLINE constexpr std::size_t _buffer_size()
        {
            return ((Size / 16) + (Size % 16 != 0)) * 2;
        }

        template<auto... Cs>
        struct tstring_ {
            using value_type                  = typename pack_value_type<Cs...>::type;
            constexpr static std::size_t size = sizeof...(Cs);
            constexpr static value_type  str[size] = { Cs... };

            constexpr static std::size_t buffer_size = _buffer_size<sizeof(str)>();
            constexpr static std::size_t buffer_align =
#ifndef JM_XORSTR_DISABLE_AVX_INTRINSICS
                ((sizeof(str) > 16) ? 32 : 16);
#else
                16;
#endif
        };

        template<std::size_t I, std::uint64_t K>
        struct _ki {
            constexpr static std::size_t   idx = I;
            constexpr static std::uint64_t key = K;
        };

        template<std::uint32_t Seed>
        XORSTR_FORCEINLINE constexpr std::uint32_t key4() noexcept
        {
            std::uint32_t value = Seed;
            for(char c : __TIME__)
                value = static_cast<std::uint32_t>((value ^ c) * 16777619ull);
            return value;
        }

        template<std::size_t S>
        XORSTR_FORCEINLINE constexpr std::uint64_t key8()
        {
            constexpr auto first_part  = key4<2166136261 + S>();
            constexpr auto second_part = key4<first_part>();
            return (static_cast<std::uint64_t>(first_part) << 32) | second_part;
        }

        // loads up to 8 characters of string into uint64 and xors it with the key
        template<class T>
        XORSTR_FORCEINLINE constexpr std::uint64_t
        load_xored_str8(std::uint64_t key, std::size_t idx) noexcept
        {
            using cast_type = typename unsigned_<sizeof(typename T::value_type)>::type;
            constexpr auto value_size = sizeof(typename T::value_type);
            constexpr auto idx_offset = 8 / value_size;

            std::uint64_t value = key;
            for(std::size_t i = 0; i < idx_offset && i + idx * idx_offset < T::size; ++i)
                value ^=
                    (std::uint64_t{ static_cast<cast_type>(T::str[i + idx * idx_offset]) }
                     << ((i % idx_offset) * 8 * value_size));

            return value;
        }

        // forces compiler to use registers instead of stuffing constants in rdata
        XORSTR_FORCEINLINE std::uint64_t load_from_reg(std::uint64_t value) noexcept
        {
#if defined(__clang__) || defined(__GNUC__)
            asm("" : "=r"(value) : "0"(value) :);
#endif
            return value;
        }

        XORSTR_FORCEINLINE void xor128(std::uint64_t*       value,
                                       const std::uint64_t* key) noexcept
        {
            _mm_store_si128(
                reinterpret_cast<__m128i*>(value),
                _mm_xor_si128(_mm_load_si128(reinterpret_cast<const __m128i*>(value)),
                              _mm_load_si128(reinterpret_cast<const __m128i*>(key))));
        }

        XORSTR_FORCEINLINE void xor256(std::uint64_t*       value,
                                       const std::uint64_t* key) noexcept
        {
            _mm256_store_si256(
                reinterpret_cast<__m256i*>(value),
                _mm256_xor_si256(
                    _mm256_load_si256(reinterpret_cast<const __m256i*>(value)),
                    _mm256_load_si256(reinterpret_cast<const __m256i*>(key))));
        }

        template<std::uint64_t V>
        struct uint64_v {
            constexpr static std::uint64_t value = V;
        };

    } // namespace detail

    template<class T, class... Keys>
    class xor_string {
        alignas(T::buffer_align) std::uint64_t _storage[T::buffer_size];

        template<std::size_t... Idxs>
        XORSTR_FORCEINLINE void _crypt_256(const std::uint64_t* keys,
                                           std::index_sequence<Idxs...>) noexcept
        {
            (detail::xor256(_storage + Idxs * 4, keys + Idxs * 4), ...);
        }

        template<std::size_t... Idxs>
        XORSTR_FORCEINLINE void _crypt_128(const std::uint64_t* keys,
                                           std::index_sequence<Idxs...>) noexcept
        {
            (detail::xor128(_storage + Idxs * 2, keys + Idxs * 2), ...);
        }

    public:
        using value_type    = typename T::value_type;
        using size_type     = std::size_t;
        using pointer       = value_type*;
        using const_pointer = const value_type*;

        XORSTR_FORCEINLINE xor_string() noexcept
            : _storage{ detail::load_from_reg(detail::uint64_v<detail::load_xored_str8<T>(
                                                  Keys::key, Keys::idx)>::value)... }
        {}

        XORSTR_FORCEINLINE constexpr size_type size() const noexcept
        {
            return T::size - 1;
        }

        XORSTR_FORCEINLINE void crypt() noexcept
        {
#if defined(__clang__)
            alignas(T::buffer_align)
                std::uint64_t arr[sizeof...(Keys)]{ detail::load_from_reg(Keys::key)... };
            std::uint64_t*    keys =
                (std::uint64_t*)detail::load_from_reg((std::uint64_t)arr);
#else
            alignas(T::buffer_align) std::uint64_t keys[sizeof...(Keys)]{
                detail::load_from_reg(Keys::key)...
            };
#endif

#ifndef JM_XORSTR_DISABLE_AVX_INTRINSICS
            _crypt_256(keys, std::make_index_sequence<T::buffer_size / 4>{});
            if constexpr(T::buffer_size % 4 != 0)
                _crypt_128(keys, std::index_sequence<T::buffer_size / 2 - 1>{});
#else
            _crypt_128(keys, std::make_index_sequence<T::buffer_size / 2>{});
#endif
        }

        XORSTR_FORCEINLINE const_pointer get() const noexcept
        {
            return reinterpret_cast<const_pointer>(_storage);
        }

        XORSTR_FORCEINLINE pointer get() noexcept
        {
            return reinterpret_cast<pointer>(_storage);
        }

        XORSTR_FORCEINLINE pointer crypt_get() noexcept
        {
            crypt();
            return (pointer)(_storage);
        }
    };

    template<class Tstr, std::size_t... StringIndices, std::size_t... KeyIndices>
    XORSTR_FORCEINLINE constexpr auto
    make_xorstr(Tstr str_lambda,
                std::index_sequence<StringIndices...>,
                std::index_sequence<KeyIndices...>) noexcept
    {
        return xor_string<detail::tstring_<str_lambda()[StringIndices]...>,
                          detail::_ki<KeyIndices, detail::key8<KeyIndices>()>...>{};
    }

} // namespace jm

#endif // include guard
