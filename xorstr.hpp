#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <type_traits>
#include <utility>

namespace
{
	constexpr std::uint64_t const_time_seed()
	{
		// custom compile-time seed source for key schedule -nigel
		return
			(static_cast<std::uint64_t>(__TIME__[0] - '0') << 56) ^
			(static_cast<std::uint64_t>(__TIME__[1] - '0') << 48) ^
			(static_cast<std::uint64_t>(__TIME__[3] - '0') << 40) ^
			(static_cast<std::uint64_t>(__TIME__[4] - '0') << 32) ^
			(static_cast<std::uint64_t>(__TIME__[6] - '0') << 24) ^
			(static_cast<std::uint64_t>(__TIME__[7] - '0') << 16) ^
			0x9e3779b97f4a7c15ULL;
	}
}

#ifdef _MSC_VER
#define ALWAYS_INLINE __forceinline
#else
#define ALWAYS_INLINE __attribute__((always_inline))
#endif

template<typename _string_type, size_t _length>
class _Basic_XorStr
{
	using value_type = typename _string_type::value_type;
	using unsigned_value_type = typename std::make_unsigned<value_type>::type;
	using key_type = std::uint64_t;
	static constexpr auto _length_minus_one = _length - 1;

public:
	constexpr ALWAYS_INLINE _Basic_XorStr(value_type const (&str)[_length])
		: _seed(derive_seed(str, std::make_index_sequence<_length_minus_one>())),
		_data{ crypt(str[0], 0, _seed), '\0' },
		_cache{ '\0' },
		_cache_ready(false)
	{
		init_data(str, std::make_index_sequence<_length_minus_one>());
	}

	inline auto c_str() const
	{
		decrypt_to_cache();
		return _cache;
	}

	inline auto str() const
	{
		decrypt_to_cache();
		return _string_type(_cache, _cache + _length_minus_one);
	}

	inline operator _string_type() const
	{
		return str();
	}

	~_Basic_XorStr()
	{
		// zero sensitive buffers on object teardown -nigel
		secure_zero(_cache, _length);
		secure_zero(_data, _length);
		_cache_ready = false;
	}

private:
	static constexpr ALWAYS_INLINE key_type mix64(key_type x)
	{
		x ^= (x >> 30);
		x *= 0xbf58476d1ce4e5b9ULL;
		x ^= (x >> 27);
		x *= 0x94d049bb133111ebULL;
		x ^= (x >> 31);
		return x;
	}

	static constexpr ALWAYS_INLINE key_type index_key(key_type seed, size_t i)
	{
		return mix64(seed + (0x9e3779b97f4a7c15ULL * static_cast<key_type>(i + 1)));
	}

	static constexpr ALWAYS_INLINE value_type crypt(value_type c, size_t i, key_type seed)
	{
		const key_type k = index_key(seed, i);
		const unsigned_value_type key_part = static_cast<unsigned_value_type>(
			k & static_cast<key_type>(std::numeric_limits<unsigned_value_type>::max()));
		return static_cast<value_type>(static_cast<unsigned_value_type>(c) ^ key_part);
	}

	template<size_t... indices>
	constexpr ALWAYS_INLINE void init_data(value_type const (&str)[_length], std::index_sequence<indices...>)
	{
		((_data[indices] = crypt(str[indices], indices, _seed)), ...);
		_data[_length_minus_one] = static_cast<value_type>('\0');
	}

	template<size_t... indices>
	static constexpr ALWAYS_INLINE key_type derive_seed(value_type const (&str)[_length], std::index_sequence<indices...>)
	{
		key_type seed = mix64(const_time_seed() ^ (static_cast<key_type>(_length_minus_one) << 40));
		((seed = mix64(seed ^ (static_cast<key_type>(
			static_cast<typename std::make_unsigned<value_type>::type>(str[indices])) + (static_cast<key_type>(indices) << 8)))), ...);
		return seed == 0 ? 0xa5a5a5a5a5a5a5a5ULL : seed;
	}

	static ALWAYS_INLINE void secure_zero(volatile value_type* ptr, size_t count)
	{
		for (size_t i = 0; i < count; ++i)
		{
			ptr[i] = static_cast<value_type>(0);
		}
	}

	inline void decrypt_to_cache() const
	{
		if (_cache_ready)
		{
			return;
		}

		for (size_t i = 0; i < _length_minus_one; ++i)
		{
			_cache[i] = crypt(_data[i], i, _seed);
		}
		_cache[_length_minus_one] = static_cast<value_type>('\0');
		_cache_ready = true;
	}

	const key_type _seed;
	value_type _data[_length];
	mutable value_type _cache[_length];
	mutable bool _cache_ready;
};
//---------------------------------------------------------------------------
template<size_t _length>
using XorStrA = _Basic_XorStr<std::string, _length>;
template<size_t _length>
using XorStrW = _Basic_XorStr<std::wstring, _length>;
template<size_t _length>
using XorStrU16 = _Basic_XorStr<std::u16string, _length>;
template<size_t _length>
using XorStrU32 = _Basic_XorStr<std::u32string, _length>;
//---------------------------------------------------------------------------
template<typename _string_type, size_t _length, size_t _length2>
inline auto operator==(const _Basic_XorStr<_string_type, _length>& lhs, const _Basic_XorStr<_string_type, _length2>& rhs)
{
	static_assert(_length == _length2, "XorStr== different length");

	return _length == _length2 && lhs.str() == rhs.str();
}
//---------------------------------------------------------------------------
template<typename _string_type, size_t _length>
inline auto operator==(const _string_type& lhs, const _Basic_XorStr<_string_type, _length>& rhs)
{
	return lhs.size() == (_length - 1) && lhs == rhs.str();
}
//---------------------------------------------------------------------------
template<typename _stream_type, typename _string_type, size_t _length>
inline auto& operator<<(_stream_type& lhs, const _Basic_XorStr<_string_type, _length>& rhs)
{
	lhs << rhs.c_str();

	return lhs;
}
//---------------------------------------------------------------------------
template<typename _string_type, size_t _length, size_t _length2>
inline auto operator+(const _Basic_XorStr<_string_type, _length>& lhs, const _Basic_XorStr<_string_type, _length2>& rhs)
{
	return lhs.str() + rhs.str();
}
//---------------------------------------------------------------------------
template<typename _string_type, size_t _length>
inline auto operator+(const _string_type& lhs, const _Basic_XorStr<_string_type, _length>& rhs)
{
	return lhs + rhs.str();
}
//---------------------------------------------------------------------------
template<size_t _length>
constexpr ALWAYS_INLINE auto XorStr(char const (&str)[_length])
{
	return XorStrA<_length>(str);
}
//---------------------------------------------------------------------------
template<size_t _length>
constexpr ALWAYS_INLINE auto XorStr(wchar_t const (&str)[_length])
{
	return XorStrW<_length>(str);
}
//---------------------------------------------------------------------------
template<size_t _length>
constexpr ALWAYS_INLINE auto XorStr(char16_t const (&str)[_length])
{
	return XorStrU16<_length>(str);
}
//---------------------------------------------------------------------------
template<size_t _length>
constexpr ALWAYS_INLINE auto XorStr(char32_t const (&str)[_length])
{
	return XorStrU32<_length>(str);
}
//---------------------------------------------------------------------------
