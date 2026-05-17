#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <bit>
#include <intrin.h>
#include <stdio.h>
#include <cstdio>
#include <cstdint>

namespace fn
{
	class c_decryptor
	{
	public:
		std::uintptr_t decrypt_v ( uint64_t v )
		{
			if ( !v ) return 0;
			v ^= 0xC774FEull;
			v = _rotl64( v , 56 );
			v ^= 0xF81BA2C7ull;
			v *= 0x80CD98FC8EC532E9ull;
			return static_cast< uintptr_t >( v );
		}

		std::uintptr_t decrypt_rot32 ( std::uint64_t v )
		{
			if ( !v ) return 0;
			v ^= 0xC774FEull;

			std::uint32_t low = _rotl( static_cast<std::uint32_t>(v) , 16 );
			std::uint32_t high = _rotl( static_cast<std::uint32_t>(v >> 32) , 16 );
			v = ( static_cast< std::uint64_t >( high ) << 32 ) | low;

			v ^= 0xF81BA2C7ull;
			v *= 0x80CD98FC8EC532E9ull;
			return static_cast< std::uintptr_t >( v );
		}

		// endian byteswap
		std::uintptr_t decrypt_byteswap ( std::uint64_t v )
		{
			if ( !v ) return 0;
			v ^= 0xC774FEull;
			v = _byteswap_uint64( v );
			v ^= 0xF81BA2C7ull;
			v *= 0x80CD98FC8EC532E9ull;
			return static_cast< std::uintptr_t >( v );
		}

		auto call ( )
		{
			uint64_t rva = seh->rvm< uint64_t >( seh->m_module + g_world_rva );
			if ( !rva ) return 0;

			uintptr_t res1 = decrypt_v( rva );
			if ( this->is_valid( res1 ) ) return res1;
			uintptr_t res2 = decrypt_rot32( rva );
			if ( this->is_valid( res2 ) ) return res2;
			uintptr_t res3 = decrypt_byteswap( rva );
			if ( this->is_valid( res3 ) ) return res3;
		}

	private:
		bool is_valid ( std::uintptr_t ptr )
		{
			return ( ptr > 0x00010000 && ptr < 0x7FFFFFFFFFFF );
		}
	};
}

std::int32_t main ( int argc , char *argv[ ] )
{
	fn::c_decryptor decrypt;

	std::uintptr_t uworld = decrypt.call( );
	std::printf( "decrypted uworld -> <0x%llx>\n" , uworld );

	std::cin.get( );
}
