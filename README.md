## example
```cpp
std::int32_t main ( int argc , char *argv[ ] )
{
	fn::c_decryptor decrypt;

	std::uintptr_t uworld = decrypt.call( );
	std::printf( "decrypted uworld -> <0x%llx>\n" , uworld );

	std::cin.get( );
}
```
