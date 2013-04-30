#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include <iostream>
#include <string>
#include "codex.hpp"

int main( int argc, const char **argv )
{
    assert( encode::html::dec(0) == "&#0;" );
    assert( encode::html::dec('\'') == "&#39;" );
    assert( encode::html::hex('\'') == "&#x27;" );
    assert( escape::html("<hi>") == "&lt;hi&gt;" );
    assert( encode::uri::hex('\'') == "%27" );
    assert( encode::uri::hex('%') == "%25" );
    assert( encode::uri::strings("hello", "world") == "hello=world&" );
    assert( encode::string::quote("hello \"world\"") == "hello \\\"world\\\"" );
    assert( encode::string::brace("hello world", "[]") == "[hello world]" );

    std::cout << "All ok." << std::endl;
    return 0;
}

#define joint2(n,l) n##l
#define joint(n,l) joint2(n,l)
#define test(desc) void joint(fn,__LINE__)(); const int joint(var,__LINE__) = std::printf("%s ... %s\n", desc, (joint(fn,__LINE__)(), "OK") ); void joint(fn,__LINE__)()

test("utf8::decode() should decode codepoint from utf8 string in the single octet range 00-7f")
{
    const unsigned char ustr1[]={ 1 };
    const unsigned char ustr2[]={ 0x32 };
    const unsigned char ustr3[]={ 0x7f };
    const unsigned char ustr_er[]={ 0x80 };

    const char* str1 = (const char*)ustr1;
    const char* str2 = (const char*)ustr2;
    const char* str3 = (const char*)ustr3;
    const char* str_er = (const char*)ustr_er;

    unsigned int codepoint = 0;

    const char* res = 0;

    codepoint = 0;
    res = utf8::decode(str1, 1, &codepoint);
    assert( codepoint == 1u);
    assert( res == str1+1 );

    codepoint = 0;
    res = utf8::decode(str2, 1, &codepoint);
    assert( codepoint == 0x32u);
    assert( res == str2+1 );

    codepoint = 0;
    res = utf8::decode(str3, 1, &codepoint);
    assert( codepoint == 0x7fu);
    assert( res == str3+1 );

    codepoint = 0;
    res = utf8::decode(str_er, 1, &codepoint);
    assert( codepoint == 0xfffdu);
    assert( res == str_er+1 );
}

test("utf8::decode() should decode codepoint from utf8 string in the two octet range 80-7ff")
{
    const unsigned char ustr1[]={ 0xc2u, 0x80u };
    const unsigned char ustr2[]={ 0xc4u, 0x80u };
    const unsigned char ustr3[]={ 0xdfu, 0xbfu };
    const unsigned char ustr_er[]={ 0xdfu, 0xc0u };
    const unsigned char ustr_er2[]={ 0xdfu };

    const char* str1 = (const char*)ustr1;
    const char* str2 = (const char*)ustr2;
    const char* str3 = (const char*)ustr3;
    const char* str_er = (const char*)ustr_er;
    const char* str_er2 = (const char*)ustr_er2;

    unsigned int codepoint = 0;

    const char* res = 0;

    codepoint = 0;
    res = utf8::decode(str1, 2, &codepoint);
    assert( codepoint == 0x80u);
    assert( res == str1+2 );

    codepoint = 0;
    res = utf8::decode(str2, 2, &codepoint);
    assert( codepoint == 0x100u);
    assert( res == str2+2 );

    codepoint = 0;
    res = utf8::decode(str3, 2, &codepoint);
    assert( codepoint == 0x7ffu);
    assert( res == str3+2 );

    codepoint = 0;
    res = utf8::decode(str_er, 2, &codepoint);
    assert( codepoint == 0xfffdu);
    assert( res == str_er+2 );

    codepoint = 0;
    res = utf8::decode(str_er2, 1, &codepoint);
    assert( codepoint == 0xfffdu);
    assert( res == str_er2+1 );
}

test("utf8::decode() should decode codepoint from utf8 string in the three octet range 800-ffff")
{
    const unsigned char ustr1[]={ 0xe0u, 0xa0u, 0x80u };
    const unsigned char ustr2[]={ 0xe1u, 0x80u, 0x80u };
    const unsigned char ustr3[]={ 0xefu, 0xbfu, 0xbfu };
    const unsigned char ustr_er[]={ 0xefu, 0xbfu, 0xc0u };
    const unsigned char ustr_er2[]={ 0xefu, 0xbfu };

    const char* str1 = (const char*)ustr1;
    const char* str2 = (const char*)ustr2;
    const char* str3 = (const char*)ustr3;
    const char* str_er = (const char*)ustr_er;
    const char* str_er2 = (const char*)ustr_er2;

    unsigned int codepoint = 0;

    const char* res = 0;

    codepoint = 0;
    res = utf8::decode(str1, 3, &codepoint);
    assert( codepoint == 0x800u);
    assert( res == str1+3 );

    codepoint = 0;
    res = utf8::decode(str2, 3, &codepoint);
    assert( codepoint == 0x1000u);
    assert( res == str2+3 );

    codepoint = 0;
    res = utf8::decode(str3, 3, &codepoint);
    assert( codepoint == 0xffffu);
    assert( res == str3+3 );

    codepoint = 0;
    res = utf8::decode(str_er, 3, &codepoint);
    assert( codepoint == 0xfffdu);
    assert( res == str_er+3 );

    codepoint = 0;
    res = utf8::decode(str_er2, 2, &codepoint);
    assert( codepoint == 0xfffdu);
    assert( res == str_er2+2 );
}

test("utf8::decode() should decode codepoint from utf8 string in the four octet range 10000-1ffff")
{
    const unsigned char ustr1[]={ 0xf0u, 0x90u, 0x80u, 0x80u };
    const unsigned char ustr2[]={ 0xf0u, 0x92u, 0x80u, 0x80u };
    const unsigned char ustr3[]={ 0xf0u, 0x9fu, 0xbfu, 0xbfu };
    const unsigned char ustr_er[]={ 0xf0u, 0x9fu, 0xbfu, 0xc0u };
    const unsigned char ustr_er2[]={ 0xf0u, 0x9fu, 0xbfu };

    const char* str1 = (const char*)ustr1;
    const char* str2 = (const char*)ustr2;
    const char* str3 = (const char*)ustr3;
    const char* str_er = (const char*)ustr_er;
    const char* str_er2 = (const char*)ustr_er2;

    unsigned int codepoint = 0;

    const char* res = 0;

    codepoint = 0;
    res = utf8::decode(str1, 4, &codepoint);
    assert( codepoint == 0x10000u);
    assert( res == str1+4 );

    codepoint = 0;
    res = utf8::decode(str2, 4, &codepoint);
    assert( codepoint == 0x12000u);
    assert( res == str2+4 );

    codepoint = 0;
    res = utf8::decode(str3, 4, &codepoint);
    assert( codepoint == 0x1ffffu);
    assert( res == str3+4 );

    codepoint = 0;
    res = utf8::decode(str_er, 4, &codepoint);
    assert( codepoint == 0xfffdu);
    assert( res == str_er+4 );

    codepoint = 0;
    res = utf8::decode(str_er2, 3, &codepoint);
    assert( codepoint == 0xfffdu);
    assert( res == str_er2+3 );
}

test("utf8::decode() should not allow overlong sequences")
{
    const unsigned char ustr1[]={ 0xc0u, 0xafu };
    const unsigned char ustr2[]={ 0xe0u, 0x80u, 0xafu };
    const unsigned char ustr3[]={ 0xf0u, 0x80u, 0x80u, 0xafu };
    const unsigned char ustr4[]={ 0xf8u, 0x80u, 0x80u, 0x80u, 0xafu };
    const unsigned char ustr5[]={ 0xfcu, 0x80u, 0x80u, 0x80u, 0x80u, 0xafu };

    const char* str1 = (const char*)ustr1;
    const char* str2 = (const char*)ustr2;
    const char* str3 = (const char*)ustr3;
    const char* str4 = (const char*)ustr4;
    const char* str5 = (const char*)ustr5;

    unsigned int codepoint;

    codepoint = 0;
    utf8::decode(str1, 2, &codepoint);
    assert( codepoint == 0xfffdu);

    codepoint = 0;
    utf8::decode(str2, 3, &codepoint);
    assert( codepoint == 0xfffdu);

    codepoint = 0;
    utf8::decode(str3, 4, &codepoint);
    assert( codepoint == 0xfffdu);

    codepoint = 0;
    utf8::decode(str4, 5, &codepoint);
    assert( codepoint == 0xfffdu);

    codepoint = 0;
    utf8::decode(str5, 6, &codepoint);
    assert( codepoint == 0xfffdu);
}

test("utf8::decode() should not allow maximum overlong sequences")
{
    const unsigned char ustr1[]={ 0xc1u, 0xbfu };
    const unsigned char ustr2[]={ 0xe0u, 0x9fu, 0xbfu };
    const unsigned char ustr3[]={ 0xf0u, 0x8fu, 0xbfu, 0xbfu };
    const unsigned char ustr4[]={ 0xf8u, 0x87u, 0xbfu, 0xbfu, 0xbfu };
    const unsigned char ustr5[]={ 0xfcu, 0x83u, 0xbfu, 0xbfu, 0xbfu, 0xbfu };

    const char* str1 = (const char*)ustr1;
    const char* str2 = (const char*)ustr2;
    const char* str3 = (const char*)ustr3;
    const char* str4 = (const char*)ustr4;
    const char* str5 = (const char*)ustr5;

    unsigned int codepoint;

    codepoint = 0;
    utf8::decode(str1, 2, &codepoint);
    assert( codepoint == 0xfffdu);

    codepoint = 0;
    utf8::decode(str2, 3, &codepoint);
    assert( codepoint == 0xfffdu);

    codepoint = 0;
    utf8::decode(str3, 4, &codepoint);
    assert( codepoint == 0xfffdu);

    codepoint = 0;
    utf8::decode(str4, 5, &codepoint);
    assert( codepoint == 0xfffdu);

    codepoint = 0;
    utf8::decode(str5, 6, &codepoint);
    assert( codepoint == 0xfffdu);
}

test("utf8::decode() should not allow codepoints designated as surrogates")
{
    for(size_t i = 0xa0; i <= 0xbf; ++i) {
        for(size_t j = 0x80; j <= 0xbf; ++j) {
            const unsigned char ustr1[]={ (unsigned char)0xedu, (unsigned char)i, (unsigned char)j };
            const char* str1 = (const char*)ustr1;
            unsigned int codepoint = 0;
            utf8::decode(str1, 3, &codepoint);
            assert( codepoint == 0xfffdu);
        }
    }
}

test("utf8::encode() should encode all valid codepoints to utf8")
{
    char buf[8];
    for(unsigned int i = 0; i < 0x1ffff; ++i)
    {
        // Skip surrogates, as they are not allowed in utf8
        if( i >= 0xd800 && i <= 0xdfff ) continue;

        std::memset(buf, 0, 8);

        const char* ret1 = utf8::encode(i, buf);
        uint32_t res = 0;
        const char* ret2 = utf8::decode(buf,7,&res);
        assert( i == res );
        assert( ret1 == ret2 );
    }
}

test("utf8::strlen() should count distinct codepoints")
{
    const char* str1 = "foobar";
    const char* str2 = "foob\xc3\xa6r";
    const char* str3 = "foob\xf0\x9f\x99\x88r";

    assert( utf8::strlen(str1) == 6);
    assert( utf8::strlen(str2) == 6);
    assert( utf8::strlen(str3) == 6);
}

test("utf8::strnlen() should count distinct codepoints")
{
    const char* str1 = "foobar";
    const char* str2 = "foob\xc3\xa6r";
    const char* str3 = "foob\xf0\x9f\x99\x88r";

    assert( utf8::strnlen(str1,6) == 6);
    assert( utf8::strnlen(str2,7) == 6);
    assert( utf8::strnlen(str3,9) == 6);
}

test("utf8::is_continuation_byte() should return true if a given byte is not the initial byte of a utf8 sequence")
{
    const char* str1 = "f";
    const char* str2 = "f\xc3\xa6r";
    const char* str3 = "f\xf0\x9f\x99\x88r";
    assert( !utf8::is_continuation_byte( str1[0] ) );

    assert( !utf8::is_continuation_byte( str2[0] ) );
    assert( !utf8::is_continuation_byte( str2[1] ) );
    assert( utf8::is_continuation_byte( str2[2] ) );

    assert( !utf8::is_continuation_byte( str3[0] ) );
    assert( !utf8::is_continuation_byte( str3[1] ) );
    assert( utf8::is_continuation_byte( str3[2] ) );
    assert( utf8::is_continuation_byte( str3[3] ) );
    assert( utf8::is_continuation_byte( str3[4] ) );
}

test("utf8::is_initial_byte() should return true if a given byte is the initial byte of a utf8 sequence")
{
    const char* str1 = "f";
    const char* str2 = "f\xc3\xa6r";
    const char* str3 = "f\xf0\x9f\x99\x88r";
    assert( utf8::is_initial_byte( str1[0] ) );

    assert( utf8::is_initial_byte( str2[0] ) );
    assert( utf8::is_initial_byte( str2[1] ) );
    assert( !utf8::is_initial_byte( str2[2] ) );

    assert( utf8::is_initial_byte( str3[0] ) );
    assert( utf8::is_initial_byte( str3[1] ) );
    assert( !utf8::is_initial_byte( str3[2] ) );
    assert( !utf8::is_initial_byte( str3[3] ) );
    assert( !utf8::is_initial_byte( str3[4] ) );
}
