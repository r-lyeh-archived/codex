#pragma once
#include <cstdint>
#include <string>

namespace escape
{
    std::string html( const std::string &text );
    std::string url( const std::string &text );
    std::string uri( const std::string &text );
    std::string js( const std::string &text );
}

namespace unescape
{
    std::string html( const std::string &text );
    std::string url( const std::string &text );
    std::string uri( const std::string &text );
    std::string js( const std::string &text );
}

namespace encode
{
    namespace html
    {
        // ' -> &#x27;
        std::string hex( unsigned ch );
        // ' -> &#39;
        std::string dec( unsigned ch );
    }

    namespace uri
    {
        // ' -> %27 ; % -> %25
        std::string hex( unsigned ch );
        // ( hello, world ) -> hello=world&
        std::string strings( const std::string &key, const std::string &value );
    }

    namespace string
    {
        // " -> \" ; hello "world" -> hello \"world\"
        std::string quote( const std::string &text );
        // brace( hello, {} ) -> {hello}
        std::string brace( const std::string &text, const char emb[2] = "\"\"" );
    }
}

namespace decode
{}

namespace utf8
{
    const char* decode(const char* str, int maxbytes, std::uint32_t* result);
    const char* encode(std::uint32_t codepoint, char* str);
    int strlen(const char* str);
    int strnlen(const char* str, int bytes);
    bool is_continuation_byte(int byte);
    bool is_initial_byte(int byte);
}
