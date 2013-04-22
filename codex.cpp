/* Simple escaping/unescaping/encoding/decoding functions.
 * Copyright (c) 2013 Mario 'rlyeh' Rodriguez

 * Based on code from escape-utils by Brian Lopez
 * Copyright (c) 2010-2011 Brian Lopez - http://github.com/brianmario

 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

 * To do:
 * - [...]

 * - rlyeh
 */

#include <cassert>

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>

#include "codex.hpp"

// Unreserved Characters RFC 3986 [ref] http://en.wikipedia.org/wiki/Percent-encoding
// May be encoded but it is not necessary.
#define URI_IS_UNRESERVED(c) ( IS_ALPHANUM(c) || c == '-' || c == '_' || c == '.' || c == '~' )
// Reserved Characters RFC 3986 [ref] http://en.wikipedia.org/wiki/Percent-encoding
// Have to be encoded sometimes
#define URI_IS_RESERVED(c)   ( c == '!' || c == '*' || c == '\'' || c == '(' || c == ')' || c == ';' || c == ':' || c == '@' || c == '&' || c == '=' || c == '+' || c == '$' || c == ',' ||  c == '/' || c == '?' || c == '#' || c == '[' || c == ']' )
// Unsafe Characters
// All others
#define URI_IS_UNSAFE(c)     ( URI_IS_UNRESERVED(c) || URI_IS_RESERVED(c) ? false : true )
#define URI_SAFE(c)          ( URI_IS_UNRESERVED(c) || URI_IS_RESERVED(c) )
#define URL_SAFE(c)          ( URI_IS_UNRESERVED(c) )

// IN_RANGE(c,b,e) is alias for ( c >= b && c <= e ) only if b < e
// IS_ALPHA/IS_ALPHANUM/IS_HEX are sorted by priority of occurrence
#define IN_RANGE(c,b,e) (unsigned((c) - (b)) <= (e)-(b)) //
#define IS_NUMBER(c)    (IN_RANGE(c,'0','9'))
#define IS_ALPHA(c)     (IN_RANGE(c,'a','z') || IN_RANGE(c,'A','Z'))
#define IS_ALPHANUM(c)  (IN_RANGE(c,'a','z') || IN_RANGE(c,'0','9') || IN_RANGE(c,'A','Z'))
#define IS_HEX(c)       (IN_RANGE(c,'0','9') || IN_RANGE(c,'a','f') || IN_RANGE(c,'A','F'))

#define UN_HEX(c)    ( c <= '9' ? c - '0' : ( c <= 'F' ? c - 'A' + 10 : c - 'a' + 10 ) )
#define HEX_F0(c)   ( "0123456789ABCDEF"[(c >> 4) & 0x0f] )
#define HEX_0F(c)   ( "0123456789ABCDEF"[(c     ) & 0x0f] )


namespace {

    template< size_t N >
    struct bitsmap
    {
        unsigned char map[ N / 8 ];

        bitsmap() {
          static_assert( (N > 0) && (!(N % 8)), "not divisible by 8" );
          clear();
        }

        inline void set( unsigned pos, int value = 1 ) {
          map[ pos / 8 ] |= ((value & 1) << (pos % 8));
        }

        inline void unset( unsigned pos ) {
          set( pos, false );
        }

        inline int get( unsigned pos ) const {
          return ( map[ pos / 8 ] & (1 << (pos % 8)) ) > 0;
        }

        void clear( bool value = false ) {
          memset( map, value ? 0xFF : 0x00, N/8 );
        }
    };

#   define $codex_expand( fn, MACRO ) \
    inline int fn( int ch ) { \
    if(0) { \
      static char table[256], *once = 0; \
      if( !once ) { \
        for( int c = 0; c < 256; ++c ) \
          table[ c ] = MACRO(c) ? 1 : 0; \
        once = table; \
      } \
      return table[ unsigned(ch) ]; \
    } else { \
      static bitsmap<256> table, *once = 0; \
      if( !once ) { \
        table.clear(0); \
        for( int c = 0; c < 256; ++c ) \
          table.set( c, MACRO(c) ); \
        once = &table; \
      } \
      return table.get( ch ); \
    } \
    }

    $codex_expand( is_uri_safe, URI_SAFE )
    $codex_expand( is_url_safe, URL_SAFE )
    $codex_expand( is_hex, IS_HEX )
    $codex_expand( is_alpha, IS_ALPHA )
    $codex_expand( is_number, IS_NUMBER )
    $codex_expand( is_alphanum, IS_ALPHANUM )

#   undef $codex_expand
}

namespace
{
    size_t escape_html(char *out, const char *in, int secure = 1);
    size_t unescape_html(char *out, const char *in);
    size_t escape_javascript(char *out, const char *in);
    size_t unescape_javascript(char *out, const char *in);
    size_t escape_url(char *out, const char *in);
    size_t unescape_url(char *out, const char *in);
    size_t escape_uri(char *out, const char *in);
    size_t unescape_uri(char *out, const char *in);

    /*
    HTML escaping follows the OWASP suggestion. All other entities are left as-is.
    < --> &lt;
    > --> &gt;
    & --> &amp;
    ' --> &#x27;     &apos; is not recommended
    " --> &quot;
    / --> &#x2F;     forward slash is included as it helps end an HTML entity
    */
    size_t escape_html(char *out, const char *in, int secure) {
      const char *base = out;

      while (*in) {
        const char &curChar = *in++;

        if (curChar == '<') {
          *out++ = '&'; *out++ = 'l'; *out++ = 't'; *out++ = ';';
        } else if (curChar == '>') {
          *out++ = '&'; *out++ = 'g'; *out++ = 't'; *out++ = ';';
        } else if (curChar == '&') {
          *out++ = '&'; *out++ = 'a'; *out++ = 'm'; *out++ = 'p'; *out++ = ';';
        } else if (curChar == '\'') {
          *out++ = '&'; *out++ = '#'; *out++ = '3'; *out++ = '9'; *out++ = ';';
        } else if (curChar == '\"') {
          *out++ = '&'; *out++ = 'q'; *out++ = 'u'; *out++ = 'o'; *out++ = 't'; *out++ = ';';
        } else if (secure && curChar == '/') {
          *out++ = '&'; *out++ = '#'; *out++ = '4'; *out++ = '7'; *out++ = ';';
        } else {
          *out++ = curChar;
        }
      }

      return out - base;
    }

    size_t unescape_html(char *out, const char *in) {
      const char *base = out;

      while (*in) {
        const char &curChar = *in++;
        if (curChar == '&') {
          if (*in == 'l' && *(in+1) == 't' && *(in+2) == ';') {
            *out++ = '<';
            in+=3;
          } else if (*in == 'g' && *(in+1) == 't' && *(in+2) == ';') {
            *out++ = '>';
            in+=3;
          } else if (*in == 'a' && *(in+1) == 'm' && *(in+2) == 'p' && *(in+3) == ';') {
            *out++ = '&';
            in+=4;
          } else if (*in == '#' && *(in+1) == '3' && *(in+2) == '9' && *(in+3) == ';') {
            *out++ = '\'';
            in+=4;
          } else if (*in == '#' && *(in+1) == '4' && *(in+2) == '7' && *(in+3) == ';') {
            *out++ = '/';
            in+=4;
          } else if (*in == 'q' && *(in+1) == 'u' && *(in+2) == 'o' && *(in+3) == 't' && *(in+4) == ';') {
            *out++ = '\"';
            in+=5;
          } else {
            /* incomplete tag, pass it through */
            *out++ = curChar;
          }
        } else {
          *out++ = curChar;
        }
      }

      return out - base;
    }

    size_t escape_javascript(char *out, const char *in) {
      const char *base = out;

      while (*in) {
        const char &curChar = *in++;
        switch (curChar) {
        case '\\':
          *out++ = '\\'; *out++ = '\\';
          break;
        case '<':
          *out++ = '<';
          if (*in == '/') {
            *out++ = '\\'; *out++ = '/';
            in++;;
          }
          break;
        case '\r':
          if (*in == '\n') {
            *out++ = '\\'; *out++ = 'n';
            in++;
          } else {
            *out++ = '\\'; *out++ = 'n';
          }
          break;
        case '\n':
          *out++ = '\\'; *out++ = 'n';
          break;
        case '\'':
          *out++ = '\\'; *out++ = '\'';
          break;
        case '\"':
          *out++ = '\\'; *out++ = '\"';
          break;
        default:
          *out++ = curChar;
          break;
        }
      }

      return out - base;
    }

    size_t unescape_javascript(char *out, const char *in) {
      const char *base = out;

      while (*in) {
        const char &curChar = *in++;
        if (curChar == '\\') {
          if (*in == 'n') {
            *out++ = '\n';
          } else if (*in == '\\') {
            *out++ = '\\';
          } else if (*in == '\'') {
            *out++ = '\'';
          } else if (*in == '\"') {
            *out++ = '\"';
          } else if (*in == '/') {
            *out++ = '/';
          } else {
            /* incomplete escape, pass it through */
            *out++ = curChar;
            continue;
          }
          in++;
        } else {
          *out++ = curChar;
        }
      }

      return out - base;
    }

    size_t escape_url(char *out, const char *in) {
      const char *base = out;

      while (*in) {
        const char &curChar = *in++;
        if (curChar == ' ') {
          *out++ = '+';
        } else if (URL_SAFE(curChar)) {
          *out++ = curChar;
        } else {
          *out++ = '%'; *out++ = HEX_F0(curChar); *out++ = HEX_0F(curChar);
        }
      }

      return out - base;
    }

    size_t unescape_url(char *out, const char *in) {
      const char *base = out;

      while (*in) {
        const char &curChar = *in++;
        if (curChar == '%') {
          if (IS_HEX(*in) && IS_HEX(*(in+1))) {
            *out++ = (UN_HEX(*in) << 4) + UN_HEX(*(in+1));
            in+=2;
          } else {
            /* incomplete escape, pass it through */
            *out++ = curChar;
          }
        } else if (curChar == '+') {
          *out++ = ' ';
        } else {
          *out++ = curChar;
        }
      }

      return out - base;
    }

    size_t escape_uri(char *out, const char *in) {
      const char *base = out;

      while (*in) {
        const char &curChar = *in++;
        if (URI_SAFE(curChar)) {
            *out++ = curChar;
        } else {
            *out++ = '%'; *out++ = HEX_F0(curChar); *out++ = HEX_0F(curChar);
        }
      }

      return out - base;
    }

    size_t unescape_uri(char *out, const char *in) {
      const char *base = out;

      while (*in) {
        const char &curChar = *in++;
        if (curChar == '%') {
          if (IS_HEX(*in) && IS_HEX(*(in+1))) {
            *out++ = (UN_HEX(*in) << 4) + UN_HEX(*(in+1));
            in+=2;
          } else {
            /* incomplete escape, pass it through */
            *out++ = curChar;
          }
        } else {
          *out++ = curChar;
        }
      }

      return out - base;
    }
} // anon::

namespace escape
{
    std::string js( const std::string &input )   {
        enum { mul = 3 };
        std::string output( input.size() * mul, '\0' );
        output.resize( escape_javascript( &output[0], input.c_str() ) );
        return output;
    }
    std::string url( const std::string &input )  {
        enum { mul = 3 };
        std::string output( input.size() * mul, '\0' );
        output.resize( escape_url( &output[0], input.c_str() ) );
        return output;
    }
    std::string uri( const std::string &input )  {
        enum { mul = 3 };
        std::string output( input.size() * mul, '\0' );
        output.resize( escape_uri( &output[0], input.c_str() ) );
        return output;
    }
    std::string html( const std::string &input ) {
        enum { mul = 6 };
        std::string output( input.size() * mul, '\0' );
        output.resize( escape_html( &output[0], input.c_str() ) );
        return output;
    }
}

namespace unescape
{
    std::string js( const std::string &input )   {
        enum { mul = 1 };
        std::string output( input.size() * mul, '\0' );
        output.resize( unescape_javascript( &output[0], input.c_str() ) );
        return output;
    }
    std::string url( const std::string &input )  {
        enum { mul = 1 };
        std::string output( input.size() * mul, '\0' );
        output.resize( unescape_url( &output[0], input.c_str() ) );
        return output;
    }
    std::string uri( const std::string &input )  {
        enum { mul = 1 };
        std::string output( input.size() * mul, '\0' );
        output.resize( unescape_uri( &output[0], input.c_str() ) );
        return output;
    }
    std::string html( const std::string &input ) {
        enum { mul = 1 };
        std::string output( input.size() * mul, '\0' );
        output.resize( unescape_html( &output[0], input.c_str() ) );
        return output;
    }
}

namespace encode
{
    namespace html
    {
        // ' -> &#x27;
        std::string hex( unsigned ch ) {
            assert( ch <= 0xFFFF );
            std::stringstream ss;
            ss << "&#x" << std::hex << ch << ';';
            return ss.str();
        }
        // ' -> &#39;
        std::string dec( unsigned ch ) {
            std::stringstream ss;
            ss << "&#" << ch << ';';
            return ss.str();
        }
    }

    namespace uri
    {
        // ' -> %27 ; % -> %25
        std::string hex( unsigned ch ) {
            assert( ch <= 0xFF );
            std::stringstream ss;
            ss << "%" << std::hex << std::setw(2) << std::setfill('0') << ch;
            return ss.str();
        }
        // ( hello, world ) -> hello=world&
        std::string strings( const std::string &key, const std::string &value ) {
            return key + '=' + value + '&';
        }
    }

    namespace string
    {
        // " -> \"
        // hello "world" -> hello \"world\"
        std::string quote( const std::string &text ) {
            std::string out;
            out.reserve( text.size() );
            for( auto &in : text )
                if( in == '\"' )    out += "\\\"";
                else                out += in;
            return out;
        }
        std::string quote( const std::string &key, const std::string &value ) {
            return key + '=' + value + '&';
        }

        // brace( hello, {} ) -> {hello}
        std::string brace( const std::string &text, const char emb[2] ) {
            return std::string() + emb[0] + text + emb[1];
        }
    }
}

static_assert( int('0') == 48, "wrong text encoding" );
static_assert( int('A') == 65, "wrong text encoding" );
static_assert( int('a') == 97, "wrong text encoding" );

#undef URI_IS_UNRESERVED
#undef URI_IS_RESERVED
#undef URI_IS_UNSAFE
#undef URI_SAFE
#undef URL_SAFE

#undef IN_RANGE
#undef IS_NUMBER
#undef IS_ALPHA
#undef IS_ALPHANUM
#undef IS_HEX

#undef UN_HEX
#undef HEX_F0
#undef HEX_0F
