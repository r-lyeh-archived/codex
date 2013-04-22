#include <cassert>
#include <string>
#include <iostream>
#include "codex.hpp"

int main( int argc, const char **argv )
{
    assert( encode::html::dec(0) == "&#0;" );
    assert( encode::html::dec('\'') == "&#39;" );
    assert( encode::html::hex('\'') == "&#x27;" );
    assert( encode::uri::hex('\'') == "%27" );
    assert( encode::uri::hex('%') == "%25" );
    assert( encode::uri::strings("hello", "world") == "hello=world&" );
    assert( encode::string::quote("hello \"world\"") == "hello \\\"world\\\"" );
    assert( encode::string::brace("hello world", "[]") == "[hello world]" );
    assert( escape::html("<hi>") == "&lt;hi&gt;" );

    std::cout << "All ok." << std::endl;
    return 0;
}
