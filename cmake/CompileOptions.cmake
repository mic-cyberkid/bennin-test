# Set global compile options
if(MSVC)
    add_compile_options(
        /W4              # Warning level 4
        /WX              # Treat warnings as errors
        /std:c++20       # C++20 standard
        /permissive-     # Strict conformance
        /D_WIN32_WINNT=0x0601 # Target Windows 7 (or later)
        /Os              # Favor size
        /GL              # Whole Program Optimization
        /MT              # Static runtime
        /GS-             # Disable buffer security check (risky but common for small implants)
        /EHsc            # Enable exception handling
    )
    # Prevent min/max macros
    add_compile_definitions(NOMINMAX)
    add_link_options(
        /LTCG            # Link Time Code Generation
        /OPT:REF         # Remove unused functions
        /OPT:ICF         # COMDAT folding
        /NODEFAULTLIB:libcmtd.lib # Avoid debug runtime conflict if any
    )
else()
    # GCC/Clang
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()
