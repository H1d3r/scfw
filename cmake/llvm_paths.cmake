# LLVM tool search paths (cross-platform)
# Included by both toolchain.cmake and scfw.cmake
set(SCFW_LLVM_SEARCH_PATHS
    # macOS Homebrew
    /opt/homebrew/opt/llvm/bin
    /usr/local/opt/llvm/bin
    # Linux
    /usr/lib/llvm-22/bin
    /usr/lib/llvm-21/bin
    /usr/lib/llvm-20/bin
    /usr/lib/llvm-19/bin
    /usr/bin
    # Windows
    "$ENV{ProgramFiles}/LLVM/bin"
    "$ENV{ProgramW6432}/LLVM/bin"
)
