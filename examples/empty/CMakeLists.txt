add_executable(empty main.cpp)
target_link_libraries(empty PRIVATE scfw)
scfw_extract_shellcode(empty)
