add_executable(messagebox main.cpp)
target_link_libraries(messagebox PRIVATE scfw)
scfw_extract_shellcode(messagebox)
