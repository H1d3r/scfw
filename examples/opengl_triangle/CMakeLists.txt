add_executable(opengl_triangle main.cpp)
target_link_libraries(opengl_triangle PRIVATE scfw)

# For some reason LTO causes bigger binary size here, disable it
set_target_properties(opengl_triangle PROPERTIES SCFW_OPT_LTO OFF)

scfw_extract_shellcode(opengl_triangle)
