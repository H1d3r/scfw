add_executable(scrun scrun.c)
target_compile_options(scrun PRIVATE
    --target=${CMAKE_C_COMPILER_TARGET}
    ${SCFW_WINSDK_COMPILE_OPTIONS}
)
target_compile_definitions(scrun PRIVATE _CRT_SECURE_NO_WARNINGS)
target_include_directories(scrun PRIVATE ${SCFW_WINSDK_INCLUDE_DIRS})
target_link_options(scrun PRIVATE
    --target=${CMAKE_C_COMPILER_TARGET}
    -fuse-ld=lld
    -Wl,/SUBSYSTEM:CONSOLE
)
foreach(_dir IN LISTS SCFW_WINSDK_LIB_DIRS)
    target_link_options(scrun PRIVATE "-Wl,/LIBPATH:${_dir}")
endforeach()
