add_executable(libhat_example_c_buffer
    buffer/main.c
)
target_link_libraries(libhat_example_c_buffer PRIVATE libhat::libhat_c)

add_executable(libhat_example_c_module
    module/main.c
)
target_link_libraries(libhat_example_c_module PRIVATE libhat::libhat_c)
