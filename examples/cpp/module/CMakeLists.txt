add_executable(libhat_example_cpp_module
    main.cpp
)
target_link_libraries(libhat_example_cpp_module PRIVATE libhat::libhat_module)
