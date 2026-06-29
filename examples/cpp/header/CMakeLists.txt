add_executable(libhat_example_cpp_header
    main.cpp
)
target_link_libraries(libhat_example_cpp_header PRIVATE libhat::libhat_cpp)
