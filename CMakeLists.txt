cmake_minimum_required(VERSION 3.22)
project(test1)

find_package(Boost COMPONENTS filesystem iostreams program_options REQUIRED)

include_directories(${Boost_INCLUDE_DIRS})
add_executable(program main.cpp)

target_link_libraries(program LINK_PUBLIC Boost::filesystem Boost::iostreams Boost::program_options)


