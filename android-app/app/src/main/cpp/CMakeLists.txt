cmake_minimum_required(VERSION 3.22.1)
project(openfluxbridge LANGUAGES CXX)

add_library(openfluxbridge SHARED openflux_bridge.cpp)
set_target_properties(openfluxbridge PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
