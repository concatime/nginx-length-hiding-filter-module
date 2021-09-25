cmake_minimum_required(VERSION 3.12)
cmake_policy(VERSION ${CMAKE_VERSION})

project(ngx_http_length_hiding_filter_module
	DESCRIPTION "Nginx Length Hiding Filter Module"
	HOMEPAGE_URL "https://github.com/concatime/nginx-length-hiding-filter-module"
	LANGUAGES C)

if(POLICY CMP0083)
	include(CheckPIESupported)
	check_pie_supported()
endif()

add_library(${PROJECT_NAME})
set_target_properties(${PROJECT_NAME} PROPERTIES
	POSITION_INDEPENDENT_CODE YES
	C_EXTENSIONS NO)
target_compile_features(${PROJECT_NAME} PRIVATE c_std_90)
target_include_directories(${PROJECT_NAME} PRIVATE
	../nginx/src/core
	../nginx/src/event
	../nginx/src/http
	../nginx/src/http/modules
	../nginx/src/os/unix
	../nginx/objs)
target_sources(${PROJECT_NAME} PRIVATE src/ngx_http_length_hiding_filter_module.c)
