cmake_minimum_required (VERSION 3.0)
set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_SOURCE_DIR}/cmake)

set (PROJECT_NAME hdf5-filter-julea)
project (${PROJECT_NAME})

set (VERSION_MAJOR 0)
set (VERSION_MINOR 1)

find_package(PkgConfig REQUIRED)
find_package(HDF5 REQUIRED)
pkg_search_module(JULEA REQUIRED julea)
find_package(MPI REQUIRED)

pkg_search_module(GLIB REQUIRED glib-2.0)
include_directories(${GLIB_INCLUDE_DIRS})
link_directories(${GLIB_LIBRARY_DIRS})


include(CTest)
include(FeatureSummary)
include(CheckCSourceCompiles)

set (H5_DEFAULT_PLUGINDIR "/usr/local/hdf5/lib/plugin")

# compile flags
set (CMAKE_C_FLAGS
    "${CMAKE_C_FLAGS} -ggdb3 -std=gnu11 -ldl -pedantic -Wall -Wextra -pedantic-errors"
)
set (CMAKE_C_FLAGS_DEBUG   "-O0")
set (CMAKE_C_FLAGS_RELEASE "-O3")
set (CMAKE_INSTALL_RPATH "${HDF5_LIBRARY_DIRS}" "${JULEA_LIBRARY_DIRS}")

include_directories(${CMAKE_SOURCE_DIR}/ ${CMAKE_BINARY_DIR} ${HDF5_INCLUDE_DIR} ${JULEA_INCLUDE_DIRS} ${MPI_C_INCLUDE_PATH})
add_library(hdf5-filter-julea SHARED julea-hdf5-filter.c)
target_link_libraries(hdf5-filter-julea -L${JULEA_LIBRARY_DIRS} ${GLIB_LIBRARIES} ${HDF5_LIBRARIES} ${JULEA_LIBRARIES})

## Installation
install(TARGETS hdf5-filter-julea LIBRARY DESTINATION ${H5_DEFAULT_PLUGINDIR})
install(FILES julea-hdf5-filter.h DESTINATION include)