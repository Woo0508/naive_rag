cmake_minimum_required(VERSION 3.30)
project(naive_rag LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenMP QUIET)

find_package(faiss CONFIG QUIET)
if(TARGET faiss::faiss)
    add_library(faiss ALIAS faiss::faiss)
elseif(NOT TARGET faiss)
    # Conda/micromamba installs of Faiss often don't ship faissConfig.cmake.
    # Fall back to locating headers + library in CMAKE_PREFIX_PATH / CONDA_PREFIX.
    set(_faiss_hints "")
    if(DEFINED CMAKE_PREFIX_PATH)
        list(APPEND _faiss_hints ${CMAKE_PREFIX_PATH})
    endif()
    if(DEFINED ENV{CONDA_PREFIX})
        list(APPEND _faiss_hints "$ENV{CONDA_PREFIX}")
    endif()

    find_path(FAISS_INCLUDE_DIR
        NAMES faiss/Index.h
        HINTS ${_faiss_hints}
        PATH_SUFFIXES include)
    find_library(FAISS_LIBRARY
        NAMES faiss
        HINTS ${_faiss_hints}
        PATH_SUFFIXES lib)

    if(NOT FAISS_INCLUDE_DIR OR NOT FAISS_LIBRARY)
        message(FATAL_ERROR
            "Faiss not found. Install Faiss and reconfigure with -DCMAKE_PREFIX_PATH=<prefix> "
            "(for micromamba/conda: -DCMAKE_PREFIX_PATH=$CONDA_PREFIX).")
    endif()

    add_library(faiss UNKNOWN IMPORTED)
    set_target_properties(faiss PROPERTIES
        IMPORTED_LOCATION "${FAISS_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${FAISS_INCLUDE_DIR}")
endif()



add_executable(naive_rag main.cpp
        include/config.h
        include/client.h
        include/server.h
        include/vector_utils.h
        src/client.cpp
        src/server.cpp
        src/vector_utils.cpp
        src/openFHE_wrapper.cpp
        utils.cpp)

target_link_libraries(naive_rag PRIVATE faiss)
if(OpenMP_CXX_FOUND)
    target_link_libraries(naive_rag PRIVATE OpenMP::OpenMP_CXX)
endif()

add_library(openfhecorelib SHARED IMPORTED)
add_library(openfhepkelib SHARED IMPORTED)

set_target_properties(openfhecorelib PROPERTIES IMPORTED_LOCATION "/usr/local/lib/libOPENFHEpke.so")
set_target_properties(openfhecorelib PROPERTIES IMPORTED_LOCATION "/usr/local/lib/libOPENFHEcore.so")

include_directories("/usr/local/include/openfhe")
include_directories("/usr/local/include/openfhe/core")
include_directories("/usr/local/include/openfhe/pke")
include_directories("/usr/local/include/openfhe/binfhe")

link_directories("/usr/local/lib")
link_directories("/usr/include")

#target_link_libraries(SLAP omp)
target_link_libraries(naive_rag PRIVATE OPENFHEcore)
target_link_libraries(naive_rag PRIVATE OPENFHEpke)
target_link_libraries(naive_rag PRIVATE OPENFHEbinfhe)

set(CMAKE_PREFIX_PATH "/usr/local/lib/OpenFHE")
find_package("OpenFHE" QUIET)