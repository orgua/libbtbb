#
# This file is part of Libbtbb.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.
#
# Based slightly upon the hackrf cmake setup.

include(${PROJECT_SOURCE_DIR}/../cmake/set_release.cmake)
add_definitions( -DRELEASE="${RELEASE_STRING}" )
message(STATUS "Setting version string ${RELEASE_STRING}")

# Source
set(SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/bluetooth_packet.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/bluetooth_piconet.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/bluetooth_le_packet.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/companies.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/pcap.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/pcapng.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/pcapng-bt.cpp

        ${CMAKE_CURRENT_SOURCE_DIR}/btbb.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/pcap-common.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/sw_check_tables.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/uthash.hpp

			  	  CACHE INTERNAL "List of C sources")

set(HEADER_FILES ${CMAKE_CURRENT_SOURCE_DIR}/btbb.hpp
			  CACHE INTERNAL "List of C headers")

if( NOT ${BUILD_SHARED_LIB} AND NOT ${BUILD_STATIC} )
	message( FATAL_ERROR "Not building static or shared library - at least one must be built")
endif( NOT ${BUILD_SHARED_LIB} AND NOT ${BUILD_STATIC} )

set(CMAKE_MACOSX_RPATH 1)

if( ${BUILD_SHARED_LIB} )
    # Shared library
    message(STATUS "Building shared library")
    add_library(btbb SHARED ${SOURCE_FILES})
    set_target_properties(btbb PROPERTIES VERSION ${MAJOR_VERSION}.${MINOR_VERSION} SOVERSION 1)
    set_target_properties(btbb PROPERTIES CLEAN_DIRECT_OUTPUT 1)
#    install(TARGETS btbb
#            LIBRARY DESTINATION lib${LIB_SUFFIX}
#            COMPONENT sharedlibs)
endif( ${BUILD_SHARED_LIB} )

if( ${BUILD_STATIC_LIB} )
    # Static library
    message(STATUS "Building static library")
    add_library(btbb-static STATIC ${SOURCE_FILES})
    set_target_properties(btbb-static PROPERTIES OUTPUT_NAME "btbb")
    set_target_properties(btbb-static PROPERTIES CLEAN_DIRECT_OUTPUT 1)
    install(TARGETS btbb-static
            DESTINATION lib${LIB_SUFFIX}
            COMPONENT staticlibs)
endif( ${BUILD_STATIC_LIB} )

install(FILES ${HEADER_FILES}
        DESTINATION include
        COMPONENT headers
        )
