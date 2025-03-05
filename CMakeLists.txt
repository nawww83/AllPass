cmake_minimum_required(VERSION 3.16)

project(AllPass VERSION 0.1 LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_compile_options("-msse4.1")

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets)

set(APP_DIR AppCore)
set(UTILS_DIR utils)
set(LFSR_DIR ${UTILS_DIR}/lfsr)

INCLUDE_DIRECTORIES(${UTILS_DIR} ${LFSR_DIR} images)

set(COMMON_SRC
    ${APP_DIR}/main.cpp
    ${APP_DIR}/widget.cpp
    ${APP_DIR}/worker.cpp
    ${APP_DIR}/passitemdelegate.cpp
    ${APP_DIR}/storagemanager.cpp
    ${APP_DIR}/widget.ui
    ${APP_DIR}/images.qrc
    ${APP_DIR}/widget.h
    ${APP_DIR}/passitemdelegate.h
    ${APP_DIR}/worker.h
    ${APP_DIR}/storagemanager.h
    ${UTILS_DIR}/constants.h
    ${UTILS_DIR}/key.h
    ${UTILS_DIR}/stream_cipher.h
    ${UTILS_DIR}/utils.h
    ${LFSR_DIR}/io_utils.h
    ${LFSR_DIR}/lfsr.h
    ${LFSR_DIR}/lfsr_hash.h
)

set(PROJECT_SOURCES
    ${COMMON_SRC}
)

set(app_icon_resource_windows "${CMAKE_CURRENT_SOURCE_DIR}/${APP_DIR}/app.rc")

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(AllPass
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
        ${app_icon_resource_windows}
    )
# Define target properties for Android with Qt 6 as:
#    set_property(TARGET AllPass APPEND PROPERTY QT_ANDROID_PACKAGE_SOURCE_DIR
#                 ${CMAKE_CURRENT_SOURCE_DIR}/android)
# For more information, see https://doc.qt.io/qt-6/qt-add-executable.html#target-creation
else()
    if(ANDROID)
        add_library(AllPass SHARED
            ${PROJECT_SOURCES}
        )
# Define properties for Android with Qt 5 after find_package() calls as:
#    set(ANDROID_PACKAGE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/android")
    else()
        add_executable(AllPass
            ${PROJECT_SOURCES}
        )
    endif()
endif()

target_link_libraries(AllPass PRIVATE Qt${QT_VERSION_MAJOR}::Widgets)

# Qt for iOS sets MACOSX_BUNDLE_GUI_IDENTIFIER automatically since Qt 6.1.
# If you are developing for iOS or macOS you should consider setting an
# explicit, fixed bundle identifier manually though.
if(${QT_VERSION} VERSION_LESS 6.1.0)
  set(BUNDLE_ID_OPTION MACOSX_BUNDLE_GUI_IDENTIFIER com.example.AllPass)
endif()
set_target_properties(AllPass PROPERTIES
    ${BUNDLE_ID_OPTION}
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

include(GNUInstallDirs)
install(TARGETS AllPass
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(AllPass)
endif()
