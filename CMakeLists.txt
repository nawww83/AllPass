cmake_minimum_required(VERSION 3.16)

project(AllPass VERSION 2.00 LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- Секция высокопроизводительных оптимизаций и крипто-безопасности ОС ---
if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    if(NOT ANDROID AND NOT IOS)
        if(MSVC)
            # Оптимизации и защита для компилятора Microsoft (MSVC)
            # /Ox - максимальная оптимизация, /arch:AVX2 - векторные инструкции CPU
            # /GS - защита от переполнения буфера (Stack Canary)
            # /ControlFlowGuard - защита от изменения указателей функций (CFG)
            add_compile_options(/Ox /arch:AVX2 /Oi /Ot /GL /GS /controlflowguard)
            set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /LTCG /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA")
        else()
            # Оптимизации и защита для GCC / Clang / MinGW
            add_compile_options("-O3")
            add_compile_options("-mssse3" "-msse4.1") # Поддержка SSE для SIMD в LFSR

            # 🛡️ Усиление безопасности стека и бинарного файла (Крипто-гигиена ОС)
            add_compile_options("-fstack-protector-strong") # Защита стека от переполнения (Stack Canaries)
            add_compile_options("-D_FORTIFY_SOURCE=2")      # Контроль безопасного использования функций работы с памятью
            add_compile_options("-fPIE")                    # Позиционно-независимый исполняемый код для ASLR

            if(NOT WIN32)
                # Флаги строгой линковки только для нативного Linux
                set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie -Wl,-z,relro -Wl,-z,now")
            endif()

            # Проверка и включение -march=native
            include(CheckCXXCompilerFlag)
            check_cxx_compiler_flag("-march=native" HAS_MARCH_NATIVE)
            if(HAS_MARCH_NATIVE)
                add_compile_options("-march=native")
            endif()

            # Включаем LTO (Link Time Optimization) для инлайнинга крипто-функций через файлы
            check_cxx_compiler_flag("-flto" HAS_FLTO)
            if(HAS_FLTO)
                add_compile_options("-flto")
                set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -flto")
            endif()
        endif()
    endif()
else()
    # В режиме отладки (Debug) также добавляем базовую защиту стека от случайных сбоев
    if(NOT MSVC AND NOT ANDROID AND NOT IOS)
        add_compile_options("-fstack-protector-strong")
    endif()
endif()
# --------------------------------------------------------------------------

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets Network)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets Network)

set(APP_DIR AppCore)
set(UTILS_DIR utils)
set(LFSR_DIR ${UTILS_DIR}/lfsr)

INCLUDE_DIRECTORIES(${APP_DIR} ${UTILS_DIR} ${LFSR_DIR} images)

set(COMMON_SRC
    ${APP_DIR}/main.cpp
    ${APP_DIR}/widget.cpp
    ${APP_DIR}/worker.cpp
    ${APP_DIR}/passitemdelegate.cpp
    ${APP_DIR}/storagemanager.cpp
    ${APP_DIR}/usbstorages.cpp
    ${APP_DIR}/crypto_table_item.cpp
    ${APP_DIR}/crypto_table_item.h
    ${APP_DIR}/widget.ui
    ${APP_DIR}/images.qrc
    ${APP_DIR}/widget.h
    ${APP_DIR}/passitemdelegate.h
    ${APP_DIR}/worker.h
    ${APP_DIR}/storagemanager.h
    ${APP_DIR}/usbstorages.h
    ${UTILS_DIR}/constants.h
    ${UTILS_DIR}/key.h
    ${UTILS_DIR}/stream_cipher.h
    ${UTILS_DIR}/utils.h
    ${UTILS_DIR}/utils_global.h
    ${UTILS_DIR}/global_data.h
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
        AppCore/usbstorages.h AppCore/usbstorages.cpp
        utils/collatz_cipher.h

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
            utils/global_data.h
            utils/utils_global.h
            AppCore/crypto_table_item.h
            AppCore/crypto_table_item.cpp
        )
    endif()
endif()

target_link_libraries(AllPass PRIVATE Qt${QT_VERSION_MAJOR}::Widgets Qt${QT_VERSION_MAJOR}::Network)

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

# Специфичные настройки линковки для Windows (требуются для WMI/COM)
if(WIN32)
    target_link_libraries(AllPass PRIVATE
        wbemuuid
        ole32
        oleaut32
    )
endif()

# Исправление сборки в режиме Debug для GCC/Clang/MinGW
if(NOT MSVC AND NOT ANDROID AND NOT IOS)
    target_compile_options(AllPass PRIVATE "-mssse3" "-msse4.1")
endif()

include(GNUInstallDirs)
install(TARGETS AllPass
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(AllPass)
endif()
