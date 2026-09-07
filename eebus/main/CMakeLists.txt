file(GLOB_RECURSE OPENEEBUS_SRCS
    "../openeebus/src/common/*.c"
    "../openeebus/src/service/*.c"
    "../openeebus/src/ship/*.c"
    "../openeebus/src/spine/*.c"
    "../openeebus/src/use_case/*.c"
)
file(GLOB_RECURSE PORT_SRCS
    "../port/src/common/*.c"
)
list(REMOVE_ITEM OPENEEBUS_SRCS
    "${CMAKE_CURRENT_SOURCE_DIR}/../openeebus/src/common/debug.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/../openeebus/src/common/eebus_mutex/eebus_mutex.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/../openeebus/src/common/eebus_queue/eebus_queue.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/../openeebus/src/common/eebus_thread/eebus_thread.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/../openeebus/src/common/eebus_timer/eebus_timer_apple.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/../openeebus/src/common/eebus_timer/eebus_timer_linux.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/../openeebus/src/common/eebus_timer/eebus_timer_windows.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/../openeebus/src/ship/mdns/ship_mdns_avahi.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/../openeebus/src/ship/mdns/ship_mdns_bonjour.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/../openeebus/src/ship/tls_certificate/applink.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/../openeebus/src/ship/tls_certificate/openssl_util.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/../openeebus/src/ship/tls_certificate/tls_certificate.c"
)

idf_component_register(
    SRCS
    "main.c"
    ${OPENEEBUS_SRCS}
    ${PORT_SRCS}

    INCLUDE_DIRS
    "."
    "../port"
    "../openeebus"
)

target_compile_definitions(${COMPONENT_LIB} PRIVATE __freertos__)
