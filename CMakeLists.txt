FILE(GLOB_RECURSE sources "./src/impl/*.*")

set(required_components mbedtls esp_http_client esp-tls)

idf_component_register(COMPONENT_NAME "ieee-802_15_4-network-host"
                        SRCS ${sources}
                        INCLUDE_DIRS "./src/"
                        REQUIRES ${required_components})

