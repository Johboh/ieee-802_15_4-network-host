FILE(GLOB_RECURSE sources "./src/impl/*.*")

idf_component_register(COMPONENT_NAME "ieee-802_15_4-network-host"
                        SRCS ${sources}
                        INCLUDE_DIRS "./src/")

