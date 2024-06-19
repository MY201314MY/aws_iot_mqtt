# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(aws_iot_mqtt)

target_sources(app PRIVATE "src/main.c")
target_sources_ifdef(CONFIG_NET_DHCPV4 app PRIVATE "src/dhcp.c")

set(gen_dir ${CMAKE_CURRENT_BINARY_DIR}/cert)
zephyr_include_directories(${gen_dir})
generate_inc_file_for_target(
    app
    cert/broker.emqx.io-ca.der
    ${gen_dir}/broker.emqx.io-ca.der.inc
)