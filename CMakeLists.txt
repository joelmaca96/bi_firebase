idf_component_register(
    SRCS "bi_firebase.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_http_client esp_timer freertos esp_wifi mbedtls json
)