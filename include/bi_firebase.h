/**
 * @file bi_firebase.h
 * @brief Librería para conectar ESP32 a Firebase Realtime Database usando ESP-IDF
 */

#ifndef BI_FIREBASE_H
#define BI_FIREBASE_H

#include <cJSON.h>
#include <esp_http_client.h>
#include <esp_timer.h>
// #include <esp_tls.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Estados de la conexión Firebase
 */
typedef enum {
    FIREBASE_STATE_IDLE,
    FIREBASE_STATE_INIT,
    FIREBASE_STATE_AUTHENTICATING,
    FIREBASE_STATE_AUTHENTICATED,
    FIREBASE_STATE_REQUEST_PENDING,
    FIREBASE_STATE_ERROR
} firebase_state_t;

/**
 * @brief Tipos de operaciones en Firebase
 */
typedef enum {
    FIREBASE_OP_GET,
    FIREBASE_OP_PUT,
    FIREBASE_OP_POST,
    FIREBASE_OP_PATCH,
    FIREBASE_OP_DELETE
} firebase_operation_t;

/**
 * @brief Tipo de autenticación
 */
typedef enum { FIREBASE_AUTH_API_KEY, FIREBASE_AUTH_JWT, FIREBASE_AUTH_CUSTOM_TOKEN } firebase_auth_type_t;

/**
 * @brief Tipos de datos para lectura y escritura
 */
typedef enum {
    FIREBASE_DATA_TYPE_STRING,
    FIREBASE_DATA_TYPE_INT,
    FIREBASE_DATA_TYPE_FLOAT,
    FIREBASE_DATA_TYPE_BOOL,
    FIREBASE_DATA_TYPE_JSON,
    FIREBASE_DATA_TYPE_ARRAY,
    FIREBASE_DATA_TYPE_NULL
} firebase_data_type_t;

/**
 * @brief Callback para notificar eventos
 */
typedef void (*firebase_event_callback_t)(void *data, int event_id);

/**
 * @brief Estructura para almacenar datos de autenticación
 */
typedef struct {
    firebase_auth_type_t auth_type;
    char *api_key;
    char *user_email;
    char *user_password;
    char *custom_token;
    char *id_token;
    char *refresh_token;
    int64_t token_expiry;
    char *uid;
} firebase_auth_t;

/**
 * @brief Estructura para valor en Firebase
 */
typedef struct {
    firebase_data_type_t type;
    union {
        char *string_val;
        int int_val;
        float float_val;
        bool bool_val;
        void *json_val;
        void *blob_val;
    } data;
    size_t data_size;
} firebase_data_value_t;

/**
 * @brief Estructura para configuración de Firebase
 */
typedef struct {
    char *database_url;
    firebase_auth_t auth;
    firebase_event_callback_t event_callback;
    void *user_data;
    esp_http_client_config_t http_config;
    int timeout_ms;
    bool secure_connection;
} firebase_config_t;

/**
 * @brief Estructura para solicitud Firebase
 */
typedef struct {
    firebase_operation_t operation;
    char *path;
    firebase_data_value_t *data;
    char *etag;
    bool shallow;
    char *order_by;
    char *equal_to;
    int limit_to_first;
    int limit_to_last;
    char *start_at;
    char *end_at;
} firebase_request_t;

/**
 * @brief Estructura principal para manejar la conexión Firebase
 */
typedef struct {
    firebase_config_t config;
    firebase_state_t state;
    esp_http_client_handle_t http_client;
    char *response_buffer;
    size_t response_buffer_size;
    int http_status;
    esp_timer_handle_t token_refresh_timer;
    firebase_auth_t auth;
} firebase_handle_t;

/**
 * @brief Inicializa la librería Firebase
 *
 * @param config Configuración para la conexión
 * @return firebase_handle_t* Manejador de la conexión o NULL si falla
 */
firebase_handle_t *firebase_init(firebase_config_t *config);

/**
 * @brief Libera recursos utilizados por la librería
 *
 * @param handle Manejador de la conexión
 */
void firebase_deinit(firebase_handle_t *handle);

/**
 * @brief Autenticación con email y contraseña
 *
 * @param handle Manejador de la conexión
 * @param email Email de la cuenta
 * @param password Contraseña de la cuenta
 * @return bool true si la autenticación fue exitosa
 */
bool firebase_auth_with_password(firebase_handle_t *handle, const char *email, const char *password);

/**
 * @brief Autenticación con token personalizado
 *
 * @param handle Manejador de la conexión
 * @param custom_token Token personalizado generado en Firebase
 * @return bool true si la autenticación fue exitosa
 */
bool firebase_auth_with_custom_token(firebase_handle_t *handle, const char *custom_token);

/**
 * @brief Actualiza el token de autenticación
 *
 * @param handle Manejador de la conexión
 * @return bool true si la actualización fue exitosa
 */
bool firebase_refresh_token(firebase_handle_t *handle);

/**
 * @brief Verifica si está autenticado
 *
 * @param handle Manejador de la conexión
 * @return bool true si está autenticado y el token es válido
 */
bool firebase_is_authenticated(firebase_handle_t *handle);

/**
 * @brief Obtiene datos de una ruta específica (GET)
 *
 * @param handle Manejador de la conexión
 * @param path Ruta en la base de datos
 * @param value Puntero donde se almacenará el valor
 * @return bool true si la operación fue exitosa
 */
bool firebase_get(firebase_handle_t *handle, const char *path, firebase_data_value_t *value);

/**
 * @brief Establece datos en una ruta específica (PUT)
 *
 * @param handle Manejador de la conexión
 * @param path Ruta en la base de datos
 * @param value Valor a establecer
 * @return bool true si la operación fue exitosa
 */
bool firebase_set(firebase_handle_t *handle, const char *path, const firebase_data_value_t *value);

/**
 * @brief Actualiza uno o más campos en una ruta específica (PATCH)
 *
 * @param handle Manejador de la conexión
 * @param path Ruta en la base de datos
 * @param value Valor a actualizar (debe ser JSON)
 * @return bool true si la operación fue exitosa
 */
bool firebase_update(firebase_handle_t *handle, const char *path, const firebase_data_value_t *value);

/**
 * @brief Añade datos a una lista generando una clave única (POST)
 *
 * @param handle Manejador de la conexión
 * @param path Ruta en la base de datos
 * @param value Valor a añadir
 * @param generated_key Buffer donde se guardará la clave generada
 * @param key_size Tamaño del buffer para la clave
 * @return bool true si la operación fue exitosa
 */
bool firebase_push(firebase_handle_t *handle, const char *path, const firebase_data_value_t *value, char *generated_key,
                   size_t key_size);

/**
 * @brief Elimina datos de una ruta específica (DELETE)
 *
 * @param handle Manejador de la conexión
 * @param path Ruta en la base de datos
 * @return bool true si la operación fue exitosa
 */
bool firebase_delete(firebase_handle_t *handle, const char *path);

/**
 * @brief Crea un valor de tipo string
 *
 * @param value Estructura donde guardar el valor
 * @param string_data String a guardar
 * @return bool true si se creó correctamente
 */
bool firebase_set_string(firebase_data_value_t *value, const char *string_data);

/**
 * @brief Crea un valor de tipo entero
 *
 * @param value Estructura donde guardar el valor
 * @param int_data Entero a guardar
 * @return bool true si se creó correctamente
 */
bool firebase_set_int(firebase_data_value_t *value, int int_data);

/**
 * @brief Crea un valor de tipo float
 *
 * @param value Estructura donde guardar el valor
 * @param float_data Float a guardar
 * @return bool true si se creó correctamente
 */
bool firebase_set_float(firebase_data_value_t *value, float float_data);

/**
 * @brief Crea un valor de tipo booleano
 *
 * @param value Estructura donde guardar el valor
 * @param bool_data Booleano a guardar
 * @return bool true si se creó correctamente
 */
bool firebase_set_bool(firebase_data_value_t *value, bool bool_data);

/**
 * @brief Crea un valor de tipo JSON
 *
 * @param value Estructura donde guardar el valor
 * @param json_string String JSON a guardar
 * @return bool true si se creó correctamente
 */
bool firebase_set_json(firebase_data_value_t *value, const char *json_string);

/**
 * @brief Libera los recursos utilizados por un valor
 *
 * @param value Valor a liberar
 */
void firebase_free_value(firebase_data_value_t *value);

/**
 * @brief Verifica y mantiene la autenticación periódicamente
 *
 * @param handle Manejador de la conexión
 * @return bool true si la verificación fue exitosa
 */
bool firebase_maintain_auth(firebase_handle_t *handle);

/**
 * @brief Configura una consulta para obtener datos
 *
 * @param request Solicitud a configurar
 * @param order_by Campo para ordenar
 * @param equal_to Valor para filtrar igualdad
 * @param limit_to_first Limitar a primeros N elementos
 * @param limit_to_last Limitar a últimos N elementos
 * @param start_at Valor para iniciar consulta
 * @param end_at Valor para finalizar consulta
 */
void firebase_configure_query(firebase_request_t *request, const char *order_by, const char *equal_to,
                              int limit_to_first, int limit_to_last, const char *start_at, const char *end_at);

/**
 * @brief Configura escucha para cambios en tiempo real
 *
 * @param handle Manejador de la conexión
 * @param path Ruta a escuchar
 * @param callback Función de callback
 * @param user_data Datos a pasar al callback
 * @return int ID de la escucha o -1 si falla
 */
int firebase_listen(firebase_handle_t *handle, const char *path, firebase_event_callback_t callback, void *user_data);

/**
 * @brief Detiene una escucha
 *
 * @param handle Manejador de la conexión
 * @param listen_id ID de la escucha
 * @return bool true si se detuvo correctamente
 */
bool firebase_stop_listen(firebase_handle_t *handle, int listen_id);

#ifdef __cplusplus
}
#endif

#endif /* BI_FIREBASE_H */