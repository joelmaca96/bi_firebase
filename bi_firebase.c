/**
 * @file bi_firebase.c
 * @brief Implementación de la librería para Firebase Realtime Database en ESP32
 */

#include "bi_firebase.h"
#include <cJSON.h>
#include <esp_http_client.h>
#include <esp_log.h>
#include <esp_timer.h>
// #include <esp_tls.h>
#include <esp_wifi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <freertos/task.h>
#include <mbedtls/base64.h>
#include <mbedtls/sha256.h>
#include <stdlib.h>
#include <string.h>

static const char *TAG = "BI_FIREBASE";

#define FIREBASE_TOKEN_REFRESH_TIME_MS (50 * 60 * 1000) // 50 minutos
#define FIREBASE_MAX_RESPONSE_SIZE     4096
#define FIREBASE_HTTP_TIMEOUT_MS       10000
#define FIREBASE_AUTH_URL              "https://identitytoolkit.googleapis.com/v1/accounts"
#define FIREBASE_REFRESH_URL           "https://securetoken.googleapis.com/v1/token"

// Estructura para almacenar el estado de las escuchas
typedef struct firebase_listen_info {
    int id;
    char *path;
    firebase_event_callback_t callback;
    void *user_data;
    bool active;
    struct firebase_listen_info *next;
} firebase_listen_info_t;

// Estructura para ampliar firebase_handle_t con datos privados
typedef struct {
    firebase_handle_t public_handle;
    SemaphoreHandle_t mutex;
    firebase_listen_info_t *listeners;
    int next_listener_id;
    TaskHandle_t listener_task;
    bool listener_running;
} firebase_handle_private_t;

// Funciones estáticas de ayuda

/**
 * Codifica un string a formato URL
 */
static char *url_encode(const char *str) {
    if (!str)
        return NULL;

    const char hex[] = "0123456789ABCDEF";
    size_t len       = strlen(str);
    char *encoded    = malloc(len * 3 + 1); // En el peor caso, cada carácter se codifica como %XX

    if (!encoded)
        return NULL;

    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)str[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' ||
            c == '.' || c == '~') {
            encoded[j++] = c;
        } else if (c == ' ') {
            encoded[j++] = '+';
        } else {
            encoded[j++] = '%';
            encoded[j++] = hex[c >> 4];
            encoded[j++] = hex[c & 15];
        }
    }
    encoded[j] = '\0';

    return encoded;
}

/**
 * Función para manejar eventos HTTP
 */
static esp_err_t http_event_handler(esp_http_client_event_t *evt) {
    firebase_handle_private_t *handle = (firebase_handle_private_t *)evt->user_data;

    switch (evt->event_id) {
    case HTTP_EVENT_ON_DATA:
        // Realocar buffer si es necesario
        if (handle->public_handle.response_buffer == NULL) {
            handle->public_handle.response_buffer = malloc(evt->data_len + 1);
            if (!handle->public_handle.response_buffer) {
                ESP_LOGE(TAG, "No se pudo asignar memoria para la respuesta");
                return ESP_FAIL;
            }
            handle->public_handle.response_buffer_size = evt->data_len;
            memcpy(handle->public_handle.response_buffer, evt->data, evt->data_len);
            handle->public_handle.response_buffer[evt->data_len] = 0;
        } else {
            size_t new_size  = handle->public_handle.response_buffer_size + evt->data_len;
            char *new_buffer = realloc(handle->public_handle.response_buffer, new_size + 1);
            if (!new_buffer) {
                ESP_LOGE(TAG, "No se pudo reasignar memoria para la respuesta");
                return ESP_FAIL;
            }
            handle->public_handle.response_buffer = new_buffer;
            memcpy(handle->public_handle.response_buffer + handle->public_handle.response_buffer_size, evt->data,
                   evt->data_len);
            handle->public_handle.response_buffer_size      = new_size;
            handle->public_handle.response_buffer[new_size] = 0;
        }
        break;
    case HTTP_EVENT_ON_FINISH:
        handle->public_handle.http_status = esp_http_client_get_status_code(evt->client);
        ESP_LOGI(TAG, "HTTP request completada con status: %d", handle->public_handle.http_status);
        break;
    case HTTP_EVENT_DISCONNECTED:
        ESP_LOGI(TAG, "HTTP desconectado");
        if (handle->public_handle.state == FIREBASE_STATE_REQUEST_PENDING) {
            handle->public_handle.state = FIREBASE_STATE_AUTHENTICATED;
        }
        break;
    default: break;
    }
    return ESP_OK;
}

/**
 * Función para limpiar el buffer de respuesta
 */
static void clear_response_buffer(firebase_handle_t *handle) {
    if (handle->response_buffer) {
        free(handle->response_buffer);
        handle->response_buffer      = NULL;
        handle->response_buffer_size = 0;
    }
}

/**
 * Función de callback para el temporizador de renovación de token
 */
static void token_refresh_timer_callback(void *arg) {
    firebase_handle_t *handle = (firebase_handle_t *)arg;
    firebase_refresh_token(handle);
}

/**
 * Parsea una respuesta JSON y extrae los tokens
 */
static bool parse_auth_response(firebase_handle_t *handle, const char *response) {
    cJSON *json = cJSON_Parse(response);
    if (!json) {
        ESP_LOGE(TAG, "Error al parsear respuesta JSON");
        return false;
    }

    bool success = false;

    // Intentar obtener los tokens
    cJSON *id_token      = cJSON_GetObjectItem(json, "idToken");
    cJSON *refresh_token = cJSON_GetObjectItem(json, "refreshToken");
    cJSON *expires_in    = cJSON_GetObjectItem(json, "expiresIn");

    if (id_token && refresh_token && expires_in && cJSON_IsString(id_token) && cJSON_IsString(refresh_token) &&
        cJSON_IsNumber(expires_in)) {

        // Liberar los tokens anteriores si existen
        if (handle->auth.id_token)
            free(handle->auth.id_token);
        if (handle->auth.refresh_token)
            free(handle->auth.refresh_token);

        // Guardar nuevos tokens
        handle->auth.id_token      = strdup(id_token->valuestring);
        handle->auth.refresh_token = strdup(refresh_token->valuestring);

        // Calcular tiempo de expiración (actual + expires_in - margen de seguridad de 5 minutos)
        int64_t current_time      = esp_timer_get_time() / 1000; // Convertir a ms
        handle->auth.token_expiry = current_time + (expires_in->valueint * 1000) - (5 * 60 * 1000);

        ESP_LOGI(TAG, "Tokens de autenticación obtenidos con éxito, expiran en %d segundos", expires_in->valueint);
        success = true;
    } else {
        // Intentar obtener mensaje de error
        cJSON *error = cJSON_GetObjectItem(json, "error");
        if (error) {
            cJSON *message = cJSON_GetObjectItem(error, "message");
            if (message && cJSON_IsString(message)) {
                ESP_LOGE(TAG, "Error de autenticación: %s", message->valuestring);
            }
        } else {
            ESP_LOGE(TAG, "Formato de respuesta de autenticación inválido");
        }
    }

    cJSON_Delete(json);
    return success;
}

/**
 * Realiza una solicitud HTTP
 */
static bool make_http_request(firebase_handle_t *handle, const char *url, const char *method, const char *content_type,
                              const char *data, int data_len) {
    // Reiniciar buffer de respuesta
    clear_response_buffer(handle);

    esp_http_client_config_t config = handle->config.http_config;
    config.url                      = url;
    config.method                   = !method ? HTTP_METHOD_GET
                                              : (strcmp(method, "GET") == 0      ? HTTP_METHOD_GET
                                                 : strcmp(method, "POST") == 0   ? HTTP_METHOD_POST
                                                 : strcmp(method, "PUT") == 0    ? HTTP_METHOD_PUT
                                                 : strcmp(method, "PATCH") == 0  ? HTTP_METHOD_PATCH
                                                 : strcmp(method, "DELETE") == 0 ? HTTP_METHOD_DELETE
                                                                                 : HTTP_METHOD_GET);

    config.timeout_ms    = handle->config.timeout_ms > 0 ? handle->config.timeout_ms : FIREBASE_HTTP_TIMEOUT_MS;
    config.event_handler = http_event_handler;
    config.user_data     = handle;

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        ESP_LOGE(TAG, "Error al inicializar cliente HTTP");
        return false;
    }

    // Establecer cabeceras
    if (content_type) {
        esp_http_client_set_header(client, "Content-Type", content_type);
    }

    // Si estamos autenticados y no es una solicitud de autenticación, usar el token
    if (handle->auth.id_token && strstr(url, "identitytoolkit") == NULL && strstr(url, "securetoken") == NULL) {
        char auth_header[256];
        snprintf(auth_header, sizeof(auth_header), "Bearer %s", handle->auth.id_token);
        esp_http_client_set_header(client, "Authorization", auth_header);
    }

    // Establecer datos si es necesario
    if (data && data_len > 0) {
        esp_http_client_set_post_field(client, data, data_len);
    }

    handle->state = FIREBASE_STATE_REQUEST_PENDING;

    esp_err_t err = esp_http_client_perform(client);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Error HTTP: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        handle->state = FIREBASE_STATE_ERROR;
        return false;
    }

    // Verificar código de estado HTTP
    int status_code     = esp_http_client_get_status_code(client);
    handle->http_status = status_code;

    // Limpiar cliente HTTP
    esp_http_client_cleanup(client);

    if (status_code < 200 || status_code >= 300) {
        ESP_LOGE(TAG, "Error HTTP %d: %s", status_code,
                 handle->response_buffer ? handle->response_buffer : "Sin datos");
        handle->state = FIREBASE_STATE_ERROR;
        return false;
    }

    handle->state = FIREBASE_STATE_AUTHENTICATED;
    return true;
}

/**
 * Construye una URL para Firebase
 */
static char *build_firebase_url(firebase_handle_t *handle, const char *path, const firebase_request_t *request) {
    // Calcular tamaño máximo de la URL
    size_t base_len    = strlen(handle->config.database_url);
    size_t path_len    = path ? strlen(path) : 0;
    size_t max_url_len = base_len + path_len + 256; // Espacio extra para parámetros

    char *url = malloc(max_url_len);
    if (!url)
        return NULL;

    // Construir URL base
    if (path && path[0] == '/') {
        // Quitar la barra inicial para evitar doble barra
        snprintf(url, max_url_len, "%s%s.json", handle->config.database_url, path);
    } else {
        snprintf(url, max_url_len, "%s/%s.json", handle->config.database_url, path ? path : "");
    }

    // Añadir parámetros de consulta si existen
    if (request) {
        char *params_start = url + strlen(url);
        int remaining_len  = max_url_len - strlen(url);
        bool has_params    = false;

        // Añadir auth token como parámetro si existe
        if (handle->auth.id_token) {
            snprintf(params_start, remaining_len, "%sauth=%s", has_params ? "&" : "?", handle->auth.id_token);
            has_params    = true;
            params_start  = url + strlen(url);
            remaining_len = max_url_len - strlen(url);
        }

        // Shallow
        if (request->shallow) {
            snprintf(params_start, remaining_len, "%sshallow=true", has_params ? "&" : "?");
            has_params    = true;
            params_start  = url + strlen(url);
            remaining_len = max_url_len - strlen(url);
        }

        // OrderBy
        if (request->order_by) {
            char *encoded_order = url_encode(request->order_by);
            if (encoded_order) {
                snprintf(params_start, remaining_len, "%sorderBy=\"%s\"", has_params ? "&" : "?", encoded_order);
                free(encoded_order);
                has_params    = true;
                params_start  = url + strlen(url);
                remaining_len = max_url_len - strlen(url);
            }
        }

        // EqualTo
        if (request->equal_to) {
            char *encoded_equal = url_encode(request->equal_to);
            if (encoded_equal) {
                snprintf(params_start, remaining_len, "%sequalTo=\"%s\"", has_params ? "&" : "?", encoded_equal);
                free(encoded_equal);
                has_params    = true;
                params_start  = url + strlen(url);
                remaining_len = max_url_len - strlen(url);
            }
        }

        // LimitToFirst
        if (request->limit_to_first > 0) {
            snprintf(params_start, remaining_len, "%slimitToFirst=%d", has_params ? "&" : "?", request->limit_to_first);
            has_params    = true;
            params_start  = url + strlen(url);
            remaining_len = max_url_len - strlen(url);
        }

        // LimitToLast
        if (request->limit_to_last > 0) {
            snprintf(params_start, remaining_len, "%slimitToLast=%d", has_params ? "&" : "?", request->limit_to_last);
            has_params    = true;
            params_start  = url + strlen(url);
            remaining_len = max_url_len - strlen(url);
        }

        // StartAt
        if (request->start_at) {
            char *encoded_start = url_encode(request->start_at);
            if (encoded_start) {
                snprintf(params_start, remaining_len, "%sstartAt=\"%s\"", has_params ? "&" : "?", encoded_start);
                free(encoded_start);
                has_params    = true;
                params_start  = url + strlen(url);
                remaining_len = max_url_len - strlen(url);
            }
        }

        // EndAt
        if (request->end_at) {
            char *encoded_end = url_encode(request->end_at);
            if (encoded_end) {
                snprintf(params_start, remaining_len, "%sendAt=\"%s\"", has_params ? "&" : "?", encoded_end);
                free(encoded_end);
                has_params = true;
            }
        }
    }

    return url;
}

/**
 * Convierte un valor a formato JSON
 */
static cJSON *value_to_json(const firebase_data_value_t *value) {
    if (!value)
        return NULL;

    switch (value->type) {
    case FIREBASE_DATA_TYPE_STRING: return cJSON_CreateString(value->data.string_val ? value->data.string_val : "");

    case FIREBASE_DATA_TYPE_INT: return cJSON_CreateNumber(value->data.int_val);

    case FIREBASE_DATA_TYPE_FLOAT: return cJSON_CreateNumber(value->data.float_val);

    case FIREBASE_DATA_TYPE_BOOL: return cJSON_CreateBool(value->data.bool_val);

    case FIREBASE_DATA_TYPE_JSON:
        if (value->data.string_val) {
            return cJSON_Parse(value->data.string_val);
        }
        return NULL;

    case FIREBASE_DATA_TYPE_NULL: return cJSON_CreateNull();

    default: return NULL;
    }
}

/**
 * Convierte un JSON a valor Firebase
 */
static bool json_to_value(cJSON *json, firebase_data_value_t *value) {
    if (!json || !value)
        return false;

    memset(value, 0, sizeof(firebase_data_value_t));

    if (cJSON_IsString(json)) {
        value->type            = FIREBASE_DATA_TYPE_STRING;
        value->data.string_val = strdup(json->valuestring);
        return true;
    } else if (cJSON_IsNumber(json)) {
        // Ver si es entero o float
        double num = json->valuedouble;
        if (num == (int)num) {
            value->type         = FIREBASE_DATA_TYPE_INT;
            value->data.int_val = (int)num;
        } else {
            value->type           = FIREBASE_DATA_TYPE_FLOAT;
            value->data.float_val = (float)num;
        }
        return true;
    } else if (cJSON_IsBool(json)) {
        value->type          = FIREBASE_DATA_TYPE_BOOL;
        value->data.bool_val = cJSON_IsTrue(json);
        return true;
    } else if (cJSON_IsNull(json)) {
        value->type = FIREBASE_DATA_TYPE_NULL;
        return true;
    } else if (cJSON_IsObject(json) || cJSON_IsArray(json)) {
        value->type    = FIREBASE_DATA_TYPE_JSON;
        char *json_str = cJSON_PrintUnformatted(json);
        if (json_str) {
            value->data.string_val = json_str;
            return true;
        }
    }

    return false;
}

/**
 * Tarea para escuchar eventos de Firebase
 */
static void firebase_listener_task(void *pvParameters) {
    firebase_handle_private_t *handle = (firebase_handle_private_t *)pvParameters;

    ESP_LOGI(TAG, "Tarea de escucha de Firebase iniciada");

    while (handle->listener_running) {
        // Verificar si hay listeners activos
        bool has_active_listeners = false;

        xSemaphoreTake(handle->mutex, portMAX_DELAY);
        firebase_listen_info_t *listener = handle->listeners;
        while (listener) {
            if (listener->active) {
                has_active_listeners = true;
                break;
            }
            listener = listener->next;
        }
        xSemaphoreGive(handle->mutex);

        if (!has_active_listeners) {
            // No hay listeners activos, esperar
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }

        // Verificar autenticación
        if (!firebase_is_authenticated(&handle->public_handle)) {
            ESP_LOGW(TAG, "No autenticado, intentando renovar token...");
            firebase_refresh_token(&handle->public_handle);
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }

        // Procesar cada listener activo
        xSemaphoreTake(handle->mutex, portMAX_DELAY);
        listener = handle->listeners;
        while (listener && handle->listener_running) {
            if (listener->active) {
                // Liberar mutex durante la solicitud HTTP
                xSemaphoreGive(handle->mutex);

                // Construir URL para escuchar cambios
                char *url = build_firebase_url(&handle->public_handle, listener->path, NULL);
                if (url) {
                    ESP_LOGI(TAG, "Escuchando cambios en %s", url);

                    firebase_data_value_t value;
                    memset(&value, 0, sizeof(value));

                    if (make_http_request(&handle->public_handle, url, "GET", NULL, NULL, 0) &&
                        handle->public_handle.response_buffer) {

                        cJSON *json = cJSON_Parse(handle->public_handle.response_buffer);
                        if (json) {
                            if (json_to_value(json, &value)) {
                                // Notificar cambio
                                if (listener->callback) {
                                    listener->callback(listener->user_data, listener->id);
                                }
                            }
                            cJSON_Delete(json);
                        }

                        firebase_free_value(&value);
                    }

                    free(url);
                }

                // Volver a tomar mutex
                xSemaphoreTake(handle->mutex, portMAX_DELAY);
            }

            listener = listener->next;
        }
        xSemaphoreGive(handle->mutex);

        // Esperar antes de la siguiente verificación
        vTaskDelay(pdMS_TO_TICKS(2000));
    }

    ESP_LOGI(TAG, "Tarea de escucha de Firebase finalizada");
    handle->listener_task = NULL;
    vTaskDelete(NULL);
}

// Implementación de funciones públicas

firebase_handle_t *firebase_init(firebase_config_t *config) {
    if (!config || !config->database_url) {
        ESP_LOGE(TAG, "Configuración inválida");
        return NULL;
    }

    firebase_handle_private_t *handle = calloc(1, sizeof(firebase_handle_private_t));
    if (!handle) {
        ESP_LOGE(TAG, "No se pudo asignar memoria para handle");
        return NULL;
    }

    // Copiar configuración
    handle->public_handle.config.database_url   = strdup(config->database_url);
    handle->public_handle.config.host           = config->host ? strdup(config->host) : NULL;
    handle->public_handle.config.event_callback = config->event_callback;
    handle->public_handle.config.user_data      = config->user_data;
    handle->public_handle.config.http_config    = config->http_config;
    handle->public_handle.config.timeout_ms = config->timeout_ms > 0 ? config->timeout_ms : FIREBASE_HTTP_TIMEOUT_MS;
    handle->public_handle.config.secure_connection = config->secure_connection;

    // Copiar información de autenticación
    handle->public_handle.auth.auth_type     = config->auth.auth_type;
    handle->public_handle.auth.api_key       = config->auth.api_key ? strdup(config->auth.api_key) : NULL;
    handle->public_handle.auth.user_email    = config->auth.user_email ? strdup(config->auth.user_email) : NULL;
    handle->public_handle.auth.user_password = config->auth.user_password ? strdup(config->auth.user_password) : NULL;
    handle->public_handle.auth.custom_token  = config->auth.custom_token ? strdup(config->auth.custom_token) : NULL;
    handle->public_handle.auth.id_token      = config->auth.id_token ? strdup(config->auth.id_token) : NULL;
    handle->public_handle.auth.refresh_token = config->auth.refresh_token ? strdup(config->auth.refresh_token) : NULL;
    handle->public_handle.auth.token_expiry  = config->auth.token_expiry;

    // Inicializar el estado
    handle->public_handle.state = FIREBASE_STATE_INIT;
    handle->mutex               = xSemaphoreCreateMutex();

    if (!handle->mutex) {
        ESP_LOGE(TAG, "Error al crear mutex");
        firebase_deinit(&handle->public_handle);
        return NULL;
    }

    // Crear timer para refrescar el token
    esp_timer_create_args_t timer_args = {
        .callback = token_refresh_timer_callback, .arg = &handle->public_handle, .name = "firebase_token_refresh"};

    if (esp_timer_create(&timer_args, &handle->public_handle.token_refresh_timer) != ESP_OK) {
        ESP_LOGE(TAG, "Error al crear timer de refresco de token");
        firebase_deinit(&handle->public_handle);
        return NULL;
    }

    // Iniciar timer de refresco de token
    esp_timer_start_periodic(handle->public_handle.token_refresh_timer, FIREBASE_TOKEN_REFRESH_TIME_MS);

    // Iniciar tarea de escucha
    handle->listener_running = true;
    handle->next_listener_id = 1;

    xTaskCreate(firebase_listener_task, "firebase_listener", 4096, handle, 5, &handle->listener_task);

    ESP_LOGI(TAG, "Firebase inicializado correctamente");
    return &handle->public_handle;
}

void firebase_deinit(firebase_handle_t *handle) {
    if (!handle)
        return;

    firebase_handle_private_t *private_handle = (firebase_handle_private_t *)handle;

    // Detener la tarea de escucha
    if (private_handle->listener_running) {
        private_handle->listener_running = false;

        // Esperar a que la tarea termine
        int timeout = 10; // 1 segundo
        while (private_handle->listener_task && timeout-- > 0) {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
    }

    // Detener timer de refresco de token
    if (handle->token_refresh_timer) {
        esp_timer_stop(handle->token_refresh_timer);
        esp_timer_delete(handle->token_refresh_timer);
    }

    // Liberar recursos de autenticación
    if (handle->auth.api_key)
        free(handle->auth.api_key);
    if (handle->auth.user_email)
        free(handle->auth.user_email);
    if (handle->auth.user_password)
        free(handle->auth.user_password);
    if (handle->auth.custom_token)
        free(handle->auth.custom_token);
    if (handle->auth.id_token)
        free(handle->auth.id_token);
    if (handle->auth.refresh_token)
        free(handle->auth.refresh_token);

    // Liberar configuración
    if (handle->config.database_url)
        free(handle->config.database_url);
    if (handle->config.host)
        free(handle->config.host);

    // Liberar buffer de respuesta
    clear_response_buffer(handle);

    // Liberar listeners
    firebase_listen_info_t *listener = private_handle->listeners;
    while (listener) {
        firebase_listen_info_t *next = listener->next;
        if (listener->path)
            free(listener->path);
        free(listener);
        listener = next;
    }

    // Liberar mutex
    if (private_handle->mutex) {
        vSemaphoreDelete(private_handle->mutex);
    }

    // Liberar handle
    free(private_handle);

    ESP_LOGI(TAG, "Firebase liberado correctamente");
}

bool firebase_auth_with_password(firebase_handle_t *handle, const char *email, const char *password) {
    if (!handle || !email || !password || !handle->config.database_url || !handle->auth.api_key) {
        ESP_LOGE(TAG, "Parámetros inválidos para autenticación");
        return false;
    }

    handle->state = FIREBASE_STATE_AUTHENTICATING;

    // Construir URL de autenticación
    char url[256];
    snprintf(url, sizeof(url), "%s:signInWithPassword?key=%s", FIREBASE_AUTH_URL, handle->auth.api_key);

    // Construir payload JSON
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "email", email);
    cJSON_AddStringToObject(json, "password", password);
    cJSON_AddBoolToObject(json, "returnSecureToken", true);

    char *payload = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);

    if (!payload) {
        ESP_LOGE(TAG, "Error al crear payload JSON");
        handle->state = FIREBASE_STATE_ERROR;
        return false;
    }

    // Realizar solicitud HTTP
    bool success = make_http_request(handle, url, "POST", "application/json", payload, strlen(payload));
    free(payload);

    if (!success || !handle->response_buffer) {
        ESP_LOGE(TAG, "Error en solicitud de autenticación");
        handle->state = FIREBASE_STATE_ERROR;
        return false;
    }

    // Parsear respuesta
    if (!parse_auth_response(handle, handle->response_buffer)) {
        ESP_LOGE(TAG, "Error al parsear respuesta de autenticación");
        handle->state = FIREBASE_STATE_ERROR;
        return false;
    }

    // Guardar credenciales
    if (handle->auth.user_email)
        free(handle->auth.user_email);
    if (handle->auth.user_password)
        free(handle->auth.user_password);

    handle->auth.user_email    = strdup(email);
    handle->auth.user_password = strdup(password);
    handle->auth.auth_type     = FIREBASE_AUTH_API_KEY;

    handle->state = FIREBASE_STATE_AUTHENTICATED;
    ESP_LOGI(TAG, "Autenticación exitosa con email/password");

    return true;
}

bool firebase_auth_with_custom_token(firebase_handle_t *handle, const char *custom_token) {
    if (!handle || !custom_token || !handle->config.database_url || !handle->auth.api_key) {
        ESP_LOGE(TAG, "Parámetros inválidos para autenticación");
        return false;
    }

    handle->state = FIREBASE_STATE_AUTHENTICATING;

    // Construir URL de autenticación
    char url[256];
    snprintf(url, sizeof(url), "%s:signInWithCustomToken?key=%s", FIREBASE_AUTH_URL, handle->auth.api_key);

    // Construir payload JSON
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "token", custom_token);
    cJSON_AddBoolToObject(json, "returnSecureToken", true);

    char *payload = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);

    if (!payload) {
        ESP_LOGE(TAG, "Error al crear payload JSON");
        handle->state = FIREBASE_STATE_ERROR;
        return false;
    }

    // Realizar solicitud HTTP
    bool success = make_http_request(handle, url, "POST", "application/json", payload, strlen(payload));
    free(payload);

    if (!success || !handle->response_buffer) {
        ESP_LOGE(TAG, "Error en solicitud de autenticación");
        handle->state = FIREBASE_STATE_ERROR;
        return false;
    }

    // Parsear respuesta
    if (!parse_auth_response(handle, handle->response_buffer)) {
        ESP_LOGE(TAG, "Error al parsear respuesta de autenticación");
        handle->state = FIREBASE_STATE_ERROR;
        return false;
    }

    // Guardar credenciales
    if (handle->auth.custom_token)
        free(handle->auth.custom_token);
    handle->auth.custom_token = strdup(custom_token);
    handle->auth.auth_type    = FIREBASE_AUTH_CUSTOM_TOKEN;

    handle->state = FIREBASE_STATE_AUTHENTICATED;
    ESP_LOGI(TAG, "Autenticación exitosa con token personalizado");

    return true;
}

bool firebase_refresh_token(firebase_handle_t *handle) {
    if (!handle || !handle->auth.refresh_token || !handle->auth.api_key) {
        ESP_LOGW(TAG, "No se puede refrescar el token: falta refresh_token o api_key");
        return false;
    }

    // Si aún no ha expirado, no refrescar
    int64_t current_time = esp_timer_get_time() / 1000; // Convertir a ms
    if (handle->auth.token_expiry > current_time) {
        ESP_LOGI(TAG, "Token aún válido, no es necesario refrescarlo");
        return true;
    }

    ESP_LOGI(TAG, "Refrescando token de autenticación");

    // Construir URL de refresco
    char url[256];
    snprintf(url, sizeof(url), "%s?key=%s", FIREBASE_REFRESH_URL, handle->auth.api_key);

    // Construir payload JSON
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "grant_type", "refresh_token");
    cJSON_AddStringToObject(json, "refresh_token", handle->auth.refresh_token);

    char *payload = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);

    if (!payload) {
        ESP_LOGE(TAG, "Error al crear payload JSON");
        return false;
    }

    // Realizar solicitud HTTP
    bool success = make_http_request(handle, url, "POST", "application/json", payload, strlen(payload));
    free(payload);

    if (!success || !handle->response_buffer) {
        ESP_LOGE(TAG, "Error en solicitud de refresco de token");
        return false;
    }

    // Parsear respuesta
    cJSON *resp_json = cJSON_Parse(handle->response_buffer);
    if (!resp_json) {
        ESP_LOGE(TAG, "Error al parsear respuesta de refresco de token");
        return false;
    }

    bool refresh_success = false;

    // Intentar obtener los tokens
    cJSON *id_token      = cJSON_GetObjectItem(resp_json, "id_token");
    cJSON *refresh_token = cJSON_GetObjectItem(resp_json, "refresh_token");
    cJSON *expires_in    = cJSON_GetObjectItem(resp_json, "expires_in");

    if (id_token && refresh_token && expires_in && cJSON_IsString(id_token) && cJSON_IsString(refresh_token) &&
        cJSON_IsNumber(expires_in)) {

        // Liberar los tokens anteriores si existen
        if (handle->auth.id_token)
            free(handle->auth.id_token);
        if (handle->auth.refresh_token)
            free(handle->auth.refresh_token);

        // Guardar nuevos tokens
        handle->auth.id_token      = strdup(id_token->valuestring);
        handle->auth.refresh_token = strdup(refresh_token->valuestring);

        // Calcular tiempo de expiración (actual + expires_in - margen de seguridad de 5 minutos)
        int64_t current_time      = esp_timer_get_time() / 1000; // Convertir a ms
        handle->auth.token_expiry = current_time + (expires_in->valueint * 1000) - (5 * 60 * 1000);

        ESP_LOGI(TAG, "Token refrescado con éxito, expira en %d segundos", expires_in->valueint);
        refresh_success = true;
    } else {
        // Intentar reautenticarse si el refresco falla
        if (handle->auth.auth_type == FIREBASE_AUTH_API_KEY && handle->auth.user_email && handle->auth.user_password) {

            ESP_LOGW(TAG, "Refresco de token falló, intentando reautenticarse");
            refresh_success = firebase_auth_with_password(handle, handle->auth.user_email, handle->auth.user_password);
        } else if (handle->auth.auth_type == FIREBASE_AUTH_CUSTOM_TOKEN && handle->auth.custom_token) {
            ESP_LOGW(TAG, "Refresco de token falló, intentando reautenticarse");
            refresh_success = firebase_auth_with_custom_token(handle, handle->auth.custom_token);
        }
    }

    cJSON_Delete(resp_json);
    return refresh_success;
}

bool firebase_is_authenticated(firebase_handle_t *handle) {
    if (!handle || !handle->auth.id_token || !handle->auth.refresh_token) {
        return false;
    }

    // Verificar si el token ha expirado
    int64_t current_time = esp_timer_get_time() / 1000; // Convertir a ms
    if (handle->auth.token_expiry <= current_time) {
        ESP_LOGW(TAG, "Token expirado");
        return false;
    }

    return true;
}

bool firebase_maintain_auth(firebase_handle_t *handle) {
    if (!handle)
        return false;

    if (!firebase_is_authenticated(handle)) {
        return firebase_refresh_token(handle);
    }

    return true;
}

bool firebase_get(firebase_handle_t *handle, const char *path, firebase_data_value_t *value) {
    if (!handle || !path || !value) {
        ESP_LOGE(TAG, "Parámetros inválidos para GET");
        return false;
    }

    // Verificar autenticación
    if (!firebase_maintain_auth(handle)) {
        ESP_LOGE(TAG, "Error de autenticación");
        return false;
    }

    // Construir URL
    char *url = build_firebase_url(handle, path, NULL);
    if (!url) {
        ESP_LOGE(TAG, "Error al construir URL");
        return false;
    }

    ESP_LOGI(TAG, "Realizando GET en %s", url);

    // Realizar solicitud HTTP
    bool success = make_http_request(handle, url, "GET", NULL, NULL, 0);
    free(url);

    if (!success || !handle->response_buffer) {
        ESP_LOGE(TAG, "Error en solicitud GET");
        return false;
    }

    // Parsear respuesta JSON
    cJSON *json = cJSON_Parse(handle->response_buffer);
    if (!json) {
        ESP_LOGE(TAG, "Error al parsear respuesta JSON: %s", handle->response_buffer);
        return false;
    }

    // Convertir JSON a valor Firebase
    bool parse_success = json_to_value(json, value);
    cJSON_Delete(json);

    if (!parse_success) {
        ESP_LOGE(TAG, "Error al convertir JSON a valor Firebase");
        return false;
    }

    return true;
}

bool firebase_set(firebase_handle_t *handle, const char *path, const firebase_data_value_t *value) {
    if (!handle || !path || !value) {
        ESP_LOGE(TAG, "Parámetros inválidos para SET");
        return false;
    }

    // Verificar autenticación
    if (!firebase_maintain_auth(handle)) {
        ESP_LOGE(TAG, "Error de autenticación");
        return false;
    }

    // Construir URL
    char *url = build_firebase_url(handle, path, NULL);
    if (!url) {
        ESP_LOGE(TAG, "Error al construir URL");
        return false;
    }

    // Convertir valor a JSON
    cJSON *json = value_to_json(value);
    if (!json) {
        ESP_LOGE(TAG, "Error al convertir valor a JSON");
        free(url);
        return false;
    }

    char *payload = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);

    if (!payload) {
        ESP_LOGE(TAG, "Error al serializar JSON");
        free(url);
        return false;
    }

    ESP_LOGI(TAG, "Realizando PUT en %s: %s", url, payload);

    // Realizar solicitud HTTP
    bool success = make_http_request(handle, url, "PUT", "application/json", payload, strlen(payload));

    free(url);
    free(payload);

    if (!success) {
        ESP_LOGE(TAG, "Error en solicitud PUT");
        return false;
    }

    return true;
}

bool firebase_update(firebase_handle_t *handle, const char *path, const firebase_data_value_t *value) {
    if (!handle || !path || !value || value->type != FIREBASE_DATA_TYPE_JSON) {
        ESP_LOGE(TAG, "Parámetros inválidos para UPDATE (debe ser JSON)");
        return false;
    }

    // Verificar autenticación
    if (!firebase_maintain_auth(handle)) {
        ESP_LOGE(TAG, "Error de autenticación");
        return false;
    }

    // Construir URL
    char *url = build_firebase_url(handle, path, NULL);
    if (!url) {
        ESP_LOGE(TAG, "Error al construir URL");
        return false;
    }

    ESP_LOGI(TAG, "Realizando PATCH en %s: %s", url, value->data.string_val);

    // Realizar solicitud HTTP
    bool success = make_http_request(handle, url, "PATCH", "application/json", value->data.string_val,
                                     strlen(value->data.string_val));

    free(url);

    if (!success) {
        ESP_LOGE(TAG, "Error en solicitud PATCH");
        return false;
    }

    return true;
}

bool firebase_push(firebase_handle_t *handle, const char *path, const firebase_data_value_t *value, char *generated_key,
                   size_t key_size) {
    if (!handle || !path || !value) {
        ESP_LOGE(TAG, "Parámetros inválidos para PUSH");
        return false;
    }

    // Verificar autenticación
    if (!firebase_maintain_auth(handle)) {
        ESP_LOGE(TAG, "Error de autenticación");
        return false;
    }

    // Construir URL
    char *url = build_firebase_url(handle, path, NULL);
    if (!url) {
        ESP_LOGE(TAG, "Error al construir URL");
        return false;
    }

    // Convertir valor a JSON
    cJSON *json = value_to_json(value);
    if (!json) {
        ESP_LOGE(TAG, "Error al convertir valor a JSON");
        free(url);
        return false;
    }

    char *payload = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);

    if (!payload) {
        ESP_LOGE(TAG, "Error al serializar JSON");
        free(url);
        return false;
    }

    ESP_LOGI(TAG, "Realizando POST en %s: %s", url, payload);

    // Realizar solicitud HTTP
    bool success = make_http_request(handle, url, "POST", "application/json", payload, strlen(payload));

    free(url);
    free(payload);

    if (!success || !handle->response_buffer) {
        ESP_LOGE(TAG, "Error en solicitud POST");
        return false;
    }

    // Extraer clave generada
    if (generated_key && key_size > 0) {
        cJSON *json_response = cJSON_Parse(handle->response_buffer);
        if (json_response) {
            cJSON *name = cJSON_GetObjectItem(json_response, "name");
            if (name && cJSON_IsString(name)) {
                strncpy(generated_key, name->valuestring, key_size - 1);
                generated_key[key_size - 1] = '\0';
                ESP_LOGI(TAG, "Clave generada: %s", generated_key);
            } else {
                generated_key[0] = '\0';
            }
            cJSON_Delete(json_response);
        } else {
            generated_key[0] = '\0';
        }
    }

    return true;
}

bool firebase_delete(firebase_handle_t *handle, const char *path) {
    if (!handle || !path) {
        ESP_LOGE(TAG, "Parámetros inválidos para DELETE");
        return false;
    }

    // Verificar autenticación
    if (!firebase_maintain_auth(handle)) {
        ESP_LOGE(TAG, "Error de autenticación");
        return false;
    }

    // Construir URL
    char *url = build_firebase_url(handle, path, NULL);
    if (!url) {
        ESP_LOGE(TAG, "Error al construir URL");
        return false;
    }

    ESP_LOGI(TAG, "Realizando DELETE en %s", url);

    // Realizar solicitud HTTP
    bool success = make_http_request(handle, url, "DELETE", NULL, NULL, 0);

    free(url);

    if (!success) {
        ESP_LOGE(TAG, "Error en solicitud DELETE");
        return false;
    }

    return true;
}

bool firebase_set_string(firebase_data_value_t *value, const char *string_data) {
    if (!value || !string_data)
        return false;

    // Liberar dato anterior si existe
    firebase_free_value(value);

    value->type            = FIREBASE_DATA_TYPE_STRING;
    value->data.string_val = strdup(string_data);

    return value->data.string_val != NULL;
}

bool firebase_set_int(firebase_data_value_t *value, int int_data) {
    if (!value)
        return false;

    // Liberar dato anterior si existe
    firebase_free_value(value);

    value->type         = FIREBASE_DATA_TYPE_INT;
    value->data.int_val = int_data;

    return true;
}

bool firebase_set_float(firebase_data_value_t *value, float float_data) {
    if (!value)
        return false;

    // Liberar dato anterior si existe
    firebase_free_value(value);

    value->type           = FIREBASE_DATA_TYPE_FLOAT;
    value->data.float_val = float_data;

    return true;
}

bool firebase_set_bool(firebase_data_value_t *value, bool bool_data) {
    if (!value)
        return false;

    // Liberar dato anterior si existe
    firebase_free_value(value);

    value->type          = FIREBASE_DATA_TYPE_BOOL;
    value->data.bool_val = bool_data;

    return true;
}

bool firebase_set_json(firebase_data_value_t *value, const char *json_string) {
    if (!value || !json_string)
        return false;

    // Validar que sea un JSON válido
    cJSON *json = cJSON_Parse(json_string);
    if (!json) {
        ESP_LOGE(TAG, "JSON inválido");
        return false;
    }
    cJSON_Delete(json);

    // Liberar dato anterior si existe
    firebase_free_value(value);

    value->type            = FIREBASE_DATA_TYPE_JSON;
    value->data.string_val = strdup(json_string);

    return value->data.string_val != NULL;
}

void firebase_free_value(firebase_data_value_t *value) {
    if (!value)
        return;

    // Liberar memoria según el tipo de dato
    switch (value->type) {
    case FIREBASE_DATA_TYPE_STRING:
    case FIREBASE_DATA_TYPE_JSON:
        if (value->data.string_val) {
            free(value->data.string_val);
            value->data.string_val = NULL;
        }
        break;

    case FIREBASE_DATA_TYPE_ARRAY:
        if (value->data.blob_val) {
            free(value->data.blob_val);
            value->data.blob_val = NULL;
        }
        break;

    default:
        // Otros tipos no requieren liberación
        break;
    }

    // Reiniciar tipo y tamaño
    value->type      = FIREBASE_DATA_TYPE_NULL;
    value->data_size = 0;
}

void firebase_configure_query(firebase_request_t *request, const char *order_by, const char *equal_to,
                              int limit_to_first, int limit_to_last, const char *start_at, const char *end_at) {
    if (!request)
        return;

    // Limpiar valores anteriores
    if (request->order_by) {
        free(request->order_by);
        request->order_by = NULL;
    }

    if (request->equal_to) {
        free(request->equal_to);
        request->equal_to = NULL;
    }

    if (request->start_at) {
        free(request->start_at);
        request->start_at = NULL;
    }

    if (request->end_at) {
        free(request->end_at);
        request->end_at = NULL;
    }

    // Establecer nuevos valores
    request->order_by       = order_by ? strdup(order_by) : NULL;
    request->equal_to       = equal_to ? strdup(equal_to) : NULL;
    request->limit_to_first = limit_to_first;
    request->limit_to_last  = limit_to_last;
    request->start_at       = start_at ? strdup(start_at) : NULL;
    request->end_at         = end_at ? strdup(end_at) : NULL;
}

int firebase_listen(firebase_handle_t *handle, const char *path, firebase_event_callback_t callback, void *user_data) {
    if (!handle || !path || !callback) {
        ESP_LOGE(TAG, "Parámetros inválidos para LISTEN");
        return -1;
    }

    firebase_handle_private_t *private_handle = (firebase_handle_private_t *)handle;

    // Verificar que la tarea listener esté en ejecución
    if (!private_handle->listener_running || !private_handle->listener_task) {
        ESP_LOGE(TAG, "Tarea de escucha no está en ejecución");
        return -1;
    }

    // Crear nueva estructura de listener
    firebase_listen_info_t *new_listener = calloc(1, sizeof(firebase_listen_info_t));
    if (!new_listener) {
        ESP_LOGE(TAG, "No se pudo asignar memoria para listener");
        return -1;
    }

    new_listener->id        = private_handle->next_listener_id++;
    new_listener->path      = strdup(path);
    new_listener->callback  = callback;
    new_listener->user_data = user_data;
    new_listener->active    = true;

    // Añadir a la lista de listeners
    xSemaphoreTake(private_handle->mutex, portMAX_DELAY);

    new_listener->next        = private_handle->listeners;
    private_handle->listeners = new_listener;

    xSemaphoreGive(private_handle->mutex);

    ESP_LOGI(TAG, "Listener registrado con ID %d para la ruta %s", new_listener->id, path);

    return new_listener->id;
}

bool firebase_stop_listen(firebase_handle_t *handle, int listen_id) {
    if (!handle || listen_id < 0) {
        ESP_LOGE(TAG, "Parámetros inválidos para STOP_LISTEN");
        return false;
    }

    firebase_handle_private_t *private_handle = (firebase_handle_private_t *)handle;
    bool found                                = false;

    // Buscar el listener por ID
    xSemaphoreTake(private_handle->mutex, portMAX_DELAY);

    firebase_listen_info_t *current = private_handle->listeners;
    firebase_listen_info_t *prev    = NULL;

    while (current) {
        if (current->id == listen_id) {
            // Encontrado - eliminar de la lista
            if (prev) {
                prev->next = current->next;
            } else {
                private_handle->listeners = current->next;
            }

            ESP_LOGI(TAG, "Listener %d detenido", listen_id);

            if (current->path)
                free(current->path);
            free(current);

            found = true;
            break;
        }

        prev    = current;
        current = current->next;
    }

    xSemaphoreGive(private_handle->mutex);

    if (!found) {
        ESP_LOGW(TAG, "Listener %d no encontrado", listen_id);
    }

    return found;
}