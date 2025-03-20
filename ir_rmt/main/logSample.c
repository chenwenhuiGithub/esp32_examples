#include "esp_log.h"
#include "esp_err.h"
#include "esp_http_server.h"
#include "logSample.h"


static const char *TAG = "logSample";
httpd_handle_t s_hd_httpd = NULL;
static int s_fd = 0;

static int log_sample_vprintf(const char *format, va_list args) {  
    static uint8_t payload[CONFIG_LOGSAMPLE_LOG_MAX_LENGTH] = {0};
    static httpd_ws_frame_t ws_frame = {
        .type = HTTPD_WS_TYPE_TEXT,
        .payload = payload,
    }; 
    size_t len = 0;

    len = vsnprintf((char *)ws_frame.payload, sizeof(payload), format, args);
    ws_frame.len = len;
    httpd_ws_send_data(s_hd_httpd, s_fd, &ws_frame);
    return len;
}

static void log_sample_start() {
    esp_log_set_vprintf(&log_sample_vprintf);
}

static void log_sample_stop() {
    esp_log_set_vprintf(&vprintf);
}

esp_err_t http_get_logSample_handler(httpd_req_t *req) {
    uint8_t payload[16] = {0};
    httpd_ws_frame_t ws_frame = {
        .payload = payload,
    }; 

    if (HTTP_GET == req->method) {
        ESP_LOGI(TAG, "handshake done");
        return ESP_OK;
    }

    s_fd = httpd_req_to_sockfd(req);
    httpd_ws_recv_frame(req, &ws_frame, sizeof(payload));
    ESP_LOGI(TAG, "s_fd:%d payload:%s", s_fd, ws_frame.payload);
    if (0 == memcmp(ws_frame.payload, "start", strlen("start"))) {
        log_sample_start();
    } else if (0 == memcmp(ws_frame.payload, "stop", strlen("stop"))) {
        log_sample_stop();
    }

    return ESP_OK;
}

void logSample_init() {
    esp_err_t err = ESP_OK;
    httpd_config_t httpd_cfg = HTTPD_DEFAULT_CONFIG();
    const httpd_uri_t uri_get_logSample = {
        .uri       = "/logSample",
        .method    = HTTP_GET,
        .handler   = http_get_logSample_handler,
        .user_ctx  = NULL,
        .is_websocket = true,
        .handle_ws_control_frames = false
    };

    err = httpd_start(&s_hd_httpd, &httpd_cfg);
    if (ESP_OK == err) {
        httpd_register_uri_handler(s_hd_httpd, &uri_get_logSample);
        ESP_LOGI(TAG, "websocket server start success, port:%d", httpd_cfg.server_port);
    } else {
        ESP_LOGE(TAG, "websocket server start error:%d", err);
    }
}
