#include "esp_log.h"
#include "esp_http_client.h"
#include "esp_ota_ops.h"
#include "esp_app_format.h"
#include "esp_app_desc.h"
#include "mbedtls/md.h"
#include "mbedtls/ssl.h"
#include "cJSON.h"
#include "cloud.h"
#include "ota.h"


typedef struct {
    char url[256];
    char version[16];
    char sha256[65]; // hexstring
    uint32_t size;
} ota_task_t;

extern const char remote_server_root_crt_start[]    asm("_binary_remote_server_root_crt_start");
extern const char remote_server_root_crt_end[]      asm("_binary_remote_server_root_crt_end");

extern const uint8_t ota_sign_pub_key_start[]       asm("_binary_ota_sign_pub_key_start");
extern const uint8_t ota_sign_pub_key_end[]         asm("_binary_ota_sign_pub_key_end");


static const char *TAG = "ota";
static ota_task_t s_ota_task = {0};
static esp_ota_handle_t s_hd_ota = 0;
static esp_http_client_handle_t s_hd_http = NULL;
static uint32_t s_download_size = 0;
static char s_ota_buf[CONFIG_OTA_DOWNLOAD_BUF_SIZE] = {0};


static void ota_progress_cb(void *pvParameters) {
    uint8_t progress = 0;
    static uint8_t last_progress = 0;
    char buf[256] = {0};
    
    while (1) {
        progress = s_download_size * 100 / s_ota_task.size;
        if (last_progress != progress) {
            sprintf(buf, "{\"id\":\"%s\", \"params\":{\"step\":\"%u\", \"desc\":\"success\"}}", cloud_gen_msg_id(), progress);
            cloud_publish(CONFIG_TOPIC_OTA_PROGRESS, (uint8_t *)buf, strlen(buf), 0);
            last_progress = progress;
            ESP_LOGI(TAG, "report progress: %u%%", progress);     
        }
        if (100 == progress) {
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(CONFIG_OTA_REPORT_PROGRESS_MS));
    }

    vTaskDelete(NULL);
}

static void ota_download_cb(void *pvParameters) {
    esp_err_t err = ESP_OK;
    const esp_partition_t *part_ota = NULL;
    int len = 0;
    esp_app_desc_t app_desc = {0};
    uint8_t retry = 0;
    uint8_t sha256[32] = {0};
    char sha256_hexstring[65] = {0};
    mbedtls_md_context_t md_ctx;
    esp_http_client_config_t http_cfg = {
        .url = s_ota_task.url,
        .method = HTTP_METHOD_GET,
        .cert_pem = remote_server_root_crt_start,
        .cert_len = remote_server_root_crt_end - remote_server_root_crt_start
    };

    part_ota = esp_ota_get_next_update_partition(NULL);
    ESP_LOGI(TAG, "ota partition, address:0x%08"PRIx32" size:0x%08"PRIx32"", part_ota->address, part_ota->size);

    for (retry = 0; retry < CONFIG_OTA_DOWNLOAD_RETRY; retry++) {
        ESP_LOGI(TAG, "download image retry:%u", retry);

        s_download_size = 0;
        mbedtls_md_init(&md_ctx);  
        mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);  
        mbedtls_md_starts(&md_ctx);

        err = esp_ota_begin(part_ota, OTA_SIZE_UNKNOWN, &s_hd_ota);
        if (ESP_OK != err) {
            ESP_LOGE(TAG, "esp_ota_begin error:%d", err);
            goto exit;
        }
        ESP_LOGI(TAG, "esp_ota_begin success");

        s_hd_http = esp_http_client_init(&http_cfg);
        err = esp_http_client_open(s_hd_http, 0);
        if (ESP_OK != err) {
            ESP_LOGE(TAG, "esp_http_client_open error:%d", err);
            goto exit;
        }
        ESP_LOGI(TAG, "esp_http_client_open success");

        esp_http_client_fetch_headers(s_hd_http);
        while (s_download_size < s_ota_task.size) {
            len = esp_http_client_read(s_hd_http, s_ota_buf, sizeof(s_ota_buf));
            if (len <= 0) {
                ESP_LOGE(TAG, "esp_http_client_read error:%d", len);
                break;
            }

            err = esp_ota_write(s_hd_ota, s_ota_buf, len);
            if (err != ESP_OK) {
                ESP_LOGE(TAG, "esp_ota_write error:%d", err);
                goto exit;
            }
            mbedtls_md_update(&md_ctx, (unsigned char *)s_ota_buf, len);
            s_download_size += len;
            ESP_LOGI(TAG, "esp_ota_write success, cur:%d totol:%lu", len, s_download_size);
            vTaskDelay(pdMS_TO_TICKS(50));
        }

        if (s_ota_task.size != s_download_size) {
            ESP_LOGE(TAG, "download image error, ota:%lu download:%lu", s_ota_task.size, s_download_size);
            goto exit;
        }
        ESP_LOGI(TAG, "download image success, ota:%lu download:%lu", s_ota_task.size, s_download_size);

        mbedtls_md_finish(&md_ctx, sha256);
        for (uint8_t i = 0; i < sizeof(sha256); i++) {
            sprintf(sha256_hexstring + (2 * i), "%02x", sha256[i]);
        }
        if (memcmp(s_ota_task.sha256, sha256_hexstring, strlen(sha256_hexstring))) {
            ESP_LOGE(TAG, "sha256 check error, ota:%s download:%s", s_ota_task.sha256, sha256_hexstring);
            goto exit;   
        }
        ESP_LOGI(TAG, "sha256 check success");

        esp_partition_read(part_ota, sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t), &app_desc, sizeof(esp_app_desc_t));
        if (memcmp(s_ota_task.version, app_desc.version, strlen(app_desc.version))) {
            ESP_LOGE(TAG, "version check error, ota:%s download:%s", s_ota_task.version, app_desc.version);
            goto exit;   
        }
        ESP_LOGI(TAG, "version check success");

        err = esp_ota_end(s_hd_ota);
        if (ESP_OK != err) {
            ESP_LOGE(TAG, "esp_ota_end error:%d", err);
            goto exit;
        }
        ESP_LOGI(TAG, "esp_ota_end success");
        err = esp_ota_set_boot_partition(part_ota);
        if (ESP_OK != err) {
            ESP_LOGE(TAG, "esp_ota_set_boot_partition error:%d", err);
            goto exit;
        }
        ESP_LOGI(TAG, "esp_ota_set_boot_partition success");

        ESP_LOGI(TAG, "restart after 3s");
        vTaskDelay(pdMS_TO_TICKS(3000));
        esp_restart();

exit:
        mbedtls_md_free(&md_ctx);
        esp_http_client_cleanup(s_hd_http);
        esp_ota_abort(s_hd_ota);
    }

    vTaskDelete(NULL);
}

void ota_remote_start(uint8_t *payload, uint32_t payload_len) {
    cJSON *json_root = cJSON_Parse((char *)payload);
    cJSON *json_data = cJSON_GetObjectItem(json_root, "data");
    cJSON *json_size = cJSON_GetObjectItem(json_data, "size");
    cJSON *json_version = cJSON_GetObjectItem(json_data, "version");
    cJSON *json_url = cJSON_GetObjectItem(json_data, "url");
    cJSON *json_sha256 = cJSON_GetObjectItem(json_data, "sign");

    memset(&s_ota_task, 0, sizeof(s_ota_task));
    memcpy(s_ota_task.url, json_url->valuestring, strlen(json_url->valuestring));
    memcpy(s_ota_task.version, json_version->valuestring, strlen(json_version->valuestring));
    memcpy(s_ota_task.sha256, json_sha256->valuestring, strlen(json_sha256->valuestring));
    s_ota_task.size = json_size->valueint;
    cJSON_Delete(json_root);

    ESP_LOGI(TAG, "url:%s", s_ota_task.url);
    ESP_LOGI(TAG, "version:%s", s_ota_task.version);
    ESP_LOGI(TAG, "sha256:%s", s_ota_task.sha256);
    ESP_LOGI(TAG, "size:%lu", s_ota_task.size);

    xTaskCreate(ota_download_cb, "ota_download", 8192, NULL, 3, NULL);
    xTaskCreate(ota_progress_cb, "ota_progress", 4096, NULL, 2, NULL);
}

void ota_report_version() {
    const esp_partition_t *part_run = NULL;
    esp_app_desc_t app_desc = {0};
    char buf[256] = {0};

    part_run = esp_ota_get_running_partition();
    esp_partition_read(part_run, sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t), &app_desc, sizeof(esp_app_desc_t));
    sprintf(buf, "{\"id\":\"%s\", \"params\":{\"version\":\"%s\"}}", cloud_gen_msg_id(), app_desc.version);
    cloud_publish(CONFIG_TOPIC_OTA_REPORT, (uint8_t *)buf, strlen(buf), 1);
    ESP_LOGI(TAG, "ota report version:%s", app_desc.version);
}

static int verify_signature(const esp_partition_t *part, uint32_t file_size) {
    int ret = 0;
    mbedtls_pk_context pk;
    mbedtls_md_context_t ctx;
    uint8_t hash_data[32] = {0};
    uint8_t sign_data[256] = {0};
    uint32_t image_size = file_size - 256; // file_size = image + signature
    uint32_t i = 0;
    uint32_t quotient = image_size / CONFIG_OTA_DOWNLOAD_BUF_SIZE;
    uint32_t remainder = image_size % CONFIG_OTA_DOWNLOAD_BUF_SIZE;

    mbedtls_pk_init(&pk);
    ret = mbedtls_pk_parse_public_key(&pk, ota_sign_pub_key_start, ota_sign_pub_key_end - ota_sign_pub_key_start);
    if (ret) {
        ESP_LOGE(TAG, "mbedtls_pk_parse_public_key error:%d", ret);
        mbedtls_pk_free(&pk);
        return ret;
    }
    mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk), MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

    mbedtls_md_init(&ctx);  
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);  
    mbedtls_md_starts(&ctx); 
    while (i < quotient) {
        esp_partition_read(part, i * CONFIG_OTA_DOWNLOAD_BUF_SIZE, s_ota_buf, CONFIG_OTA_DOWNLOAD_BUF_SIZE);
        mbedtls_md_update(&ctx, (u_int8_t *)s_ota_buf, CONFIG_OTA_DOWNLOAD_BUF_SIZE);
        i++;
    }
    if (remainder != 0) {
        esp_partition_read(part, i * CONFIG_OTA_DOWNLOAD_BUF_SIZE, s_ota_buf, remainder);
        mbedtls_md_update(&ctx, (u_int8_t *)s_ota_buf, remainder);
    }
    mbedtls_md_finish(&ctx, hash_data);  
    mbedtls_md_free(&ctx);  

    esp_partition_read(part, image_size, sign_data, 256);

    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash_data, 32, sign_data, 256);
    if (ret) {
        ESP_LOGE(TAG, "mbedtls_pk_verify error:%d", ret);
    }
    mbedtls_pk_free(&pk);

    return ret;
}

esp_err_t http_post_ota_handler(httpd_req_t *req) {
    esp_err_t err = ESP_OK;
    size_t header_len = 0, file_size = 0, file_read = 0;
    int content_length = 0, read_len = 0, boundary_len = 0;
    char *boundary = NULL, *file_begin = NULL;
    const char end_line[4] = {'\r', '\n', '\r', '\n'};
    const esp_partition_t *part_ota = NULL;

    header_len = httpd_req_get_hdr_value_len(req, "Content-Length");
    httpd_req_get_hdr_value_str(req, "Content-Length", s_ota_buf, header_len + 1);
    content_length = atoi(s_ota_buf);

    header_len = httpd_req_get_hdr_value_len(req, "Content-Type");
    httpd_req_get_hdr_value_str(req, "Content-Type", s_ota_buf, header_len + 1);
    boundary = strstr(s_ota_buf, "----");
    boundary_len = strlen(boundary);
    ESP_LOGI(TAG, "Content-Type:%s", s_ota_buf);

    // first package, include First boundary,Content-Disposition,Content-Type,filedata
    read_len = httpd_req_recv(req, s_ota_buf, sizeof(s_ota_buf));
    file_begin = memmem(s_ota_buf, read_len, end_line, sizeof(end_line));
    file_begin += sizeof(end_line);
    file_size = content_length - (file_begin - s_ota_buf) - boundary_len - 8;
    file_read = read_len - (file_begin - s_ota_buf);
    ESP_LOGI(TAG, "Content-Length:%d file_size:%d", content_length, file_size);

    part_ota = esp_ota_get_next_update_partition(NULL);
    ESP_LOGI(TAG, "ota partition, address:0x%08"PRIx32" size:0x%08"PRIx32"", part_ota->address, part_ota->size);

    err = esp_ota_begin(part_ota, OTA_SIZE_UNKNOWN, &s_hd_ota);
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "esp_ota_begin error:%d", err);
        goto exit;
    }
    ESP_LOGI(TAG, "esp_ota_begin success");

    err = esp_ota_write(s_hd_ota, file_begin, file_read);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_write error:%d", err);
        goto exit;
    }
    ESP_LOGI(TAG, "esp_ota_write success, cur:%d totol:%u", file_read, file_read);
    while (file_read < file_size) {
        read_len = httpd_req_recv(req, s_ota_buf, sizeof(s_ota_buf));
        if (read_len <= 0) {
            ESP_LOGE(TAG, "httpd_req_recv error:%d", read_len);
            break;
        }

        if (read_len > file_size - file_read) { // last package, maybe include Last boundary
            read_len = file_size - file_read;
        }
        err = esp_ota_write(s_hd_ota, s_ota_buf, read_len);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "esp_ota_write error:%d", err);
            goto exit;
        }
        file_read += read_len;
        ESP_LOGI(TAG, "esp_ota_write success, cur:%d totol:%u", read_len, file_read);
        vTaskDelay(pdMS_TO_TICKS(50));
    }

    if (file_size != file_read) {
        ESP_LOGE(TAG, "download image error, file_size:%u download:%u", file_size, file_read);
        goto exit;
    }
    ESP_LOGI(TAG, "download image success");

    if (verify_signature(part_ota, file_size)) {
        ESP_LOGE(TAG, "signature check error");
        goto exit;
    }
    ESP_LOGI(TAG, "signature check success");

    err = esp_ota_end(s_hd_ota);
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "esp_ota_end error:%d", err);
        goto exit;
    }
    ESP_LOGI(TAG, "esp_ota_end success");
    err = esp_ota_set_boot_partition(part_ota);
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "esp_ota_set_boot_partition error:%d", err);
        goto exit;
    }
    ESP_LOGI(TAG, "esp_ota_set_boot_partition success");

    httpd_resp_set_status(req, HTTPD_200);
    httpd_resp_send(req, "{\"code\":0, \"message\":\"success\"}", strlen("{\"code\":0, \"message\":\"success\"}"));

    ESP_LOGI(TAG, "restart after 3s");
    vTaskDelay(pdMS_TO_TICKS(3000));
    esp_restart();

exit:
    esp_ota_abort(s_hd_ota);
    httpd_resp_set_status(req, HTTPD_500);
    httpd_resp_send(req, "{\"code\":1, \"message\":\"error\"}", strlen("{\"code\":1, \"message\":\"error\"}"));

    return ESP_FAIL;
}
