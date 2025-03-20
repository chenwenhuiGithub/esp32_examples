#ifndef OTA_H_
#define OTA_H_

#include <stdint.h>
#include "esp_http_server.h"

#define CONFIG_OTA_REPORT_PROGRESS_MS               3000
#define CONFIG_OTA_DOWNLOAD_RETRY                   3

void ota_report_version();
void ota_remote_start(uint8_t *payload, uint32_t payload_len);
esp_err_t http_post_ota_handler(httpd_req_t *req);

#endif
