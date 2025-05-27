#include <string.h>
#include "esp_log.h"
#include "esp_err.h"
#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "logSample.h"


static const char *TAG = "logSample";
static int s_udp_sock = 0;
static struct sockaddr_in s_client_addr = {0};
static socklen_t s_client_addr_len = sizeof(s_client_addr);


static int udp_vprintf(const char *format, va_list args) {  
    size_t len = 0;
    static uint8_t tx_data[256] = {0};

    memset(tx_data, 0, sizeof(tx_data));
    len = vsnprintf((char *)tx_data, sizeof(tx_data) - 1, format, args);
	sendto(s_udp_sock, tx_data, len, 0, (struct sockaddr *)&s_client_addr, s_client_addr_len);

    return len;
}

void logSample_cb(void *pvParameters) {
    int err = 0;
    struct sockaddr_in local_addr = {0};
    uint8_t rx_data[16] = {0};
    int rx_len = 0;

    s_udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (s_udp_sock < 0) {
        ESP_LOGE(TAG, "socket create failed:%d", errno);
        goto exit;
    }

    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_addr.sin_port = htons(CONFIG_LOGSAMPLE_PORT);
    err = bind(s_udp_sock, (struct sockaddr *)&local_addr, sizeof(local_addr));
    if (err != 0) {
        ESP_LOGE(TAG, "socket bind failed:%d", errno);
        goto exit;
    }

    ESP_LOGI(TAG, "udp listen, port:%u", CONFIG_LOGSAMPLE_PORT);

    while (1) {
        rx_len = recvfrom(s_udp_sock, rx_data, sizeof(rx_data), 0, (struct sockaddr *)&s_client_addr, &s_client_addr_len);
        if (rx_len > 0) {
            if (0 == strncmp((char *)rx_data, "start", strlen("start"))) {
            	esp_log_set_vprintf(&udp_vprintf);
			}
			if (0 == strncmp((char *)rx_data, "stop", strlen("stop"))) {
				esp_log_set_vprintf(&vprintf); // default
			}
        } 
    }

exit:
    vTaskDelete(NULL);
}
