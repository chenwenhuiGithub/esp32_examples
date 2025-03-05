#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"


#define CONFIG_WIFI_STA_SSID                    "SolaxGuest"
#define CONFIG_WIFI_STA_PWD                     "solaxpower"
#define CONFIG_MDNS_INSNAME                     "udpecho_ins"
#define CONFIG_MDNS_SRVTYPE                     "_echosrv"
#define CONFIG_MDNS_TRANSPORT                   "_udp"
#define CONFIG_MDNS_RECV_TIMEOUT_MS             3000
#define CONFIG_MDNS_TTL                         4500
#define CONFIG_MDNS_MAX_SRV                     5
#define CONFIG_MDNS_MAX_TXT                     3
#define CONFIG_MDNS_SRV_PORT                    60001

#define MDNS_MULTIPLE_UDP_IP                    "224.0.0.251"
#define MDNS_MULTIPLE_UDP_PORT                  5353

typedef enum {
    MDNS_QUERY_TYPE_A = 0x01,
    MDNS_QUERY_TYPE_PTR = 0x0C,
    MDNS_QUERY_TYPE_TXT = 0x10,
    MDNS_QUERY_TYPE_AAAA = 0x1C,
    MDNS_QUERY_TYPE_SRV = 0x21,
} mdns_query_type_t;

typedef struct {
    char ins_name[32];
} mdns_ptr_t;

typedef struct {
    uint16_t priority;
    uint16_t weight;
    uint16_t port;
    char target[64];
} mdns_srv_t;

typedef struct {
    char key[32];
    char value[64];
} mdns_txt_t;

typedef struct {
    uint8_t ip[4];
} mdns_a_t;

typedef struct {
	uint8_t ip[16];
} mdns_aaaa_t;

typedef struct {
    char ins_name[32];
    char srv_type[32];
    char trans_type[16];
    uint16_t priority;
    uint16_t weight;
    uint16_t port;
    mdns_txt_t txt[CONFIG_MDNS_MAX_TXT];
    uint8_t result_txt_cnt;
    uint8_t srv_ipV4[4];
    uint8_t ipV6[16];
} mdns_service_t;

esp_err_t mdns_init();
esp_err_t mdns_query_ptr(char *srv_type, char *trans_type, mdns_ptr_t *result);
esp_err_t mdns_query_srv(char *ins_name, char *srv_type, char *trans_type, mdns_srv_t *result);
esp_err_t mdns_query_txt(char *ins_name, char *srv_type, char *trans_type, mdns_txt_t *result, uint32_t *cnt);
esp_err_t mdns_query_a(char *ins_name, char *srv_type, char *trans_type, mdns_a_t *result);
esp_err_t mdns_query_aaaa(char *ins_name, char *srv_type, char *trans_type, mdns_aaaa_t *result);
esp_err_t mdns_add_srv(char *ins_name, char *srv_type, char *trans_type, uint16_t port, uint8_t *srv_ipV4, uint8_t *ipV6, mdns_txt_t *txt, uint32_t cnt);
esp_err_t mdns_wait_query();


static const char *TAG = "mdns";
static int sock = 0;
static uint8_t req[256] = {0};
static uint8_t resp[1024] = {0};
static mdns_service_t g_srv[CONFIG_MDNS_MAX_SRV] = {0};
static uint8_t srv_cnt = 0;

esp_err_t mdns_init() {
    int err = 0;
    struct sockaddr_in local_addr = {0};
    uint8_t ttl = 3;
    uint8_t loopback = 0;
    struct ip_mreq mreq = {0};
    struct timeval tv = {
        .tv_sec = CONFIG_MDNS_RECV_TIMEOUT_MS / 1000,
        .tv_usec = (CONFIG_MDNS_RECV_TIMEOUT_MS % 1000) * 1000
    };

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0) {
        ESP_LOGE(TAG, "socket create failed:%d", errno);
        goto exit;
    }

    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_addr.sin_port = htons(MDNS_MULTIPLE_UDP_PORT);
    err = bind(sock, (struct sockaddr *)&local_addr, sizeof(local_addr));
    if (err != 0) {
        ESP_LOGE(TAG, "socket bind failed:%d", errno);
        goto exit;
    }

    err = setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
    if (err < 0) {
        ESP_LOGE(TAG, "socket setsockopt IP_MULTICAST_TTL failed:%d", errno);
        goto exit;
    }

    err = setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, &loopback, sizeof(loopback));
    if (err < 0) {
        ESP_LOGE(TAG, "socket setsockopt IP_MULTICAST_LOOP failed:%d", errno);
        goto exit;
    }

    mreq.imr_multiaddr.s_addr = inet_addr(MDNS_MULTIPLE_UDP_IP);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    err = setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
    if (err < 0) {
        ESP_LOGE(TAG, "socket setsockopt IP_ADD_MEMBERSHIP failed:%d", errno);
        goto exit;
    }

    err = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (err < 0) {
        ESP_LOGE(TAG, "socket set SO_RCVTIMEO failed:%d", errno);
        goto exit;
    }

    ESP_LOGI(TAG, "mdns socket init success");
    return ESP_OK;

exit:
    ESP_LOGE(TAG, "mdns socket init failed:%d", err);
    return err;
}

esp_err_t mdns_query_ptr(char *srv_type, char *trans_type, mdns_ptr_t *result) {
    uint32_t req_len = 0, i = 0;
    int resp_len = 0;
    char *domain = "local";
    struct sockaddr_in remote_addr = {0};
    socklen_t remote_addr_len = sizeof(remote_addr);

    req[req_len++] = 0;
    req[req_len++] = 0; // trans_id
    req[req_len++] = 0;
    req[req_len++] = 0; // flags: standard query
    req[req_len++] = 0;
    req[req_len++] = 1; // question
    req[req_len++] = 0;
    req[req_len++] = 0; // answer
    req[req_len++] = 0;
    req[req_len++] = 0; // authority
    req[req_len++] = 0;
    req[req_len++] = 0; // additional

    req[req_len++] = strlen(srv_type);
    memcpy(&req[req_len], srv_type, strlen(srv_type));
    req_len += strlen(srv_type);
    req[req_len++] = strlen(trans_type);
    memcpy(&req[req_len], trans_type, strlen(trans_type));
    req_len += strlen(trans_type);
    req[req_len++] = strlen(domain);
    memcpy(&req[req_len], domain, strlen(domain));
    req_len += strlen(domain);
    req[req_len++] = 0;

    req[req_len++] = 0;
    req[req_len++] = MDNS_QUERY_TYPE_PTR; // type
    req[req_len++] = 0;
    req[req_len++] = 0x01; // class, multicase response

    remote_addr.sin_family = AF_INET;
    remote_addr.sin_addr.s_addr = inet_addr(MDNS_MULTIPLE_UDP_IP);
    remote_addr.sin_port = htons(MDNS_MULTIPLE_UDP_PORT);
    sendto(sock, req, req_len, 0, (struct sockaddr *)&remote_addr, remote_addr_len);

    resp_len = recvfrom(sock, resp, sizeof(resp), 0, (struct sockaddr *)&remote_addr, &remote_addr_len);
    if (resp_len < 0) {
        ESP_LOGE(TAG, "socket recv timeout");
        return ESP_ERR_TIMEOUT;
    }

    i = 12; // skip trans_id(2B), flags(2B), question(2B), answer(2B), authority(2B), additional(2B)
    while (resp[i]) { // skip name
        i += resp[i] + 1;
    }
    i++;
    i += 10; // skip type(2B), class(2B), TTL(4B), length(2B)

    memcpy(result->ins_name, &resp[i + 1], resp[i]);

    return ESP_OK;
}

esp_err_t mdns_query_srv(char *ins_name, char *srv_type, char *trans_type, mdns_srv_t *result) {
    uint32_t req_len = 0, i = 0;
    int resp_len = 0;
    char *domain = "local";
    struct sockaddr_in remote_addr = {0};
    socklen_t remote_addr_len = sizeof(remote_addr);
    uint32_t target_len = 0, offset = 0;

    req[req_len++] = 0;
    req[req_len++] = 0; // trans_id
    req[req_len++] = 0;
    req[req_len++] = 0; // flags: standard query
    req[req_len++] = 0;
    req[req_len++] = 1; // question
    req[req_len++] = 0;
    req[req_len++] = 0; // answer
    req[req_len++] = 0;
    req[req_len++] = 0; // authority
    req[req_len++] = 0;
    req[req_len++] = 0; // additional

    req[req_len++] = strlen(ins_name);
    memcpy(&req[req_len], ins_name, strlen(ins_name));
    req_len += strlen(ins_name);
    req[req_len++] = strlen(srv_type);
    memcpy(&req[req_len], srv_type, strlen(srv_type));
    req_len += strlen(srv_type);
    req[req_len++] = strlen(trans_type);
    memcpy(&req[req_len], trans_type, strlen(trans_type));
    req_len += strlen(trans_type);
    req[req_len++] = strlen(domain);
    memcpy(&req[req_len], domain, strlen(domain));
    req_len += strlen(domain);
    req[req_len++] = 0;

    req[req_len++] = 0;
    req[req_len++] = MDNS_QUERY_TYPE_SRV; // type
    req[req_len++] = 0;
    req[req_len++] = 0x01; // class, multicase response

    remote_addr.sin_family = AF_INET;
    remote_addr.sin_addr.s_addr = inet_addr(MDNS_MULTIPLE_UDP_IP);
    remote_addr.sin_port = htons(MDNS_MULTIPLE_UDP_PORT);
    sendto(sock, req, req_len, 0, (struct sockaddr *)&remote_addr, remote_addr_len);

    resp_len = recvfrom(sock, resp, sizeof(resp), 0, (struct sockaddr *)&remote_addr, &remote_addr_len);
    if (resp_len < 0) {
        ESP_LOGE(TAG, "socket recv timeout");
        return ESP_ERR_TIMEOUT;
    }

    i = 12; // skip trans_id(2B), flags(2B), question(2B), answer(2B), authority(2B), additional(2B)
    while (resp[i]) { // skip name
        i += resp[i] + 1;
    }
    i++;
    i += 10; // skip type(2B), class(2B), TTL(4B), length(2B)

    result->priority = resp[i] << 8 | resp[i + 1];
    result->weight = resp[i + 2] << 8 | resp[i + 3];
    result->port = resp[i + 4] << 8 | resp[i + 5];
    if (0xc0 == resp[i + 6]) {
        offset = resp[i + 7];
    } else {
        offset = i + 6;
    }
    while (resp[offset]) {
        memcpy(result->target + target_len, &resp[offset + 1], resp[offset]);
        target_len += resp[offset];
        result->target[target_len] = '.';
        target_len += 1;
        offset += resp[offset] + 1;
    }
    result->target[target_len - 1] = 0; // delete the last char "."

    return ESP_OK;
}

esp_err_t mdns_query_txt(char *ins_name, char *srv_type, char *trans_type, mdns_txt_t *result, uint32_t *cnt) {
    uint32_t req_len = 0, i = 0;
    int resp_len = 0;
    char *domain = "local";
    struct sockaddr_in remote_addr = {0};
    socklen_t remote_addr_len = sizeof(remote_addr);
    uint16_t total_data_len = 0, data_len = 0, kv_len = 0;
    char kv[128] = {0};
    uint32_t kv_cnt = 0;
    char *ch_equal = NULL;

    req[req_len++] = 0;
    req[req_len++] = 0; // trans_id
    req[req_len++] = 0;
    req[req_len++] = 0; // flags: standard query
    req[req_len++] = 0;
    req[req_len++] = 1; // question
    req[req_len++] = 0;
    req[req_len++] = 0; // answer
    req[req_len++] = 0;
    req[req_len++] = 0; // authority
    req[req_len++] = 0;
    req[req_len++] = 0; // additional

    req[req_len++] = strlen(ins_name);
    memcpy(&req[req_len], ins_name, strlen(ins_name));
    req_len += strlen(ins_name);
    req[req_len++] = strlen(srv_type);
    memcpy(&req[req_len], srv_type, strlen(srv_type));
    req_len += strlen(srv_type);
    req[req_len++] = strlen(trans_type);
    memcpy(&req[req_len], trans_type, strlen(trans_type));
    req_len += strlen(trans_type);
    req[req_len++] = strlen(domain);
    memcpy(&req[req_len], domain, strlen(domain));
    req_len += strlen(domain);
    req[req_len++] = 0;

    req[req_len++] = 0;
    req[req_len++] = MDNS_QUERY_TYPE_TXT; // type
    req[req_len++] = 0;
    req[req_len++] = 0x01; // class, multicase response

    remote_addr.sin_family = AF_INET;
    remote_addr.sin_addr.s_addr = inet_addr(MDNS_MULTIPLE_UDP_IP);
    remote_addr.sin_port = htons(MDNS_MULTIPLE_UDP_PORT);
    sendto(sock, req, req_len, 0, (struct sockaddr *)&remote_addr, remote_addr_len);

    resp_len = recvfrom(sock, resp, sizeof(resp), 0, (struct sockaddr *)&remote_addr, &remote_addr_len);
    if (resp_len < 0) {
        ESP_LOGE(TAG, "socket recv timeout");
        return ESP_ERR_TIMEOUT;
    }

    i = 12; // skip trans_id(2B), flags(2B), question(2B), answer(2B), authority(2B), additional(2B)
    while (resp[i]) { // skip name
        i += resp[i] + 1;
    }
    i++;
    i += 8; // skip type(2B), class(2B), TTL(4B)

    total_data_len = resp[i] << 8 | resp[i + 1];
    while (data_len < total_data_len) {
        kv_len = resp[i + 2];
        memcpy(kv, &resp[i + 3], kv_len);
        kv[kv_len] = 0;
        ch_equal = strchr(kv, '=');
        memcpy(result[kv_cnt].key, kv, ch_equal - kv);
        memcpy(result[kv_cnt].value, ch_equal + 1, kv_len - (ch_equal - kv + 1));
        kv_cnt++;
        data_len += kv_len + 1;
        i += kv_len + 1;
    }
    *cnt = kv_cnt;

    return ESP_OK;
}

esp_err_t mdns_query_a(char *ins_name, char *srv_type, char *trans_type, mdns_a_t *result) {
    uint32_t req_len = 0, i = 0;
    int resp_len = 0;
    char *domain = "local";
    struct sockaddr_in remote_addr = {0};
    socklen_t remote_addr_len = sizeof(remote_addr);

    req[req_len++] = 0;
    req[req_len++] = 0; // trans_id
    req[req_len++] = 0;
    req[req_len++] = 0; // flags: standard query
    req[req_len++] = 0;
    req[req_len++] = 1; // question
    req[req_len++] = 0;
    req[req_len++] = 0; // answer
    req[req_len++] = 0;
    req[req_len++] = 0; // authority
    req[req_len++] = 0;
    req[req_len++] = 0; // additional

    req[req_len++] = strlen(ins_name);
    memcpy(&req[req_len], ins_name, strlen(ins_name));
    req_len += strlen(ins_name);
    req[req_len++] = strlen(srv_type);
    memcpy(&req[req_len], srv_type, strlen(srv_type));
    req_len += strlen(srv_type);
    req[req_len++] = strlen(trans_type);
    memcpy(&req[req_len], trans_type, strlen(trans_type));
    req_len += strlen(trans_type);
    req[req_len++] = strlen(domain);
    memcpy(&req[req_len], domain, strlen(domain));
    req_len += strlen(domain);
    req[req_len++] = 0;

    req[req_len++] = 0;
    req[req_len++] = MDNS_QUERY_TYPE_A; // type
    req[req_len++] = 0;
    req[req_len++] = 0x01; // class, multicase response

    remote_addr.sin_family = AF_INET;
    remote_addr.sin_addr.s_addr = inet_addr(MDNS_MULTIPLE_UDP_IP);
    remote_addr.sin_port = htons(MDNS_MULTIPLE_UDP_PORT);
    sendto(sock, req, req_len, 0, (struct sockaddr *)&remote_addr, remote_addr_len);

    resp_len = recvfrom(sock, resp, sizeof(resp), 0, (struct sockaddr *)&remote_addr, &remote_addr_len);
    if (resp_len < 0) {
        ESP_LOGE(TAG, "socket recv timeout");
        return ESP_ERR_TIMEOUT;
    }

    i = 12; // skip trans_id(2B), flags(2B), question(2B), answer(2B), authority(2B), additional(2B)
    while (resp[i]) { // skip name
        i += resp[i] + 1;
    }
    i++;
    i += 10; // skip type(2B), class(2B), TTL(4B), length(2B)

    memcpy(result->ip, &resp[i], 4);

    return ESP_OK;
}

esp_err_t mdns_query_aaaa(char *ins_name, char *srv_type, char *trans_type, mdns_aaaa_t *result) {
    uint32_t req_len = 0, i = 0;
    int resp_len = 0;
    char *domain = "local";
    struct sockaddr_in remote_addr = {0};
    socklen_t remote_addr_len = sizeof(remote_addr);

    req[req_len++] = 0;
    req[req_len++] = 0; // trans_id
    req[req_len++] = 0;
    req[req_len++] = 0; // flags: standard query
    req[req_len++] = 0;
    req[req_len++] = 1; // question
    req[req_len++] = 0;
    req[req_len++] = 0; // answer
    req[req_len++] = 0;
    req[req_len++] = 0; // authority
    req[req_len++] = 0;
    req[req_len++] = 0; // additional

    req[req_len++] = strlen(ins_name);
    memcpy(&req[req_len], ins_name, strlen(ins_name));
    req_len += strlen(ins_name);
    req[req_len++] = strlen(srv_type);
    memcpy(&req[req_len], srv_type, strlen(srv_type));
    req_len += strlen(srv_type);
    req[req_len++] = strlen(trans_type);
    memcpy(&req[req_len], trans_type, strlen(trans_type));
    req_len += strlen(trans_type);
    req[req_len++] = strlen(domain);
    memcpy(&req[req_len], domain, strlen(domain));
    req_len += strlen(domain);
    req[req_len++] = 0;

    req[req_len++] = 0;
    req[req_len++] = MDNS_QUERY_TYPE_AAAA; // type
    req[req_len++] = 0;
    req[req_len++] = 0x01; // class, multicase response

    remote_addr.sin_family = AF_INET;
    remote_addr.sin_addr.s_addr = inet_addr(MDNS_MULTIPLE_UDP_IP);
    remote_addr.sin_port = htons(MDNS_MULTIPLE_UDP_PORT);
    sendto(sock, req, req_len, 0, (struct sockaddr *)&remote_addr, remote_addr_len);

    resp_len = recvfrom(sock, resp, sizeof(resp), 0, (struct sockaddr *)&remote_addr, &remote_addr_len);
    if (resp_len < 0) {
        ESP_LOGE(TAG, "socket recv timeout");
        return ESP_ERR_TIMEOUT;
    }

    i = 12; // skip trans_id(2B), flags(2B), question(2B), answer(2B), authority(2B), additional(2B)
    while (resp[i]) { // skip name
        i += resp[i] + 1;
    }
    i++;
    i += 10; // skip type(2B), class(2B), TTL(4B), length(2B)

    memcpy(result->ip, &resp[i], 16);

    return ESP_OK;
}

esp_err_t mdns_add_srv(char *ins_name, char *srv_type, char *trans_type, uint16_t port, uint8_t *srv_ipV4, uint8_t *ipV6, mdns_txt_t *txt, uint32_t cnt) {
    uint32_t i = 0;

    if (CONFIG_MDNS_MAX_SRV == srv_cnt) {
        ESP_LOGE(TAG, "service is full:%u", srv_cnt);
        return -1;
    }

    memcpy(g_srv[srv_cnt].ins_name, ins_name, strlen(ins_name));
    memcpy(g_srv[srv_cnt].srv_type, srv_type, strlen(srv_type));
    memcpy(g_srv[srv_cnt].trans_type, trans_type, strlen(trans_type));
    g_srv[srv_cnt].priority = 0;
    g_srv[srv_cnt].weight = 0;
    g_srv[srv_cnt].port = port;
    for (i = 0; i < cnt; i++) {
        memcpy(g_srv[srv_cnt].txt[i].key, txt[i].key, strlen(txt[i].key));
        memcpy(g_srv[srv_cnt].txt[i].value, txt[i].value, strlen(txt[i].value));
    }
    g_srv[srv_cnt].result_txt_cnt = cnt;
    if (srv_ipV4) {
        memcpy(g_srv[srv_cnt].srv_ipV4, srv_ipV4, sizeof(srv_ipV4));
    }
    if (ipV6) {
        memcpy(g_srv[srv_cnt].ipV6, ipV6, sizeof(ipV6));
    }
    srv_cnt++;

    return ESP_OK;
}

esp_err_t mdns_wait_query() {
    struct sockaddr_in remote_addr = {0};
    socklen_t remote_addr_len = sizeof(remote_addr);
    int req_len = 0;
    uint32_t resp_len = 0, i = 0, j = 0, k = 0;
    char ins_name[32] = {0};
    char srv_type[32] = {0};
    char trans_type[16] = {0};
    char *domain = "local";
    uint32_t ins_name_len = 0, srv_type_len = 0, trans_type_len = 0;
    uint16_t query_type = 0;
    uint8_t is_unicast_resp = 0;
    uint16_t data_len = 0;

    while (1) {
        req_len = recvfrom(sock, req, sizeof(req), 0, (struct sockaddr *)&remote_addr, &remote_addr_len);
        if (req_len > 0) {
            if (req[2] & 0x80) { // response, not query
                continue;
            }

            i = 12; // skip trans_id(2B), flags(2B), question(2B), answer(2B), authority(2B), additional(2B)
            while (req[i]) { // skip name
                i += req[i] + 1;
            }
            i++;

            query_type = (req[i] << 8) | req[i + 1];
            if (req[i + 2] & 0x80) {
                is_unicast_resp = 1;
            } else {
                is_unicast_resp = 0;
            }

            resp[0] = req[0];
            resp[1] = req[1]; // trans_id
            resp[2] = 0x84;
            resp[3] = 0x00;   // flags: standard query response
            resp[4] = 0;
            resp[5] = 0;      // question
            resp[6] = 0;
            resp[7] = 1;      // answer
            resp[8] = 0;
            resp[9] = 0;      // authority
            resp[10] = 0;
            resp[11] = 0;     // additional
            resp_len = 12;

            switch (query_type) {
            case MDNS_QUERY_TYPE_PTR:
                srv_type_len = req[12];
                memcpy(srv_type, &req[13], srv_type_len);
                trans_type_len = req[13 + srv_type_len];
                memcpy(trans_type, &req[14 + srv_type_len], trans_type_len);
                ESP_LOGI(TAG, "query_type:0x%04X srv_type:%s trans_type:%s", query_type, srv_type, trans_type);

                for (j = 0; j < srv_cnt; j++) {
                    if (strlen(g_srv[j].srv_type) == srv_type_len && strncmp(g_srv[j].srv_type, srv_type, srv_type_len) == 0) {
                        if (strlen(g_srv[j].trans_type) == trans_type_len && strncmp(g_srv[j].trans_type, trans_type, trans_type_len) == 0) {
                            resp[resp_len++] = srv_type_len;
                            memcpy(&resp[resp_len], srv_type, srv_type_len);
                            resp_len += srv_type_len;
                            resp[resp_len++] = trans_type_len;
                            memcpy(&resp[resp_len], trans_type, trans_type_len);
                            resp_len += trans_type_len;
                            resp[resp_len++] = strlen(domain);
                            memcpy(&resp[resp_len], domain, strlen(domain));
                            resp_len += strlen(domain);
                            resp[resp_len++] = 0;

                            resp[resp_len++] = query_type >> 8;
                            resp[resp_len++] = query_type;
                            resp[resp_len++] = 0x00;
                            resp[resp_len++] = 0x01; // class
                            resp[resp_len++] = CONFIG_MDNS_TTL >> 24;
                            resp[resp_len++] = CONFIG_MDNS_TTL >> 16;
                            resp[resp_len++] = CONFIG_MDNS_TTL >> 8;
                            resp[resp_len++] = (uint8_t)CONFIG_MDNS_TTL; // TTL
                            resp[resp_len++] = (strlen(g_srv[j].ins_name) + 3) >> 8;
                            resp[resp_len++] = strlen(g_srv[j].ins_name) + 3; // data_len
                            resp[resp_len++] = strlen(g_srv[j].ins_name);
                            memcpy(&resp[resp_len], g_srv[j].ins_name, strlen(g_srv[j].ins_name));
                            resp_len += strlen(g_srv[j].ins_name);
                            resp[resp_len++] = 0xc0;
                            resp[resp_len++] = 0x0c;

                            if (!is_unicast_resp) {
                                remote_addr.sin_family = AF_INET;
                                remote_addr.sin_addr.s_addr = inet_addr(MDNS_MULTIPLE_UDP_IP);
                                remote_addr.sin_port = htons(MDNS_MULTIPLE_UDP_PORT);
                            }                               
                            sendto(sock, resp, resp_len, 0, (struct sockaddr *)&remote_addr, remote_addr_len);
                            break;
                        }
                    }
                }
                break;
            case MDNS_QUERY_TYPE_SRV:
            case MDNS_QUERY_TYPE_TXT:
            case MDNS_QUERY_TYPE_A:
                ins_name_len = req[12];
                memcpy(ins_name, &req[13], ins_name_len);
                srv_type_len = req[13 + ins_name_len];
                memcpy(srv_type, &req[14 + ins_name_len], srv_type_len);
                trans_type_len = req[14 + ins_name_len + srv_type_len];
                memcpy(trans_type, &req[15 + ins_name_len + srv_type_len], trans_type_len);
                ESP_LOGI(TAG, "query_type:0x%04X ins_name:%s srv_type:%s trans_type:%s", query_type, ins_name, srv_type, trans_type);

                for (j = 0; j < srv_cnt; j++) {
                    if (strlen(g_srv[j].ins_name) == ins_name_len && strncmp(g_srv[j].ins_name, ins_name, ins_name_len) == 0) {
                        if (strlen(g_srv[j].srv_type) == srv_type_len && strncmp(g_srv[j].srv_type, srv_type, srv_type_len) == 0) {
                            if (strlen(g_srv[j].trans_type) == trans_type_len && strncmp(g_srv[j].trans_type, trans_type, trans_type_len) == 0) {
                                resp[resp_len++] = ins_name_len;
                                memcpy(&resp[resp_len], ins_name, ins_name_len);
                                resp_len += ins_name_len;
                                resp[resp_len++] = srv_type_len;
                                memcpy(&resp[resp_len], srv_type, srv_type_len);
                                resp_len += srv_type_len;
                                resp[resp_len++] = trans_type_len;
                                memcpy(&resp[resp_len], trans_type, trans_type_len);
                                resp_len += trans_type_len;
                                resp[resp_len++] = strlen(domain);
                                memcpy(&resp[resp_len], domain, strlen(domain));
                                resp_len += strlen(domain);
                                resp[resp_len++] = 0;

                                resp[resp_len++] = query_type >> 8;
                                resp[resp_len++] = query_type;
                                resp[resp_len++] = 0x00;
                                resp[resp_len++] = 0x01; // class
                                resp[resp_len++] = CONFIG_MDNS_TTL >> 24;
                                resp[resp_len++] = CONFIG_MDNS_TTL >> 16;
                                resp[resp_len++] = CONFIG_MDNS_TTL >> 8;
                                resp[resp_len++] = (uint8_t)CONFIG_MDNS_TTL; // TTL

                                if (MDNS_QUERY_TYPE_SRV == query_type) {
                                    resp[resp_len++] = 0;
                                    resp[resp_len++] = 8; // data_len
                                    resp[resp_len++] = g_srv[j].priority >> 8;
                                    resp[resp_len++] = g_srv[j].priority;
                                    resp[resp_len++] = g_srv[j].weight >> 8;
                                    resp[resp_len++] = g_srv[j].weight;
                                    resp[resp_len++] = g_srv[j].port >> 8;
                                    resp[resp_len++] = g_srv[j].port;
                                    resp[resp_len++] = 0xc0;
                                    resp[resp_len++] = 0x0c;                                    
                                } else if (MDNS_QUERY_TYPE_TXT == query_type) {
                                    for (k = 0; k < g_srv[j].result_txt_cnt; k++) {
                                        data_len += 1;
                                        data_len += strlen(g_srv[j].txt[k].key) + 1 + strlen(g_srv[j].txt[k].value);
                                    }
                                    resp[resp_len++] = data_len >> 8;
                                    resp[resp_len++] = data_len; // data_len
                                    for (k = 0; k < g_srv[j].result_txt_cnt; k++) {
                                        resp[resp_len++] = strlen(g_srv[j].txt[k].key) + 1 + strlen(g_srv[j].txt[k].value);
                                        memcpy(&resp[resp_len], g_srv[j].txt[k].key, strlen(g_srv[j].txt[k].key));
                                        resp_len += strlen(g_srv[j].txt[k].key);
                                        resp[resp_len++] = '=';
                                        memcpy(&resp[resp_len], g_srv[j].txt[k].value, strlen(g_srv[j].txt[k].value));
                                        resp_len += strlen(g_srv[j].txt[k].value);
                                    }  
                                } else if (MDNS_QUERY_TYPE_A == query_type) {
                                    resp[resp_len++] = 0;
                                    resp[resp_len++] = 4; // data_len
                                    resp[resp_len++] = g_srv[j].srv_ipV4[3];
                                    resp[resp_len++] = g_srv[j].srv_ipV4[2];
                                    resp[resp_len++] = g_srv[j].srv_ipV4[1];
                                    resp[resp_len++] = g_srv[j].srv_ipV4[0];
                                }

                                if (!is_unicast_resp) {
                                    remote_addr.sin_family = AF_INET;
                                    remote_addr.sin_addr.s_addr = inet_addr(MDNS_MULTIPLE_UDP_IP);
                                    remote_addr.sin_port = htons(MDNS_MULTIPLE_UDP_PORT);
                                }                               
                                sendto(sock, resp, resp_len, 0, (struct sockaddr *)&remote_addr, remote_addr_len);
                                break;
                            }
                        }
                    }
                }
                break;
            default:
                ESP_LOGW(TAG, "unknown query_type:0x%04X", query_type);
                break;
            }
        }        
    }
}

static void mdns_test_cb(void *pvParameters) {
    esp_err_t err = ESP_OK;
    mdns_ptr_t result_ptr = {0};
    mdns_srv_t result_srv = {0};
    mdns_txt_t result_txt[5] = {0};
    uint32_t result_txt_cnt = 0;
    mdns_a_t result_a = {0};
    mdns_aaaa_t result_aaaa = {0};
    mdns_txt_t srv_txt[3] = {
        {
            .key = "board",
            .value = "ESP32"
        },
        {
            .key = "desc",
            .value = "hello world"
        },
        {
            .key = "id",
            .value = "56781234"
        }
    };
    uint32_t ip_addr = *((uint32_t *)pvParameters);
    uint8_t srv_ipV4[4] = {ip_addr >> 24, ip_addr >> 16, ip_addr >> 8, (uint8_t)ip_addr};
    uint32_t i = 0;

    mdns_init();

    ESP_LOGI(TAG, "query PTR, %s.%s.local", CONFIG_MDNS_SRVTYPE, CONFIG_MDNS_TRANSPORT);
    err = mdns_query_ptr(CONFIG_MDNS_SRVTYPE, CONFIG_MDNS_TRANSPORT, &result_ptr);
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "resp err:%d", err);
        goto exit;
    }
    ESP_LOGI(TAG, "ins_name:%s", result_ptr.ins_name);
    vTaskDelay(pdMS_TO_TICKS(1000));

    ESP_LOGI(TAG, "query SRV, %s.%s.%s.local", result_ptr.ins_name, CONFIG_MDNS_SRVTYPE, CONFIG_MDNS_TRANSPORT);
    err = mdns_query_srv(result_ptr.ins_name, CONFIG_MDNS_SRVTYPE, CONFIG_MDNS_TRANSPORT, &result_srv);
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "resp err:%d", err);
        goto exit;
    }
    ESP_LOGI(TAG, "priority:%u, weight:%u, port:%u, target:%s", result_srv.priority, result_srv.weight, result_srv.port, result_srv.target);
    vTaskDelay(pdMS_TO_TICKS(1000));

    ESP_LOGI(TAG, "query TXT, %s.%s.%s.local", result_ptr.ins_name, CONFIG_MDNS_SRVTYPE, CONFIG_MDNS_TRANSPORT);
    err = mdns_query_txt(result_ptr.ins_name, CONFIG_MDNS_SRVTYPE, CONFIG_MDNS_TRANSPORT, result_txt, &result_txt_cnt);
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "resp err:%d", err);
        goto exit;
    }
    for (i = 0; i < result_txt_cnt; i++) {
        ESP_LOGI(TAG, "%s:%s", result_txt[i].key, result_txt[i].value);
    }
    vTaskDelay(pdMS_TO_TICKS(1000));

    ESP_LOGI(TAG, "query A, %s.%s.%s.local", result_ptr.ins_name, CONFIG_MDNS_SRVTYPE, CONFIG_MDNS_TRANSPORT);
    err = mdns_query_a(result_ptr.ins_name, CONFIG_MDNS_SRVTYPE, CONFIG_MDNS_TRANSPORT, &result_a);
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "resp err:%d", err);
        goto exit;
    }
    ESP_LOGI(TAG, "ipV4:%u.%u.%u.%u", result_a.ip[0], result_a.ip[1], result_a.ip[2], result_a.ip[3]);
    vTaskDelay(pdMS_TO_TICKS(1000));

    ESP_LOGI(TAG, "query AAAA, %s.%s.%s.local", result_ptr.ins_name, CONFIG_MDNS_SRVTYPE, CONFIG_MDNS_TRANSPORT);
    err = mdns_query_aaaa(result_ptr.ins_name, CONFIG_MDNS_SRVTYPE, CONFIG_MDNS_TRANSPORT, &result_aaaa);
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "resp err:%d", err);
        goto exit;
    }
    ESP_LOGI(TAG, "ipV6:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
        result_aaaa.ip[0], result_aaaa.ip[1], result_aaaa.ip[2], result_aaaa.ip[3],
        result_aaaa.ip[4], result_aaaa.ip[5], result_aaaa.ip[6], result_aaaa.ip[7],
        result_aaaa.ip[8], result_aaaa.ip[9], result_aaaa.ip[10], result_aaaa.ip[11],
        result_aaaa.ip[12], result_aaaa.ip[13], result_aaaa.ip[14], result_aaaa.ip[15]);
    vTaskDelay(pdMS_TO_TICKS(1000));

exit:
    mdns_add_srv(CONFIG_MDNS_INSNAME, CONFIG_MDNS_SRVTYPE, CONFIG_MDNS_TRANSPORT, CONFIG_MDNS_SRV_PORT, srv_ipV4, NULL, srv_txt, sizeof(srv_txt) / sizeof(srv_txt[0]));
    mdns_wait_query();

    vTaskDelete(NULL);
}

static void event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    wifi_event_sta_connected_t *evt_sta_conn = NULL;
    wifi_event_sta_disconnected_t *evt_sta_disconn = NULL;
    ip_event_got_ip_t *evt_got_ip = NULL;

    if (WIFI_EVENT == event_base) {
        switch (event_id) {
        case WIFI_EVENT_STA_START:
            ESP_LOGI(TAG, "WIFI_EVENT_STA_START");
            ESP_LOGI(TAG, "wifi start connect, %s:%s", CONFIG_WIFI_STA_SSID, CONFIG_WIFI_STA_PWD);
            esp_wifi_connect();
            break;
        case WIFI_EVENT_STA_CONNECTED:
            evt_sta_conn = (wifi_event_sta_connected_t *)event_data;
            ESP_LOGI(TAG, "WIFI_EVENT_STA_CONNECTED, channel:%u authmode:0x%02x aid:0x%04x bssid:"MACSTR"",
                evt_sta_conn->channel, evt_sta_conn->authmode, evt_sta_conn->aid, MAC2STR(evt_sta_conn->bssid));
            break;
        case WIFI_EVENT_STA_DISCONNECTED:
            evt_sta_disconn = (wifi_event_sta_disconnected_t *)event_data; // reason:wifi_err_reason_t
            ESP_LOGE(TAG, "WIFI_EVENT_STA_DISCONNECTED, reason:0x%02x rssi:%d", evt_sta_disconn->reason, evt_sta_disconn->rssi);
            break;
        default:
            ESP_LOGW(TAG, "unknown WIFI_EVENT:%ld", event_id);
            break;
        }
    }

    if (IP_EVENT == event_base) {
        switch (event_id) {
        case IP_EVENT_STA_GOT_IP:
            evt_got_ip = (ip_event_got_ip_t *)event_data;
            ESP_LOGI(TAG, "IP_EVENT_STA_GOT_IP, ip:"IPSTR" netmask:"IPSTR" gw:"IPSTR"",
                IP2STR(&evt_got_ip->ip_info.ip), IP2STR(&evt_got_ip->ip_info.netmask), IP2STR(&evt_got_ip->ip_info.gw));
            xTaskCreate(mdns_test_cb, "mdns_test", 4096, &(evt_got_ip->ip_info.ip.addr), 5, NULL);
            break;
        case IP_EVENT_STA_LOST_IP:
            ESP_LOGE(TAG, "IP_EVENT_STA_LOST_IP");
            break;
        default:
            ESP_LOGW(TAG, "unknown IP_EVENT:%ld", event_id);
            break;
        }
    }
}

void app_main(void) {
    esp_err_t err = ESP_OK;
    wifi_init_config_t init_cfg = WIFI_INIT_CONFIG_DEFAULT();
    wifi_config_t sta_cfg = {
        .sta = {
            .ssid = CONFIG_WIFI_STA_SSID,
            .password = CONFIG_WIFI_STA_PWD,
        },
    };

    err = nvs_flash_init();
    if (ESP_ERR_NVS_NO_FREE_PAGES == err || ESP_ERR_NVS_NEW_VERSION_FOUND == err) {
        nvs_flash_erase();
        err = nvs_flash_init();
    }
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "nvs_flash_init error:%d", err);
        return;
    }

    esp_event_loop_create_default();
    esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, NULL);
    esp_event_handler_instance_register(IP_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, NULL);

    esp_netif_init();
    esp_netif_create_default_wifi_sta();

    esp_wifi_init(&init_cfg);
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_set_config(WIFI_IF_STA, &sta_cfg);
    esp_wifi_start();

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
