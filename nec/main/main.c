#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_log.h"
#include "driver/rmt_tx.h"
#include "driver/rmt_rx.h"


#define CONFIG_IR_PIN_TX                            18
#define CONFIG_IR_PIN_RX                            19

#define NEC_DURATION_MARGIN                         200
#define NEC_DURATION_LEADING_0                      9000
#define NEC_DURATION_LEADING_1                      4500
#define NEC_DURATION_ZERO_0                         560
#define NEC_DURATION_ZERO_1                         560
#define NEC_DURATION_ONE_0                          560
#define NEC_DURATION_ONE_1                          1690
#define NEC_DURATION_ENDING_0                       560
#define NEC_DURATION_ENDING_1                       0x7FFF
#define NEC_DURATION_REPEAT_0                       9000
#define NEC_DURATION_REPEAT_1                       2250
#define NEC_FRAME_LEN                               4


typedef struct {
    rmt_encoder_t base;                 // the base "class", declares the standard encoder interface
    rmt_encoder_t *encoder_copy;        // use the encoder_copy to encode the leading and ending pulse
    rmt_encoder_t *encoder_bytes;       // use the encoder_bytes to encode the address and command data
    rmt_symbol_word_t symbol_leading;   // NEC leading code with RMT representation
    rmt_symbol_word_t symbol_ending;    // NEC ending code with RMT representation
} my_encoder_t;


static const char *TAG = "nec";
static rmt_channel_handle_t hd_rx_channel = NULL;
static rmt_channel_handle_t hd_tx_channel = NULL;
static QueueHandle_t hd_queue = NULL;
static rmt_encoder_handle_t hd_my_encoder = NULL;

static size_t my_encoder_encode(rmt_encoder_t *encoder, rmt_channel_handle_t tx_channel, const void *primary_data, size_t data_size, rmt_encode_state_t *ret_state) {
    my_encoder_t *my_encoder = __containerof(encoder, my_encoder_t, base);
    rmt_encode_state_t session_state = RMT_ENCODING_RESET;
    rmt_encoder_handle_t hd_encoder_copy = my_encoder->encoder_copy;
    rmt_encoder_handle_t hd_encoder_bytes = my_encoder->encoder_bytes;
    size_t encoded_symbols = 0;

    // send leading code
    encoded_symbols += hd_encoder_copy->encode(hd_encoder_copy, tx_channel, &my_encoder->symbol_leading, sizeof(rmt_symbol_word_t), &session_state);
    if (session_state & RMT_ENCODING_MEM_FULL) {
        *ret_state |= RMT_ENCODING_MEM_FULL;
        return encoded_symbols;
    }
    // send address and command
    encoded_symbols += hd_encoder_bytes->encode(hd_encoder_bytes, tx_channel, (uint8_t *)primary_data, NEC_FRAME_LEN, &session_state);
    if (session_state & RMT_ENCODING_MEM_FULL) {
        *ret_state |= RMT_ENCODING_MEM_FULL;
        return encoded_symbols;
    }
    // send ending code
    encoded_symbols += hd_encoder_copy->encode(hd_encoder_copy, tx_channel, &my_encoder->symbol_ending, sizeof(rmt_symbol_word_t), &session_state);
    if (session_state & RMT_ENCODING_MEM_FULL) {
        *ret_state |= RMT_ENCODING_MEM_FULL;
        return encoded_symbols;
    }
    *ret_state |= RMT_ENCODING_COMPLETE;

    return encoded_symbols;
}

static esp_err_t my_encoder_del(rmt_encoder_t *encoder) {
    my_encoder_t *my_encoder = __containerof(encoder, my_encoder_t, base);
    rmt_del_encoder(my_encoder->encoder_copy);
    rmt_del_encoder(my_encoder->encoder_bytes);
    free(my_encoder);

    return ESP_OK;
}

static esp_err_t my_encoder_reset(rmt_encoder_t *encoder) {
    my_encoder_t *my_encoder = __containerof(encoder, my_encoder_t, base);
    rmt_encoder_reset(my_encoder->encoder_copy);
    rmt_encoder_reset(my_encoder->encoder_bytes);

    return ESP_OK;
}

static rmt_encoder_handle_t create_my_encoder() {
    my_encoder_t *my_encoder = NULL;
    rmt_copy_encoder_config_t copy_encoder_cfg;
    rmt_bytes_encoder_config_t bytes_encoder_cfg = {
        .bit0 = {
            .level0 = 1,
            .duration0 = NEC_DURATION_ZERO_0, // tick, 560us
            .level1 = 0,
            .duration1 = NEC_DURATION_ZERO_1, // tick, 560us
        },
        .bit1 = {
            .level0 = 1,
            .duration0 = NEC_DURATION_ONE_0, // tick, 560us
            .level1 = 0,
            .duration1 = NEC_DURATION_ONE_1, // tick, 1690us
        },
    };

    my_encoder = rmt_alloc_encoder_mem(sizeof(my_encoder_t));
    my_encoder->base.encode = my_encoder_encode;
    my_encoder->base.del = my_encoder_del;
    my_encoder->base.reset = my_encoder_reset;
    my_encoder->symbol_leading = (rmt_symbol_word_t) {
        .level0 = 1,
        .duration0 = NEC_DURATION_LEADING_0, // tick, 9000us
        .level1 = 0,
        .duration1 = NEC_DURATION_LEADING_1, // tick, 4500us
    };
    my_encoder->symbol_ending = (rmt_symbol_word_t) {
        .level0 = 1,
        .duration0 = NEC_DURATION_ENDING_0, // tick, 560us
        .level1 = 0,
        .duration1 = NEC_DURATION_ENDING_1, // tick, 0x7FFF
    };
    rmt_new_copy_encoder(&copy_encoder_cfg, &my_encoder->encoder_copy);
    rmt_new_bytes_encoder(&bytes_encoder_cfg, &my_encoder->encoder_bytes);

    return &my_encoder->base;
}


static bool on_recv_done_cb(rmt_channel_handle_t channel, const rmt_rx_done_event_data_t *edata, void *user_data) {
    BaseType_t high_task_wakeup = pdFALSE;
    xQueueSendFromISR(hd_queue, edata, &high_task_wakeup);
    return high_task_wakeup == pdTRUE;
}

static inline bool nec_check_range(uint32_t signal, uint32_t spec) {
    return ((signal < (spec + NEC_DURATION_MARGIN)) && (signal > (spec - NEC_DURATION_MARGIN)));
}

static bool nec_parse_logic0(rmt_symbol_word_t symbol) {
    return (nec_check_range(symbol.duration0, NEC_DURATION_ZERO_0) && nec_check_range(symbol.duration1, NEC_DURATION_ZERO_1));
}

static bool nec_parse_logic1(rmt_symbol_word_t symbol) {
    return (nec_check_range(symbol.duration0, NEC_DURATION_ONE_0) && nec_check_range(symbol.duration1, NEC_DURATION_ONE_1));
}

void nec_parse_frame(rmt_symbol_word_t *symbols, size_t num) {
    uint32_t i = 0, i_bit = 0, i_byte = 0;
    uint8_t frame[NEC_FRAME_LEN] = {0};

    ESP_LOGI(TAG, "NEC symbols");
    for (i = 0; i < num; i++) {
        ESP_LOGI(TAG, "%lu: {%d:%d},{%d:%d}", i, symbols[i].level0, symbols[i].duration0, symbols[i].level1, symbols[i].duration1);
    }

    if (34 == num) {
        if (!(nec_check_range(symbols[0].duration0, NEC_DURATION_LEADING_0) && nec_check_range(symbols[0].duration1, NEC_DURATION_LEADING_1))) {
            ESP_LOGE(TAG, "invalid leading symbol");
            return;
        }

        i = 1;
        for (i_byte = 0; i_byte < NEC_FRAME_LEN; i_byte++) {
            for (i_bit = 0; i_bit < 8; i_bit++) {
                if (nec_parse_logic1(symbols[i])) {
                    frame[i_byte] |= 1 << i_bit;
                } else if (nec_parse_logic0(symbols[i])) {
                    frame[i_byte] &= ~(1 << i_bit);
                } else {
                    ESP_LOGE(TAG, "invalid data symbol:%lu", i);
                    return;
                }
                i++;
            }
        }
        ESP_LOGI(TAG, "%02X %02X %02X %02X", frame[0], frame[1], frame[2], frame[3]);
    } else if (2 == num) {
        if (nec_check_range(symbols[0].duration0, NEC_DURATION_REPEAT_0) && nec_check_range(symbols[0].duration1, NEC_DURATION_REPEAT_1)) {
            ESP_LOGI(TAG, "repeat frame");
        } else {
            ESP_LOGE(TAG, "invalid repeat symbol");
        }
    } else {
        ESP_LOGE(TAG, "unknown frame");
    }
}

void ir_send(uint8_t *data, uint32_t len) {
    rmt_transmit_config_t transmit_cfg = {
        .loop_count = 0, // no loop
    };

    rmt_transmit(hd_tx_channel, hd_my_encoder, data, len, &transmit_cfg);
}

void app_main(void) {
    rmt_rx_channel_config_t rx_channel_cfg = {
        .gpio_num = CONFIG_IR_PIN_RX,
        .clk_src = RMT_CLK_SRC_DEFAULT,
        .resolution_hz = 1000000, // 1MHz, 1 tick = 1us
        .mem_block_symbols = 64
    };
    rmt_tx_channel_config_t tx_channel_cfg = {
        .gpio_num = CONFIG_IR_PIN_TX,
        .clk_src = RMT_CLK_SRC_DEFAULT,
        .resolution_hz = 1000000, // 1MHz, 1 tick = 1us
        .mem_block_symbols = 64,
        .trans_queue_depth = 4
    };
    rmt_carrier_config_t carrier_cfg = {
        .frequency_hz = 38000,
        .duty_cycle = 0.33,
    };
    rmt_receive_config_t receive_cfg = {
        .signal_range_min_ns = 1250,     // the shortest duration for NEC signal is 560us, valid signal won't be treated as noise
        .signal_range_max_ns = 12000000, // the longest duration for NEC signal is 9000us, the receive won't stop early
    };
    rmt_rx_event_callbacks_t rx_evt_cbs = {
        .on_recv_done = on_recv_done_cb,
    };
    rmt_symbol_word_t symbol_words[64] = {0}; // standard NEC frame 34 symbols
    rmt_rx_done_event_data_t rx_evt_data = {0};

    hd_queue = xQueueCreate(1, sizeof(rmt_rx_done_event_data_t));
    hd_my_encoder = create_my_encoder();

    rmt_new_rx_channel(&rx_channel_cfg, &hd_rx_channel);
    rmt_rx_register_event_callbacks(hd_rx_channel, &rx_evt_cbs, NULL);
    rmt_new_tx_channel(&tx_channel_cfg, &hd_tx_channel);
    rmt_apply_carrier(hd_tx_channel, &carrier_cfg);
    rmt_enable(hd_tx_channel);
    rmt_enable(hd_rx_channel);
    
    rmt_receive(hd_rx_channel, symbol_words, sizeof(symbol_words), &receive_cfg);
    while (1) {
        if (xQueueReceive(hd_queue, &rx_evt_data, pdMS_TO_TICKS(1000)) == pdPASS) {
            nec_parse_frame(rx_evt_data.received_symbols, rx_evt_data.num_symbols);
            rmt_receive(hd_rx_channel, symbol_words, sizeof(symbol_words), &receive_cfg);
        }
    }
}
