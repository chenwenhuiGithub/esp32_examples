#include <stdio.h>

#define CONFIG_I2C_PORT                         I2C_NUM_0
#define CONFIG_I2C_PIN_SDA                      21
#define CONFIG_I2C_PIN_SCL                      22
#define CONFIG_I2C_DEV_ADDR                     0x3C

typedef enum {
    CHAR_SIZE_6X8 = 0,
    CHAR_SIZE_8X16
} char_size_t;

typedef enum {
    POINT_STAT_OFF = 0,
    POINT_STAT_ON
} point_stat_t;

esp_err_t oled_init();
void oled_clear();
// x - 0~127, y - 0~7
void oled_show_char(uint8_t x, uint8_t y, uint8_t ch, char_size_t size);
// x - 0~127, y - 0~7
void oled_show_string(uint8_t x, uint8_t y, char *string, char_size_t size);
// x - 0~127, y - 0~7, size: 16*16
void oled_show_chinese(uint8_t x, uint8_t y, uint8_t *index, uint8_t num);
// x - 0~127, y - 0~63
void oled_show_point(uint8_t x, uint8_t y, point_stat_t stat);
// x - 0~127, y - 0~63, x1 <= x2
void oled_show_line(uint8_t x1, uint8_t y1, uint8_t x2, uint8_t y2, point_stat_t stat);
