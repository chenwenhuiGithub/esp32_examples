#include <string.h>
#include "driver/ledc.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"


#define CONFIG_GPIO_LED             2
#define CONFIG_GPIO_RGB_R           12
#define CONFIG_GPIO_RGB_G           13
#define CONFIG_GPIO_RGB_B           14
#define CONFIG_CHANNEL_LED          LEDC_CHANNEL_0
#define CONFIG_CHANNEL_RGB_R        LEDC_CHANNEL_1
#define CONFIG_CHANNEL_RGB_G        LEDC_CHANNEL_2
#define CONFIG_CHANNEL_RGB_B        LEDC_CHANNEL_3

#define CONFIG_LEDC_MODE            LEDC_LOW_SPEED_MODE
#define CONFIG_LEDC_FREQ            4000
#define CONFIG_LEDC_DUTY_RES        LEDC_TIMER_10_BIT
#define CONFIG_LEDC_DUTY_0          0
#define CONFIG_LEDC_DUTY_50         (1 << (CONFIG_LEDC_DUTY_RES - 1))
#define CONFIG_LEDC_DUTY_100        (1 << CONFIG_LEDC_DUTY_RES)
#define CONFIG_LEDC_FADE_MS         3000


#define RGB_TO_DUTY(x)              (x * (1 << CONFIG_LEDC_DUTY_RES) / 255)

#define OFF_R                       0
#define OFF_G                       0
#define OFF_B                       0

// RED - RGB:(255,0,0) HSV:(0,100,100)
#define RED_R                       RGB_TO_DUTY(255)
#define RED_G                       RGB_TO_DUTY(0)
#define RED_B                       RGB_TO_DUTY(0)

// GREEN - RGB:(0,255,0) HSV:(120,100,100)
#define GREEN_R                     RGB_TO_DUTY(0)
#define GREEN_G                     RGB_TO_DUTY(255)
#define GREEN_B                     RGB_TO_DUTY(0)

// BLUE - RGB:(0,0,255) HSV:(240,100,100)
#define BLUE_R                      RGB_TO_DUTY(0)
#define BLUE_G                      RGB_TO_DUTY(0)
#define BLUE_B                      RGB_TO_DUTY(255)

// YELLOW - RGB:(255,255,0) HSV:(60,100,100)
#define YELLOW_R                    RGB_TO_DUTY(255)
#define YELLOW_G                    RGB_TO_DUTY(255)
#define YELLOW_B                    RGB_TO_DUTY(0)

// CYAN - RGB:(0,255,255) HSV:(180,100,100)
#define CYAN_R                      RGB_TO_DUTY(0)
#define CYAN_G                      RGB_TO_DUTY(255)
#define CYAN_B                      RGB_TO_DUTY(255)

// MAGENTA - RGB:(255,0,255) HSV:(300,100,100)
#define MAGENTA_R                   RGB_TO_DUTY(255)
#define MAGENTA_G                   RGB_TO_DUTY(0)
#define MAGENTA_B                   RGB_TO_DUTY(255)

// BLUEISH PURPLE - RGB:(178,102,255) HSV:(270,60,100)
#define BLUEISH_PURPLE_R            RGB_TO_DUTY(178)
#define BLUEISH_PURPLE_G            RGB_TO_DUTY(102)
#define BLUEISH_PURPLE_B            RGB_TO_DUTY(255)


static void ledc_init() {
    ledc_timer_config_t ledc_timer_cfg = {
        .speed_mode             = CONFIG_LEDC_MODE,
        .duty_resolution        = CONFIG_LEDC_DUTY_RES,
        .timer_num              = LEDC_TIMER_0,
        .freq_hz                = CONFIG_LEDC_FREQ,
        .clk_cfg                = LEDC_AUTO_CLK
    };
    ledc_channel_config_t ledc_channel_cfg = {
        .gpio_num               = CONFIG_GPIO_LED,
        .speed_mode             = CONFIG_LEDC_MODE,
        .channel                = CONFIG_CHANNEL_LED,
        .intr_type              = LEDC_INTR_DISABLE,
        .timer_sel              = LEDC_TIMER_0,
        .duty                   = 0,
        .hpoint                 = 0,
        .flags.output_invert    = 0
    };

    ledc_timer_config(&ledc_timer_cfg);
    ledc_channel_config(&ledc_channel_cfg);

    ledc_channel_cfg.gpio_num = CONFIG_GPIO_RGB_R;
    ledc_channel_cfg.channel  = CONFIG_CHANNEL_RGB_R;
    ledc_channel_config(&ledc_channel_cfg);
    ledc_channel_cfg.gpio_num = CONFIG_GPIO_RGB_G;
    ledc_channel_cfg.channel  = CONFIG_CHANNEL_RGB_G;
    ledc_channel_config(&ledc_channel_cfg);
    ledc_channel_cfg.gpio_num = CONFIG_GPIO_RGB_B;
    ledc_channel_cfg.channel  = CONFIG_CHANNEL_RGB_B;
    ledc_channel_config(&ledc_channel_cfg);
}

static void led_set_fade_and_start(uint32_t duty) {
    ledc_set_fade_with_time(CONFIG_LEDC_MODE, CONFIG_CHANNEL_LED, duty, CONFIG_LEDC_FADE_MS);
    ledc_fade_start(CONFIG_LEDC_MODE, CONFIG_CHANNEL_LED, LEDC_FADE_NO_WAIT);
    vTaskDelay(pdMS_TO_TICKS(CONFIG_LEDC_FADE_MS));
}

static void rgb_set_fade_and_start(uint32_t duty_r, uint32_t duty_g, uint32_t duty_b) {
    ledc_set_fade_with_time(CONFIG_LEDC_MODE, CONFIG_CHANNEL_RGB_R, duty_r, CONFIG_LEDC_FADE_MS);
    ledc_set_fade_with_time(CONFIG_LEDC_MODE, CONFIG_CHANNEL_RGB_G, duty_g, CONFIG_LEDC_FADE_MS);
    ledc_set_fade_with_time(CONFIG_LEDC_MODE, CONFIG_CHANNEL_RGB_B, duty_b, CONFIG_LEDC_FADE_MS);
    ledc_fade_start(CONFIG_LEDC_MODE, CONFIG_CHANNEL_RGB_R, LEDC_FADE_NO_WAIT);
    ledc_fade_start(CONFIG_LEDC_MODE, CONFIG_CHANNEL_RGB_G, LEDC_FADE_NO_WAIT);
    ledc_fade_start(CONFIG_LEDC_MODE, CONFIG_CHANNEL_RGB_B, LEDC_FADE_NO_WAIT);
    vTaskDelay(pdMS_TO_TICKS(CONFIG_LEDC_FADE_MS));
}

void app_main(void) {
    ledc_init();
    ledc_fade_func_install(0);

    ledc_set_duty(CONFIG_LEDC_MODE, CONFIG_CHANNEL_LED, CONFIG_LEDC_DUTY_0);
    ledc_update_duty(CONFIG_LEDC_MODE, CONFIG_CHANNEL_LED);
    ledc_set_duty(CONFIG_LEDC_MODE, CONFIG_CHANNEL_RGB_R, CONFIG_LEDC_DUTY_0);
    ledc_update_duty(CONFIG_LEDC_MODE, CONFIG_CHANNEL_RGB_R);
    ledc_set_duty(CONFIG_LEDC_MODE, CONFIG_CHANNEL_RGB_G, CONFIG_LEDC_DUTY_0);
    ledc_update_duty(CONFIG_LEDC_MODE, CONFIG_CHANNEL_RGB_G);
    ledc_set_duty(CONFIG_LEDC_MODE, CONFIG_CHANNEL_RGB_B, CONFIG_LEDC_DUTY_0);
    ledc_update_duty(CONFIG_LEDC_MODE, CONFIG_CHANNEL_RGB_B);

    while (1) {
        led_set_fade_and_start(CONFIG_LEDC_DUTY_100);
        vTaskDelay(pdMS_TO_TICKS(100));

        led_set_fade_and_start(CONFIG_LEDC_DUTY_0);
        vTaskDelay(pdMS_TO_TICKS(100));


        rgb_set_fade_and_start(RED_R, RED_G, RED_B);
        vTaskDelay(pdMS_TO_TICKS(100));

        rgb_set_fade_and_start(GREEN_R, GREEN_G, GREEN_B);
        vTaskDelay(pdMS_TO_TICKS(100));

        rgb_set_fade_and_start(BLUE_R, BLUE_G, BLUE_B);
        vTaskDelay(pdMS_TO_TICKS(100));

        rgb_set_fade_and_start(YELLOW_R, YELLOW_G, YELLOW_B);
        vTaskDelay(pdMS_TO_TICKS(100));

        rgb_set_fade_and_start(CYAN_R, CYAN_G, CYAN_B);
        vTaskDelay(pdMS_TO_TICKS(100));

        rgb_set_fade_and_start(MAGENTA_R, MAGENTA_G, MAGENTA_B);
        vTaskDelay(pdMS_TO_TICKS(100));

        rgb_set_fade_and_start(BLUEISH_PURPLE_R, BLUEISH_PURPLE_G, BLUEISH_PURPLE_B);
        vTaskDelay(pdMS_TO_TICKS(100));

        rgb_set_fade_and_start(OFF_R, OFF_G, OFF_B);
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}
