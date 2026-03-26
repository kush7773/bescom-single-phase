/*
 * CCMS ESP32 — 1P2W Single-Phase Meter + AWS IoT Fleet Provisioning
 * =================================================================
 * Adapted from ccms_fleet_3p4w_arduinoeq_v3.c for 1P2W single-phase meter.
 *
 * Register map (1P2W CCMS, Modbus FC=0x04, slave 0x05):
 *
 *   30008  Voltage        1 reg  × 0.1    → V
 *   30009  Current        1 reg  × 0.01   → A
 *   30011  Active Power   1 reg  × 0.001  → kW
 *   30012  Power Factor   1 reg  × 0.01   → (0.00–1.00)
 *   30013  Frequency      1 reg  × 0.1    → Hz
 *   30015  Energy         2 regs × 0.1    → kWh  (big-endian uint32)
 *   30017  Apparent Enrgy 2 regs × 0.1    → kVAh (big-endian uint32)
 *   30025  Apparent Power 1 reg  × 0.001  → kVA
 *
 * Mapping to telemetry payload:
 *   r_voltage / r_current / r_pf / r_kw / r_kva = single-phase readings
 *   y_* and b_* fields are always 0 (single-phase has no Y/B phases)
 *
 * Hardware:
 *   RS485 TX → GPIO 17   RS485 RX → GPIO 16   RS485 DE → GPIO 4
 *   Slave ID : 0x05      Baud : 9600, 8N1      FC : 0x04 (Read Input Regs)
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <math.h>
#include <sys/time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_log.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_err.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_crt_bundle.h"

#include "nvs_flash.h"
#include "nvs.h"

#include "mqtt_client.h"
#include "cJSON.h"
#include "driver/gpio.h"
#include "driver/uart.h"

static const char *TAG = "ccms";

/* ========================================================================== */
/* Configuration                                                              */
/* ========================================================================== */
#define MQTT_BROKER_URI         "mqtts://ccms-iot.liege-microsystems.com"
#define MQTT_BROKER_PORT        8883
#define TEMPLATE_NAME           "cms-fleet-prod"
#define NVS_NAMESPACE           "ccms_certs"

#define PROVISION_TIMEOUT_MS    45000
#define MQTT_KEEPALIVE_PROV     30
#define MQTT_KEEPALIVE_DEV      60
#define WIFI_CONNECT_TIMEOUT_MS 60000
#define TELEMETRY_INTERVAL_MS   (15UL * 60UL * 1000UL)  /* 15 minutes */

#ifndef CONFIG_CCMS_WIFI_SSID
#define CONFIG_CCMS_WIFI_SSID     "YOUR_WIFI_SSID"
#endif
#ifndef CONFIG_CCMS_WIFI_PASSWORD
#define CONFIG_CCMS_WIFI_PASSWORD "YOUR_WIFI_PASSWORD"
#endif
#ifndef CONFIG_CCMS_WIFI_MAX_RETRY
#define CONFIG_CCMS_WIFI_MAX_RETRY 20
#endif

/* Fleet provisioning MQTT topics */
#define TOPIC_CREATE_CERT     "$aws/certificates/create/json"
#define TOPIC_CREATE_CERT_ACC "$aws/certificates/create/json/accepted"
#define TOPIC_CREATE_CERT_REJ "$aws/certificates/create/json/rejected"
#define TOPIC_PROVISION       "$aws/provisioning-templates/" TEMPLATE_NAME "/provision/json"
#define TOPIC_PROVISION_ACC   "$aws/provisioning-templates/" TEMPLATE_NAME "/provision/json/accepted"
#define TOPIC_PROVISION_REJ   "$aws/provisioning-templates/" TEMPLATE_NAME "/provision/json/rejected"

/* Event group bits */
#define BIT_CONNECTED     BIT0
#define BIT_SUBSCRIBED    BIT1
#define BIT_CERT_RECEIVED BIT2
#define BIT_PROV_ACCEPTED BIT3
#define BIT_ERROR         BIT4

#define MAX_TOPIC_LEN     256
#define MAX_MQTT_JSON_LEN 12288

/* ========================================================================== */
/* GPIO / UART pins                                                           */
/* ========================================================================== */
#define RS485_UART_NUM   UART_NUM_2
#define RS485_TX_PIN     GPIO_NUM_17
#define RS485_RX_PIN     GPIO_NUM_16
#define RS485_EN_PIN     GPIO_NUM_4   /* DE pin, active-HIGH for TX */

#define GPS_UART_NUM     UART_NUM_1
#define GPS_TX_PIN       GPIO_NUM_27
#define GPS_RX_PIN       GPIO_NUM_26

#define RELAY_SET_PIN    GPIO_NUM_25
#define RELAY_RESET_PIN  GPIO_NUM_33
#define POWER_RELAY_PIN  GPIO_NUM_32

#define IST_GMT_OFFSET_SEC 19800

/* ========================================================================== */
/* Modbus — 1P2W meter constants                                             */
/* ========================================================================== */
#define MB_SLAVE_ID  0x05
#define MB_FC        0x04   /* Read Input Registers */

/* ========================================================================== */
/* Embedded PEM blobs                                                         */
/* ========================================================================== */
extern const uint8_t root_ca_pem_start[]    asm("_binary_AmazonRootCA1_pem_start");
extern const uint8_t root_ca_pem_end[]      asm("_binary_AmazonRootCA1_pem_end");
extern const uint8_t claim_cert_pem_start[] asm("_binary_claim_certificate_pem_crt_start");
extern const uint8_t claim_cert_pem_end[]   asm("_binary_claim_certificate_pem_crt_end");
extern const uint8_t claim_key_pem_start[]  asm("_binary_claim_private_pem_key_start");
extern const uint8_t claim_key_pem_end[]    asm("_binary_claim_private_pem_key_end");

/* ========================================================================== */
/* Global state                                                               */
/* ========================================================================== */
static EventGroupHandle_t s_provision_events;
static EventGroupHandle_t s_wifi_events;

static char s_imei[16];
static char s_ownership_token[2048];
static char s_device_cert_pem[4096];
static char s_device_key_pem[4096];
static char s_thing_name[64];

static esp_mqtt_client_handle_t s_device_mqtt_client   = NULL;
static bool                     s_device_mqtt_connected = false;
static uint64_t                 s_last_telemetry_us     = 0;

/* Modbus state */
static bool         s_modbus_online          = false;
static uint64_t     s_last_modbus_detect_us  = 0;
static uint64_t     s_modbus_start_after_us  = 0;

/* Power-failure tracking */
static bool     s_is_battery_mode   = false;
static int      s_power_fail_buffer = 0;
static uint64_t s_last_power_check_us = 0;
static const uint64_t POWER_CHECK_INTERVAL_US = 1000ULL * 1000ULL;

static bool s_relay_on = false;

/* Fault tracking */
typedef struct { bool active; } fault_state_t;
static fault_state_t s_fault[16];

/* Wi-Fi */
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1
static int s_wifi_retry = 0;
static esp_event_handler_instance_t s_wifi_any_id_instance = NULL;
static esp_event_handler_instance_t s_wifi_got_ip_instance = NULL;

/* GPS */
typedef struct {
    double lat, lon;
    int year, month, day, hour, minute, second;
    bool loc_valid, time_valid;
} gps_fix_t;

static gps_fix_t s_gps            = {0};
static bool      s_gps_locked_once = false;
static int       s_sunrise_min     = -1;
static int       s_sunset_min      = -1;
static bool      s_solar_valid     = false;
static char      s_gps_line[128]   = {0};
static int       s_gps_line_len    = 0;

/* MQTT chunk accumulator */
typedef struct {
    char topic[MAX_TOPIC_LEN];
    char data[MAX_MQTT_JSON_LEN];
    int  total_len, collected;
    bool active;
} mqtt_chunk_accumulator_t;
static mqtt_chunk_accumulator_t s_acc = {0};

/* ========================================================================== */
/* 1P2W register map — pass reg_3xxxx directly (e.g. 30008 for voltage)     */
/* ========================================================================== */
#define REG_VOLTAGE  30008   /* 1 reg  × 0.1    → V      */
#define REG_CURRENT  30009   /* 1 reg  × 0.01   → A      */
#define REG_KW       30011   /* 1 reg  × 0.001  → kW     */
#define REG_PF       30012   /* 1 reg  × 0.01   → PF     */
#define REG_FREQ     30013   /* 1 reg  × 0.1    → Hz     */
#define REG_KWH      30015   /* 2 regs × 0.1    → kWh    */
#define REG_KVAH     30017   /* 2 regs × 0.1    → kVAh   */
#define REG_KVA      30025   /* 1 reg  × 0.001  → kVA    */

/* Fault thresholds */
#define FAULT_OV_THRESH   270.0f   /* Over Voltage   V > 270 V  */
#define FAULT_UV_THRESH   170.0f   /* Under Voltage  V < 170 V  */
#define FAULT_OL_THRESH    18.0f   /* Over Load      I > 18 A   */

/* Fault indices — single-phase */
typedef enum {
    FIDX_ROV = 0,
    FIDX_RUV,
    FIDX_OL,
    FIDX_ROL,
    FIDX_RPNl,
    FIDX_ACPFl,
    FIDX_MAX
} fault_idx_t;

/* ========================================================================== */
/* Utility                                                                    */
/* ========================================================================== */
static bool str_contains(const char *h, const char *n)
{
    return h && n && strstr(h, n) != NULL;
}

static bool pem_cert_is_valid(const char *p)
{
    return p && str_contains(p, "-----BEGIN CERTIFICATE-----") &&
           str_contains(p, "-----END CERTIFICATE-----") && strlen(p) >= 128;
}

static bool pem_key_is_valid(const char *p)
{
    return p && str_contains(p, "-----BEGIN") && str_contains(p, "PRIVATE KEY-----") &&
           str_contains(p, "-----END")   && strlen(p) >= 128;
}

static void safe_copy(char *dst, size_t sz, const char *src)
{
    if (!dst || !sz) return;
    if (!src) { dst[0] = '\0'; return; }
    strncpy(dst, src, sz - 1);
    dst[sz - 1] = '\0';
}

static float clamp_non_negative(float v) { return v < 0.0f ? 0.0f : v; }

/* Round to 2 decimal places — avoids IEEE-754 noise in JSON (e.g. 246.8000030...) */
static float round2(float v) { return roundf(v * 100.0f) / 100.0f; }

/* ========================================================================== */
/* NVS helpers                                                                */
/* ========================================================================== */
static esp_err_t nvs_save_device_certs(void)
{
    if (!pem_cert_is_valid(s_device_cert_pem) || !pem_key_is_valid(s_device_key_pem))
        return ESP_ERR_INVALID_ARG;
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = nvs_set_str(h, "dev_cert", s_device_cert_pem);
    if (err == ESP_OK) err = nvs_set_str(h, "dev_key",  s_device_key_pem);
    if (err == ESP_OK) err = nvs_set_str(h, "thing",    s_thing_name);
    if (err == ESP_OK) err = nvs_set_u8 (h, "provisioned", 1);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err;
}

static bool nvs_is_provisioned(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) != ESP_OK) return false;
    uint8_t flag = 0; char cert[256] = {0}, key[256] = {0};
    size_t csz = sizeof(cert), ksz = sizeof(key);
    esp_err_t ef = nvs_get_u8 (h, "provisioned", &flag);
    esp_err_t ec = nvs_get_str(h, "dev_cert", cert, &csz);
    esp_err_t ek = nvs_get_str(h, "dev_key",  key,  &ksz);
    nvs_close(h);
    if (ef != ESP_OK || flag != 1 || ec != ESP_OK || ek != ESP_OK) return false;
    return pem_cert_is_valid(cert) && pem_key_is_valid(key);
}

static esp_err_t nvs_clear_provisioned_flag(void)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = nvs_set_u8(h, "provisioned", 0);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err;
}

static esp_err_t nvs_load_device_certs(char *cert, size_t csz, char *key, size_t ksz)
{
    if (!cert || !csz || !key || !ksz) return ESP_ERR_INVALID_ARG;
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &h);
    if (err != ESP_OK) return err;
    size_t cn = csz, kn = ksz;
    err = nvs_get_str(h, "dev_cert", cert, &cn);
    if (err == ESP_OK) err = nvs_get_str(h, "dev_key",  key, &kn);
    nvs_close(h);
    if (err != ESP_OK) return err;
    if (!pem_cert_is_valid(cert) || !pem_key_is_valid(key)) return ESP_ERR_INVALID_CRC;
    return ESP_OK;
}

/* ========================================================================== */
/* IMEI                                                                       */
/* ========================================================================== */
static void read_device_imei(char *buf, size_t len)
{
#ifdef CONFIG_DEVICE_IMEI
    safe_copy(buf, len, CONFIG_DEVICE_IMEI);
#else
    safe_copy(buf, len, "123456789012345");
#endif
    ESP_LOGI(TAG, "Device IMEI: %s", buf);
}

/* ========================================================================== */
/* Wi-Fi                                                                      */
/* ========================================================================== */
static void wifi_event_handler(void *arg, esp_event_base_t base,
                               int32_t id, void *data)
{
    (void)arg;
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect(); return;
    }
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        s_wifi_retry++;
        if ((s_wifi_retry % 5) == 1)
            ESP_LOGW(TAG, "Wi-Fi disconnected, retry=%d", s_wifi_retry);
        xEventGroupClearBits(s_wifi_events, WIFI_CONNECTED_BIT);
        esp_wifi_connect(); return;
    }
    if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *ev = data;
        ESP_LOGI(TAG, "Wi-Fi connected, IP: " IPSTR, IP2STR(&ev->ip_info.ip));
        s_wifi_retry = 0;
        xEventGroupSetBits(s_wifi_events, WIFI_CONNECTED_BIT);
    }
}

static esp_err_t wifi_init_sta_blocking(void)
{
    if (!strcmp(CONFIG_CCMS_WIFI_SSID, "YOUR_WIFI_SSID")) {
        ESP_LOGE(TAG, "Set CCMS_WIFI_SSID in menuconfig"); return ESP_ERR_INVALID_ARG;
    }
    s_wifi_events = xEventGroupCreate();
    if (!s_wifi_events) return ESP_ERR_NO_MEM;

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                    &wifi_event_handler, NULL, &s_wifi_any_id_instance));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                    &wifi_event_handler, NULL, &s_wifi_got_ip_instance));

    wifi_config_t wc = {0};
    strncpy((char *)wc.sta.ssid,     CONFIG_CCMS_WIFI_SSID,     sizeof(wc.sta.ssid) - 1);
    strncpy((char *)wc.sta.password, CONFIG_CCMS_WIFI_PASSWORD,  sizeof(wc.sta.password) - 1);
    wc.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    wc.sta.pmf_cfg.capable    = true;
    wc.sta.pmf_cfg.required   = false;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wc));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));

    ESP_LOGI(TAG, "Connecting to Wi-Fi: %s", CONFIG_CCMS_WIFI_SSID);
    EventBits_t bits = xEventGroupWaitBits(s_wifi_events,
                                           WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
                                           pdFALSE, pdFALSE,
                                           pdMS_TO_TICKS(WIFI_CONNECT_TIMEOUT_MS));
    if (bits & WIFI_CONNECTED_BIT) return ESP_OK;
    if (bits & WIFI_FAIL_BIT)      return ESP_FAIL;
    return ESP_ERR_TIMEOUT;
}

/* ========================================================================== */
/* RS485 / Modbus — 1P2W (FC=0x04, 16-bit integer registers)                */
/* ========================================================================== */
static uint16_t mb_crc16(const uint8_t *buf, int len)
{
    uint16_t crc = 0xFFFF;
    for (int i = 0; i < len; i++) {
        crc ^= buf[i];
        for (int b = 0; b < 8; b++)
            crc = (crc & 1) ? ((crc >> 1) ^ 0xA001) : (crc >> 1);
    }
    return crc;
}

/*
 * mb_read_raw_try()
 * -----------------
 * Reads `words` × 16-bit input registers starting at the 0-based address
 * derived from `reg_3xxxx` (addr = reg_3xxxx - 30001).
 *
 * Uses FC=0x04 (Read Input Registers) as required by the 1P2W meter.
 * Sliding-window frame search to tolerate echo bytes or leading garbage.
 * 500 ms receive window — sufficient for 9600 baud response latency.
 */
static bool mb_read_raw_try(uint16_t reg_3xxxx, uint16_t words,
                            uint8_t *out, size_t out_sz)
{
    if (!out || out_sz < (size_t)(words * 2)) return false;

    uint16_t addr = reg_3xxxx - 30001;
    uint8_t req[8] = {
        MB_SLAVE_ID, MB_FC,
        (uint8_t)(addr >> 8),  (uint8_t)(addr & 0xFF),
        (uint8_t)(words >> 8), (uint8_t)(words & 0xFF),
        0, 0
    };
    uint16_t crc = mb_crc16(req, 6);
    req[6] = (uint8_t)(crc & 0xFF);
    req[7] = (uint8_t)(crc >> 8);

    /* --- TX --- */
    uart_flush_input(RS485_UART_NUM);
    gpio_set_level(RS485_EN_PIN, 1);
    uart_write_bytes(RS485_UART_NUM, (const char *)req, 8);
    uart_wait_tx_done(RS485_UART_NUM, pdMS_TO_TICKS(200));
    gpio_set_level(RS485_EN_PIN, 0);

    /* 250 ms settle — matches Arduino behaviour */
    vTaskDelay(pdMS_TO_TICKS(250));

    /* --- RX: collect bytes for up to 500 ms total --- */
    uint8_t buf[64];
    int     got = 0;
    uint64_t deadline = esp_timer_get_time() + 500000ULL;

    while (got < (int)sizeof(buf) && esp_timer_get_time() < deadline) {
        int n = uart_read_bytes(RS485_UART_NUM, buf + got,
                                (int)sizeof(buf) - got, pdMS_TO_TICKS(20));
        if (n > 0) got += n;
    }

    if (got <= 0) {
        ESP_LOGW(TAG, "MB TIMEOUT slave=0x%02X reg=%u", MB_SLAVE_ID, addr);
        return false;
    }

    /*
     * Sliding-window search for a valid FC=0x04 response frame.
     * Expected: slave_id | 0x04 | byte_count | data... | crc_lo | crc_hi
     *   byte_count = words*2
     *   total frame length = 5 + words*2
     */
    int expected = 5 + (words * 2);
    for (int i = 0; i <= got - expected; i++) {
        if (buf[i]   != MB_SLAVE_ID)        continue;
        if (buf[i+1] != MB_FC)              continue;
        if (buf[i+2] != (uint8_t)(words*2)) continue;

        uint16_t rx_crc   = ((uint16_t)buf[i + expected - 1] << 8) | buf[i + expected - 2];
        uint16_t calc_crc = mb_crc16(&buf[i], expected - 2);
        if (rx_crc != calc_crc) {
            ESP_LOGW(TAG, "MB CRC mismatch at offset %d (rx=0x%04x calc=0x%04x)",
                     i, rx_crc, calc_crc);
            continue;
        }

        memcpy(out, &buf[i + 3], words * 2);
        return true;
    }

    ESP_LOGW(TAG, "MB no valid frame in %d bytes (slave=0x%02X reg=%u)",
             got, MB_SLAVE_ID, addr);
    return false;
}

/*
 * mb_read_reg1()
 * --------------
 * Reads one 16-bit input register and returns (raw × scale).
 * Register value is big-endian: bytes [hi][lo].
 */
static float mb_read_reg1(uint16_t reg_3xxxx, float scale)
{
    uint8_t data[2] = {0};
    if (!mb_read_raw_try(reg_3xxxx, 1, data, sizeof(data))) return -1.0f;
    uint16_t raw = ((uint16_t)data[0] << 8) | data[1];
    return (float)raw * scale;
}

/*
 * mb_read_reg2()
 * --------------
 * Reads two consecutive 16-bit input registers as a big-endian uint32
 * and returns (raw × scale).
 * Byte order from meter: [b3][b2][b1][b0] → raw = b3<<24|b2<<16|b1<<8|b0
 */
static float mb_read_reg2(uint16_t reg_3xxxx, float scale)
{
    uint8_t data[4] = {0};
    if (!mb_read_raw_try(reg_3xxxx, 2, data, sizeof(data))) return -1.0f;
    uint32_t raw = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
                   ((uint32_t)data[2] <<  8) |  (uint32_t)data[3];
    return (float)raw * scale;
}

static void modbus_detect_if_needed(void)
{
    uint64_t now = esp_timer_get_time();
    if ((now - s_last_modbus_detect_us) < 8ULL * 1000ULL * 1000ULL) return;
    s_last_modbus_detect_us = now;

    /* Probe with frequency register — always non-zero when meter is live */
    uint8_t tmp[2] = {0};
    if (mb_read_raw_try(REG_FREQ, 1, tmp, sizeof(tmp))) {
        if (!s_modbus_online)
            ESP_LOGI(TAG, "Modbus online (slave=0x%02X, 9600,8N1, FC=0x04)", MB_SLAVE_ID);
        s_modbus_online = true;
    } else {
        s_modbus_online = false;
    }
}

/* ========================================================================== */
/* Relay (active-low latch)                                                  */
/* ========================================================================== */
static void relay_on(void)
{
    gpio_set_level(RELAY_RESET_PIN, 1);
    gpio_set_level(RELAY_SET_PIN,   0);
    vTaskDelay(pdMS_TO_TICKS(200));
    gpio_set_level(RELAY_SET_PIN,   1);
    s_relay_on = true;
    ESP_LOGI(TAG, "Relay ON");
}

static void relay_off(void)
{
    gpio_set_level(RELAY_SET_PIN,   1);
    gpio_set_level(RELAY_RESET_PIN, 0);
    vTaskDelay(pdMS_TO_TICKS(200));
    gpio_set_level(RELAY_RESET_PIN, 1);
    s_relay_on = false;
    ESP_LOGI(TAG, "Relay OFF");
}

/* ========================================================================== */
/* GPS                                                                        */
/* ========================================================================== */
static double nmea_to_deg(const char *v, char h)
{
    if (!v || !*v) return 0.0;
    double raw = atof(v); int deg = (int)(raw / 100.0);
    double out = (double)deg + (raw - deg * 100.0) / 60.0;
    if (h == 'S' || h == 'W') out = -out;
    return out;
}
static bool parse_hhmmss(const char *s, int *hh, int *mm, int *ss)
{
    if (!s || strlen(s) < 6) return false;
    *hh = (s[0]-'0')*10+(s[1]-'0');
    *mm = (s[2]-'0')*10+(s[3]-'0');
    *ss = (s[4]-'0')*10+(s[5]-'0');
    return true;
}
static bool parse_ddmmyy(const char *s, int *dd, int *mm, int *yy)
{
    if (!s || strlen(s) < 6) return false;
    *dd = (s[0]-'0')*10+(s[1]-'0');
    *mm = (s[2]-'0')*10+(s[3]-'0');
    *yy = 2000+(s[4]-'0')*10+(s[5]-'0');
    return true;
}
static int nmea_fields(char *s, char **f, int max)
{
    if (!s || !f || max <= 0) return 0;
    int n = 0; f[n++] = s;
    for (char *p = s; *p && n < max; p++) if (*p == ',') { *p = '\0'; f[n++] = p+1; }
    return n;
}
static void gps_parse_line(const char *line)
{
    if (!line || line[0] != '$') return;
    char buf[128] = {0}; strncpy(buf, line, 127);
    char *star = strchr(buf, '*'); if (star) *star = '\0';
    char *tok[24] = {0}; int n = nmea_fields(buf, tok, 24);
    if (n < 2) return;
    if (!strcmp(tok[0], "$GPRMC") || !strcmp(tok[0], "$GNRMC")) {
        if (n < 10) return;
        if (tok[2] && tok[2][0] == 'A') {
            s_gps.lat = nmea_to_deg(tok[3], tok[4] ? tok[4][0] : 'N');
            s_gps.lon = nmea_to_deg(tok[5], tok[6] ? tok[6][0] : 'E');
            s_gps.loc_valid = true;
        }
        int hh, mm, ss, dd, mo, yy;
        if (parse_hhmmss(tok[1], &hh, &mm, &ss) && parse_ddmmyy(tok[9], &dd, &mo, &yy)) {
            s_gps.hour = hh; s_gps.minute = mm; s_gps.second = ss;
            s_gps.day = dd; s_gps.month = mo; s_gps.year = yy;
            s_gps.time_valid = (yy > 2023);
        }
    } else if (!strcmp(tok[0], "$GPGGA") || !strcmp(tok[0], "$GNGGA")) {
        if (n < 7) return;
        if (tok[6] && atoi(tok[6]) > 0) {
            s_gps.lat = nmea_to_deg(tok[2], tok[3] ? tok[3][0] : 'N');
            s_gps.lon = nmea_to_deg(tok[4], tok[5] ? tok[5][0] : 'E');
            s_gps.loc_valid = true;
        }
    }
}
static void gps_poll_uart(void)
{
    uint8_t ch;
    while (uart_read_bytes(GPS_UART_NUM, &ch, 1, 0) == 1) {
        if (ch == '\r') continue;
        if (ch == '\n') {
            s_gps_line[s_gps_line_len] = '\0';
            if (s_gps_line_len > 6) gps_parse_line(s_gps_line);
            s_gps_line_len = 0; continue;
        }
        if (s_gps_line_len < (int)sizeof(s_gps_line) - 1)
            s_gps_line[s_gps_line_len++] = (char)ch;
        else
            s_gps_line_len = 0;
    }
}

static int64_t days_from_civil(int y, unsigned m, unsigned d)
{
    y -= m <= 2; int era = (y >= 0 ? y : y-399)/400;
    unsigned yoe = (unsigned)(y - era*400);
    unsigned doy = (153*(m+(m>2?-3:9))+2)/5+d-1;
    unsigned doe = yoe*365+yoe/4-yoe/100+doy;
    return era*146097+(int64_t)doe-719468;
}
static void sync_time_from_gps(void)
{
    if (!s_gps.time_valid) return;
    int64_t days = days_from_civil(s_gps.year, (unsigned)s_gps.month, (unsigned)s_gps.day);
    int64_t sec  = days*86400LL + s_gps.hour*3600 + s_gps.minute*60 + s_gps.second;
    struct timeval tv = {.tv_sec = sec, .tv_usec = 0};
    settimeofday(&tv, NULL);
}

static const double PI2 = 3.14159265358979323846;
static int calc_sun_minutes(bool sunrise)
{
    if (!s_gps.loc_valid) return -1;
    time_t now = time(NULL); struct tm t = {0}; localtime_r(&now, &t);
    if ((t.tm_year+1900) < 2023) return -1;
    int N = t.tm_yday + 1;
    double lh = s_gps.lon / 15.0;
    double T  = sunrise ? N+((6.0-lh)/24.0) : N+((18.0-lh)/24.0);
    double M  = (0.9856*T) - 3.289;
    double L  = fmod(M+(1.916*sin(M*PI2/180.0))+(0.020*sin(2*M*PI2/180.0))+282.634+360.0, 360.0);
    double RA = fmod(atan(0.91764*tan(L*PI2/180.0))*180.0/PI2+360.0, 360.0)/15.0;
    double sinD = 0.39782*sin(L*PI2/180.0);
    double cosD = cos(asin(sinD));
    double cosH = (cos(90.833*PI2/180.0)-sinD*sin(s_gps.lat*PI2/180.0)) /
                  (cosD*cos(s_gps.lat*PI2/180.0));
    if (cosH > 1 || cosH < -1) return -1;
    double H  = sunrise ? (360.0 - acos(cosH)*180.0/PI2) : (acos(cosH)*180.0/PI2);
    H /= 15.0;
    double UT = fmod(H+RA-(0.06571*T)-6.622-lh+48.0, 24.0);
    int m = ((int)(UT*60.0) + (IST_GMT_OFFSET_SEC/60)) % 1440;
    if (m < 0) m += 1440;
    return m;
}
static void format_hhmm(int m, char *out, size_t sz)
{
    if (m < 0) { snprintf(out, sz, "--:--"); return; }
    snprintf(out, sz, "%02d:%02d", m/60, m%60);
}
static void solar_load_from_nvs(void)
{
    nvs_handle_t h;
    if (nvs_open("solar_data", NVS_READONLY, &h) != ESP_OK) return;
    nvs_get_i32(h, "sr_min", (int32_t *)&s_sunrise_min);
    nvs_get_i32(h, "ss_min", (int32_t *)&s_sunset_min);
    size_t lsz = sizeof(double), osz = sizeof(double);
    double lat = 0.0, lon = 0.0;
    if (nvs_get_blob(h, "lat", &lat, &lsz) == ESP_OK &&
        nvs_get_blob(h, "lng", &lon, &osz) == ESP_OK) {
        s_gps.lat = lat; s_gps.lon = lon; s_gps.loc_valid = true;
    }
    nvs_close(h);
    s_solar_valid = (s_sunrise_min >= 0 && s_sunset_min >= 0);
}
static void solar_save_to_nvs(void)
{
    nvs_handle_t h;
    if (nvs_open("solar_data", NVS_READWRITE, &h) != ESP_OK) return;
    nvs_set_i32(h, "sr_min", s_sunrise_min);
    nvs_set_i32(h, "ss_min", s_sunset_min);
    nvs_set_blob(h, "lat", &s_gps.lat, sizeof(s_gps.lat));
    nvs_set_blob(h, "lng", &s_gps.lon, sizeof(s_gps.lon));
    nvs_commit(h); nvs_close(h);
}
static void gps_solar_update(void)
{
    gps_poll_uart();
    if (!s_gps.loc_valid) return;
    if (!s_gps_locked_once) {
        s_gps_locked_once = true;
        ESP_LOGI(TAG, "GPS fix: lat=%.6f lon=%.6f", s_gps.lat, s_gps.lon);
    }
    sync_time_from_gps();
    int sr = calc_sun_minutes(true), ss = calc_sun_minutes(false);
    if (sr >= 0 && ss >= 0) {
        s_sunrise_min = sr; s_sunset_min = ss; s_solar_valid = true;
        solar_save_to_nvs();
    }
}

/* ========================================================================== */
/* Power-failure logic — single phase (only R/line voltage checked)          */
/* ========================================================================== */
static void update_power_failure_logic(float rv)
{
    uint64_t now = esp_timer_get_time();
    if ((now - s_last_power_check_us) < POWER_CHECK_INTERVAL_US) return;
    s_last_power_check_us = now;

    if (!s_modbus_online) {
        if (s_is_battery_mode) {
            s_is_battery_mode = false;
            gpio_set_level(POWER_RELAY_PIN, 0);
        }
        return;
    }

    bool dead = (rv < 50.0f);
    if (dead) s_power_fail_buffer++; else s_power_fail_buffer = 0;

    if (s_power_fail_buffer >= 3 && !s_is_battery_mode) {
        gpio_set_level(POWER_RELAY_PIN, 1);
        s_is_battery_mode = true;
        ESP_LOGW(TAG, "AC power fail -> battery mode");
    } else if (s_power_fail_buffer == 0 && s_is_battery_mode) {
        gpio_set_level(POWER_RELAY_PIN, 0);
        s_is_battery_mode = false;
        ESP_LOGI(TAG, "AC restored");
    }
}

/* ========================================================================== */
/* Fault publishing                                                           */
/* ========================================================================== */
static void publish_fault(const char *code, bool active)
{
    if (!s_device_mqtt_client || !s_device_mqtt_connected) return;
    char topic[80]; snprintf(topic, sizeof(topic), "evt/%s/fault", s_imei);
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "alarmCode", code);
    cJSON_AddBoolToObject(root, "active", active);
    char *p = cJSON_PrintUnformatted(root);
    if (p) {
        esp_mqtt_client_publish(s_device_mqtt_client, topic, p, 0, 1, 0);
        ESP_LOGI(TAG, "Fault %s active=%d", code, active);
        free(p);
    }
    cJSON_Delete(root);
}

/*
 * Single-phase fault checks:
 *   ROV  — over voltage  (V > 270)
 *   RUV  — under voltage (0 < V < 170)
 *   OL   — over load     (I > 18 A)
 *   ROL  — phase over load (same threshold for single phase)
 *   RPNl — no load       (relay on, V present, I ≈ 0)
 *   ACPFl— AC power fail (battery mode active)
 */
static void check_and_publish_faults(float rv, float ri)
{
#define CHK(idx, code, cond) do { \
    bool _now = (cond); \
    if (_now != s_fault[idx].active) { \
        s_fault[idx].active = _now; \
        publish_fault(code, _now); \
    } \
} while(0)

    CHK(FIDX_ROV,   "ROV",   rv > FAULT_OV_THRESH);
    CHK(FIDX_RUV,   "RUV",   rv > 0 && rv < FAULT_UV_THRESH);
    CHK(FIDX_OL,    "OL",    ri > FAULT_OL_THRESH);
    CHK(FIDX_ROL,   "ROL",   ri > FAULT_OL_THRESH);
    CHK(FIDX_RPNl,  "RPNl",  s_relay_on && rv > 50 && ri < 0.1f);
    CHK(FIDX_ACPFl, "ACPFl", s_is_battery_mode);

#undef CHK
}

/* Build a bitmask of currently active faults for the telemetry fault_code field */
static int build_fault_code(void)
{
    int code = 0;
    for (int i = 0; i < FIDX_MAX; i++) {
        if (s_fault[i].active) code |= (1 << i);
    }
    return code;
}

/* ========================================================================== */
/* Telemetry                                                                  */
/* ========================================================================== */
static void iso_time_utc(char *out, size_t sz)
{
    time_t now = time(NULL); struct tm t = {0};
    gmtime_r(&now, &t);
    strftime(out, sz, "%Y-%m-%dT%H:%M:%SZ", &t);
}

static void publish_telemetry_now(void)
{
    if (!s_device_mqtt_client || !s_device_mqtt_connected) return;
    gps_solar_update();

    /* --- Read all single-phase registers --- */
    float rv   = clamp_non_negative(mb_read_reg1(REG_VOLTAGE, 0.1f));    /* V    */
    float ri   = clamp_non_negative(mb_read_reg1(REG_CURRENT, 0.01f));   /* A    */
    float rkw  = clamp_non_negative(mb_read_reg1(REG_KW,      0.001f));  /* kW   */
    float rpf  = mb_read_reg1(REG_PF, 0.01f);
    if (rpf < 0 || rpf > 1.0f) rpf = 0.0f;
    float freq = clamp_non_negative(mb_read_reg1(REG_FREQ, 0.1f));       /* Hz   */
    float kwh  = clamp_non_negative(mb_read_reg2(REG_KWH,  0.1f));       /* kWh  */
    float kvah = clamp_non_negative(mb_read_reg2(REG_KVAH, 0.1f));       /* kVAh */
    float rkva = clamp_non_negative(mb_read_reg1(REG_KVA,  0.001f));     /* kVA  */

    /* Y and B phase — always zero for single-phase meter */
    const float yv = 0.0f, yi = 0.0f, yfreq = 0.0f, ypf = 0.0f, ykw = 0.0f, ykva = 0.0f;
    const float bv = 0.0f, bi = 0.0f, bfreq = 0.0f, bpf = 0.0f, bkw = 0.0f, bkva = 0.0f;

    /* Overall totals come from the single phase */
    float tkw  = rkw;
    float tkva = rkva;
    float apf  = rpf;

    /* --- Power failure & fault logic --- */
    update_power_failure_logic(rv);
    check_and_publish_faults(rv, ri);

    /* --- Build payload --- */
    char topic[64], ts[32] = {0}, sr[8] = {0}, ss_s[8] = {0};
    snprintf(topic, sizeof(topic), "dt/%s", s_imei);
    iso_time_utc(ts, sizeof(ts));
    format_hhmm(s_sunrise_min, sr,   sizeof(sr));
    format_hhmm(s_sunset_min,  ss_s, sizeof(ss_s));

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "device_id",     s_imei);
    cJSON_AddStringToObject(root, "time",           ts);
    cJSON_AddBoolToObject  (root, "on_off",         s_relay_on);
    cJSON_AddNumberToObject(root, "fault_code",     build_fault_code());
    cJSON_AddNumberToObject(root, "latt",           s_gps.loc_valid ? round2((float)s_gps.lat) : 0.0);
    cJSON_AddNumberToObject(root, "long",           s_gps.loc_valid ? round2((float)s_gps.lon) : 0.0);
    cJSON_AddStringToObject(root, "box_no",         "");
    cJSON_AddStringToObject(root, "nsl",            "0");
    cJSON_AddStringToObject(root, "nwsl",           "0");
    cJSON_AddStringToObject(root, "mode",           "Auto(A)");
    cJSON_AddStringToObject(root, "sun_set_time",   ss_s);
    cJSON_AddStringToObject(root, "sun_rise_time",  sr);
    cJSON_AddNumberToObject(root, "no_lights_on",   0);

    /* Overall */
    cJSON_AddNumberToObject(root, "voltage_v",  round2(rv));
    cJSON_AddNumberToObject(root, "current_a",  round2(ri));
    cJSON_AddNumberToObject(root, "frequency",  round2(freq));
    cJSON_AddNumberToObject(root, "pf",         round2(apf));
    cJSON_AddNumberToObject(root, "kw",         round2(tkw));
    cJSON_AddNumberToObject(root, "kwh",        round2(kwh));
    cJSON_AddNumberToObject(root, "kva",        round2(tkva));
    cJSON_AddNumberToObject(root, "kvah",       round2(kvah));

    /* R-phase (= single-phase readings) */
    cJSON_AddNumberToObject(root, "r_voltage",   round2(rv));
    cJSON_AddNumberToObject(root, "r_current",   round2(ri));
    cJSON_AddNumberToObject(root, "r_frequency", round2(freq));
    cJSON_AddNumberToObject(root, "r_pf",        round2(rpf));
    cJSON_AddNumberToObject(root, "r_kw",        round2(rkw));
    cJSON_AddNumberToObject(root, "r_kva",       round2(rkva));

    /* Y-phase — always 0 (no Y phase on single-phase meter) */
    cJSON_AddNumberToObject(root, "y_voltage",   yv);
    cJSON_AddNumberToObject(root, "y_current",   yi);
    cJSON_AddNumberToObject(root, "y_frequency", yfreq);
    cJSON_AddNumberToObject(root, "y_pf",        ypf);
    cJSON_AddNumberToObject(root, "y_kw",        ykw);
    cJSON_AddNumberToObject(root, "y_kva",       ykva);

    /* B-phase — always 0 (no B phase on single-phase meter) */
    cJSON_AddNumberToObject(root, "b_voltage",   bv);
    cJSON_AddNumberToObject(root, "b_current",   bi);
    cJSON_AddNumberToObject(root, "b_frequency", bfreq);
    cJSON_AddNumberToObject(root, "b_pf",        bpf);
    cJSON_AddNumberToObject(root, "b_kw",        bkw);
    cJSON_AddNumberToObject(root, "b_kva",       bkva);

    /* Debug fields */
    cJSON_AddBoolToObject  (root, "modbus_online",   s_modbus_online);
    cJSON_AddBoolToObject  (root, "gps_locked_once", s_gps_locked_once);
    cJSON_AddStringToObject(root, "power_source",    s_is_battery_mode ? "BATTERY" : "AC_ADAPTER");

    char *payload = cJSON_PrintUnformatted(root);
    if (payload) {
        int mid = esp_mqtt_client_publish(s_device_mqtt_client, topic, payload, 0, 1, 0);
        ESP_LOGI(TAG, "Telemetry published mid=%d | V=%.1f I=%.2f kW=%.3f"
                 " kWh=%.1f kVA=%.3f PF=%.2f freq=%.1f modbus=%s",
                 mid, rv, ri, rkw, kwh, rkva, rpf, freq,
                 s_modbus_online ? "OK" : "NO");
        free(payload);
    }
    cJSON_Delete(root);
}

/* ========================================================================== */
/* Device MQTT subscriptions                                                  */
/* ========================================================================== */
static void subscribe_device_topics(esp_mqtt_client_handle_t client)
{
    char t[160];
    snprintf(t, sizeof(t), "cmd/%s/report",  s_imei);
    esp_mqtt_client_subscribe(client, t, 1);
    snprintf(t, sizeof(t), "cmd/%s/control", s_imei);
    esp_mqtt_client_subscribe(client, t, 1);

    /* OTA Jobs */
    snprintf(t, sizeof(t), "$aws/things/%s/jobs/notify",           s_imei);
    esp_mqtt_client_subscribe(client, t, 1);
    snprintf(t, sizeof(t), "$aws/things/%s/jobs/get/accepted",     s_imei);
    esp_mqtt_client_subscribe(client, t, 1);
    snprintf(t, sizeof(t), "$aws/things/%s/jobs/get/rejected",     s_imei);
    esp_mqtt_client_subscribe(client, t, 1);
    snprintf(t, sizeof(t), "$aws/things/%s/jobs/+/get/accepted",   s_imei);
    esp_mqtt_client_subscribe(client, t, 1);
    snprintf(t, sizeof(t), "$aws/things/%s/jobs/+/update/accepted",s_imei);
    esp_mqtt_client_subscribe(client, t, 1);
    snprintf(t, sizeof(t), "$aws/things/%s/jobs/+/update/rejected",s_imei);
    esp_mqtt_client_subscribe(client, t, 1);

    /* Poll for pending jobs on connect */
    snprintf(t, sizeof(t), "$aws/things/%s/jobs/get", s_imei);
    char pay[64]; snprintf(pay, sizeof(pay), "{\"clientToken\":\"%s\"}", s_imei);
    esp_mqtt_client_publish(client, t, pay, 0, 1, 0);
}

static void mqtt_device_handler(void *arg, esp_event_base_t base,
                                int32_t eid, void *edata)
{
    (void)arg; (void)base;
    esp_mqtt_event_handle_t ev = edata;

    switch ((esp_mqtt_event_id_t)eid) {
    case MQTT_EVENT_CONNECTED:
        s_device_mqtt_connected = true;
        ESP_LOGI(TAG, "Device MQTT connected");
        subscribe_device_topics(ev->client);
        publish_telemetry_now();
        break;

    case MQTT_EVENT_DISCONNECTED:
        s_device_mqtt_connected = false;
        ESP_LOGW(TAG, "Device MQTT disconnected");
        break;

    case MQTT_EVENT_DATA: {
        if (!ev->topic || ev->topic_len <= 0) break;
        char topic[160] = {0};
        int tl = ev->topic_len < (int)sizeof(topic)-1 ? ev->topic_len : (int)sizeof(topic)-1;
        memcpy(topic, ev->topic, tl);

        char report_t[96];  snprintf(report_t,  sizeof(report_t),  "cmd/%s/report",  s_imei);
        char control_t[96]; snprintf(control_t, sizeof(control_t), "cmd/%s/control", s_imei);

        if (!strcmp(topic, report_t)) {
            cJSON *r = cJSON_ParseWithLength(ev->data, ev->data_len);
            if (r) {
                cJSON *a = cJSON_GetObjectItem(r, "action");
                if (cJSON_IsString(a) && !strcmp(a->valuestring, "report"))
                    publish_telemetry_now();
                cJSON_Delete(r);
            }
        } else if (!strcmp(topic, control_t)) {
            cJSON *r = cJSON_ParseWithLength(ev->data, ev->data_len);
            if (r) {
                cJSON *rel = cJSON_GetObjectItem(r, "relay");
                cJSON *oo  = cJSON_GetObjectItem(r, "on_off");
                if (cJSON_IsString(rel)) {
                    if (!strcmp(rel->valuestring, "ON"))  relay_on();
                    if (!strcmp(rel->valuestring, "OFF")) relay_off();
                } else if (cJSON_IsBool(oo)) {
                    if (cJSON_IsTrue(oo)) relay_on(); else relay_off();
                }
                publish_telemetry_now();
                cJSON_Delete(r);
            }
        }
        /* OTA Jobs handler stub */
        break;
    }
    default: break;
    }
}

/* ========================================================================== */
/* MQTT chunk accumulator (provisioning)                                      */
/* ========================================================================== */
static void acc_reset(void) { memset(&s_acc, 0, sizeof(s_acc)); }

static bool acc_accept_chunk(const esp_mqtt_event_handle_t ev,
                             char *tout, size_t tsz, char *jout, size_t jsz)
{
    if (!ev || !tout || !jout) return false;
    char topic[MAX_TOPIC_LEN] = {0};
    int tlen = ev->topic_len;

    if (ev->current_data_offset == 0) {
        if (tlen <= 0 || tlen >= MAX_TOPIC_LEN || !ev->topic) {
            xEventGroupSetBits(s_provision_events, BIT_ERROR); return false;
        }
        memcpy(topic, ev->topic, tlen); topic[tlen] = '\0';
    } else {
        if (!s_acc.topic[0]) {
            xEventGroupSetBits(s_provision_events, BIT_ERROR); return false;
        }
        safe_copy(topic, sizeof(topic), s_acc.topic);
    }

    if (ev->total_data_len <= 0 || ev->total_data_len >= MAX_MQTT_JSON_LEN) {
        xEventGroupSetBits(s_provision_events, BIT_ERROR); return false;
    }
    if (ev->current_data_offset == 0) {
        acc_reset();
        safe_copy(s_acc.topic, sizeof(s_acc.topic), topic);
        s_acc.total_len = ev->total_data_len; s_acc.active = true;
    }
    if (!s_acc.active || strcmp(s_acc.topic, topic) != 0) {
        xEventGroupSetBits(s_provision_events, BIT_ERROR); return false;
    }
    if (ev->current_data_offset != s_acc.collected) {
        xEventGroupSetBits(s_provision_events, BIT_ERROR); return false;
    }
    int cl = ev->data_len;
    if ((s_acc.collected + cl) >= (int)sizeof(s_acc.data)) {
        xEventGroupSetBits(s_provision_events, BIT_ERROR); return false;
    }
    memcpy(&s_acc.data[s_acc.collected], ev->data, cl);
    s_acc.collected += cl; s_acc.data[s_acc.collected] = '\0';
    if (s_acc.collected < s_acc.total_len) return false;
    safe_copy(tout, tsz, s_acc.topic);
    safe_copy(jout, jsz, s_acc.data);
    acc_reset(); return true;
}

/* ========================================================================== */
/* Provisioning MQTT event handler                                            */
/* ========================================================================== */
static void handle_create_cert_accepted(esp_mqtt_client_handle_t client, cJSON *root)
{
    cJSON *cert  = cJSON_GetObjectItem(root, "certificatePem");
    cJSON *key   = cJSON_GetObjectItem(root, "privateKey");
    cJSON *token = cJSON_GetObjectItem(root, "certificateOwnershipToken");
    if (!cJSON_IsString(cert) || !cJSON_IsString(key) || !cJSON_IsString(token)) {
        xEventGroupSetBits(s_provision_events, BIT_ERROR); return;
    }
    safe_copy(s_device_cert_pem, sizeof(s_device_cert_pem), cert->valuestring);
    safe_copy(s_device_key_pem,  sizeof(s_device_key_pem),  key->valuestring);
    safe_copy(s_ownership_token, sizeof(s_ownership_token),  token->valuestring);
    if (!pem_cert_is_valid(s_device_cert_pem) || !pem_key_is_valid(s_device_key_pem)) {
        xEventGroupSetBits(s_provision_events, BIT_ERROR); return;
    }
    ESP_LOGI(TAG, "Cert received (%u/%u bytes)",
             (unsigned)strlen(s_device_cert_pem), (unsigned)strlen(s_device_key_pem));
    xEventGroupSetBits(s_provision_events, BIT_CERT_RECEIVED);

    cJSON *prov   = cJSON_CreateObject();
    cJSON *params = cJSON_CreateObject();
    cJSON_AddStringToObject(prov,   "certificateOwnershipToken", s_ownership_token);
    cJSON_AddStringToObject(params, "SerialNumber", s_imei);
    cJSON_AddItemToObject(prov, "parameters", params);
    char *payload = cJSON_PrintUnformatted(prov);
    if (payload) {
        esp_mqtt_client_publish(client, TOPIC_PROVISION, payload, 0, 1, 0);
        free(payload);
    }
    cJSON_Delete(prov);
}

static void handle_provision_accepted(cJSON *root)
{
    cJSON *thing = cJSON_GetObjectItem(root, "thingName");
    safe_copy(s_thing_name, sizeof(s_thing_name),
              (cJSON_IsString(thing) && thing->valuestring[0]) ? thing->valuestring : s_imei);
    ESP_LOGI(TAG, "Thing registered: %s", s_thing_name);
    xEventGroupSetBits(s_provision_events, BIT_PROV_ACCEPTED);
}

static void mqtt_provision_handler(void *arg, esp_event_base_t base,
                                   int32_t eid, void *edata)
{
    (void)arg; (void)base;
    esp_mqtt_event_handle_t ev = edata;
    esp_mqtt_client_handle_t client = ev->client;

    switch ((esp_mqtt_event_id_t)eid) {
    case MQTT_EVENT_CONNECTED:
        esp_mqtt_client_subscribe(client, TOPIC_CREATE_CERT_ACC, 1);
        esp_mqtt_client_subscribe(client, TOPIC_CREATE_CERT_REJ, 1);
        esp_mqtt_client_subscribe(client, TOPIC_PROVISION_ACC,   1);
        esp_mqtt_client_subscribe(client, TOPIC_PROVISION_REJ,   1);
        xEventGroupSetBits(s_provision_events, BIT_CONNECTED);
        break;
    case MQTT_EVENT_SUBSCRIBED: {
        static int sc = 0; sc++;
        if (sc >= 4) { sc = 0;
            esp_mqtt_client_publish(client, TOPIC_CREATE_CERT, "{}", 0, 1, 0);
            xEventGroupSetBits(s_provision_events, BIT_SUBSCRIBED);
        }
        break;
    }
    case MQTT_EVENT_DATA: {
        static char topic[MAX_TOPIC_LEN]; static char json[MAX_MQTT_JSON_LEN];
        if (!acc_accept_chunk(ev, topic, sizeof(topic), json, sizeof(json))) break;
        cJSON *root = cJSON_Parse(json);
        if (!root) { xEventGroupSetBits(s_provision_events, BIT_ERROR); break; }
        if      (!strcmp(topic, TOPIC_CREATE_CERT_ACC)) handle_create_cert_accepted(client, root);
        else if (!strcmp(topic, TOPIC_CREATE_CERT_REJ)) xEventGroupSetBits(s_provision_events, BIT_ERROR);
        else if (!strcmp(topic, TOPIC_PROVISION_ACC))   handle_provision_accepted(root);
        else if (!strcmp(topic, TOPIC_PROVISION_REJ))   xEventGroupSetBits(s_provision_events, BIT_ERROR);
        cJSON_Delete(root);
        break;
    }
    case MQTT_EVENT_ERROR:
        xEventGroupSetBits(s_provision_events, BIT_ERROR);
        break;
    default: break;
    }
}

/* ========================================================================== */
/* Fleet provisioning                                                         */
/* ========================================================================== */
static esp_err_t ccms_fleet_provision(void)
{
    if (nvs_is_provisioned()) { ESP_LOGI(TAG, "Already provisioned"); return ESP_OK; }
    read_device_imei(s_imei, sizeof(s_imei));
    s_provision_events = xEventGroupCreate();
    if (!s_provision_events) return ESP_ERR_NO_MEM;

    char cid[32]; snprintf(cid, sizeof(cid), "factory-%s", s_imei);
    esp_mqtt_client_config_t cfg = {
        .broker     = { .address      = { .uri = MQTT_BROKER_URI, .port = MQTT_BROKER_PORT },
                        .verification = { .crt_bundle_attach = esp_crt_bundle_attach } },
        .credentials = { .client_id   = cid,
                         .authentication = { .certificate = (const char *)claim_cert_pem_start,
                                             .key         = (const char *)claim_key_pem_start } },
        .session     = { .keepalive   = MQTT_KEEPALIVE_PROV },
    };
    esp_mqtt_client_handle_t client = esp_mqtt_client_init(&cfg);
    if (!client) { vEventGroupDelete(s_provision_events); return ESP_ERR_NO_MEM; }
    esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, mqtt_provision_handler, NULL);

    esp_err_t err = esp_mqtt_client_start(client);
    if (err != ESP_OK) {
        esp_mqtt_client_destroy(client); vEventGroupDelete(s_provision_events);
        return err;
    }
    EventBits_t bits = xEventGroupWaitBits(s_provision_events, BIT_PROV_ACCEPTED | BIT_ERROR,
                                           pdTRUE, pdFALSE, pdMS_TO_TICKS(PROVISION_TIMEOUT_MS));
    esp_mqtt_client_stop(client); esp_mqtt_client_destroy(client);
    vEventGroupDelete(s_provision_events); s_provision_events = NULL;

    if (bits & BIT_ERROR)           return ESP_FAIL;
    if (!(bits & BIT_PROV_ACCEPTED)) return ESP_ERR_TIMEOUT;

    err = nvs_save_device_certs();
    if (err != ESP_OK) return err;
    ESP_LOGI(TAG, "Provisioning complete, thing=%s", s_thing_name);
    return ESP_OK;
}

/* ========================================================================== */
/* Device connect                                                             */
/* ========================================================================== */
static esp_mqtt_client_handle_t ccms_connect_device(void)
{
    static char cert[4096], key[4096];
    if (s_imei[0] == '\0') read_device_imei(s_imei, sizeof(s_imei));
    if (nvs_load_device_certs(cert, sizeof(cert), key, sizeof(key)) != ESP_OK) {
        ESP_LOGE(TAG, "Cert load failed"); nvs_clear_provisioned_flag(); return NULL;
    }
    esp_mqtt_client_config_t cfg = {
        .broker      = { .address      = { .uri = MQTT_BROKER_URI, .port = MQTT_BROKER_PORT },
                         .verification = { .crt_bundle_attach = esp_crt_bundle_attach } },
        .credentials = { .client_id    = s_imei,
                         .authentication = { .certificate = cert, .key = key } },
        .session     = { .keepalive    = MQTT_KEEPALIVE_DEV },
    };
    esp_mqtt_client_handle_t client = esp_mqtt_client_init(&cfg);
    if (!client) return NULL;
    esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, mqtt_device_handler, NULL);
    if (esp_mqtt_client_start(client) != ESP_OK) {
        esp_mqtt_client_destroy(client); return NULL;
    }
    s_device_mqtt_client = client;
    return client;
}

/* ========================================================================== */
/* Hardware init                                                              */
/* ========================================================================== */
static void ccms_hw_init(void)
{
    gpio_config_t io = {
        .pin_bit_mask = (1ULL << RS485_EN_PIN) | (1ULL << RELAY_SET_PIN) |
                        (1ULL << RELAY_RESET_PIN) | (1ULL << POWER_RELAY_PIN),
        .mode         = GPIO_MODE_OUTPUT,
        .pull_up_en   = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    ESP_ERROR_CHECK(gpio_config(&io));
    gpio_set_level(RS485_EN_PIN,    0);
    gpio_set_level(POWER_RELAY_PIN, 0);
    gpio_set_level(RELAY_SET_PIN,   1);
    gpio_set_level(RELAY_RESET_PIN, 1);
    relay_off();

    uart_config_t mb = {
        .baud_rate  = 9600,
        .data_bits  = UART_DATA_8_BITS,
        .parity     = UART_PARITY_DISABLE,
        .stop_bits  = UART_STOP_BITS_1,
        .flow_ctrl  = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_APB
    };
    ESP_ERROR_CHECK(uart_driver_install(RS485_UART_NUM, 1024, 0, 0, NULL, 0));
    ESP_ERROR_CHECK(uart_param_config(RS485_UART_NUM, &mb));
    ESP_ERROR_CHECK(uart_set_pin(RS485_UART_NUM, RS485_TX_PIN, RS485_RX_PIN,
                                 UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));

    uart_config_t gps = {
        .baud_rate  = 9600,
        .data_bits  = UART_DATA_8_BITS,
        .parity     = UART_PARITY_DISABLE,
        .stop_bits  = UART_STOP_BITS_1,
        .flow_ctrl  = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_APB
    };
    ESP_ERROR_CHECK(uart_driver_install(GPS_UART_NUM, 1024, 0, 0, NULL, 0));
    ESP_ERROR_CHECK(uart_param_config(GPS_UART_NUM, &gps));
    ESP_ERROR_CHECK(uart_set_pin(GPS_UART_NUM, GPS_TX_PIN, GPS_RX_PIN,
                                 UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));

    solar_load_from_nvs();
    ESP_LOGI(TAG, "HW init done — RS485 UART2 TX=%d RX=%d DE=%d slave=0x%02X FC=0x%02X",
             RS485_TX_PIN, RS485_RX_PIN, RS485_EN_PIN, MB_SLAVE_ID, MB_FC);
}

/* ========================================================================== */
/* app_main                                                                   */
/* ========================================================================== */
void app_main(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    }

    ccms_hw_init();

    ret = wifi_init_sta_blocking();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Wi-Fi failed, restarting in 15s");
        vTaskDelay(pdMS_TO_TICKS(15000)); esp_restart();
    }

    read_device_imei(s_imei, sizeof(s_imei));

    ret = ccms_fleet_provision();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Provisioning failed, restarting in 30s");
        vTaskDelay(pdMS_TO_TICKS(30000)); esp_restart();
    }

    if (!ccms_connect_device()) {
        ESP_LOGE(TAG, "Device connect failed, restarting");
        esp_restart();
    }

    ESP_LOGI(TAG, "Device online — 1P2W single-phase mode, starting main loop");
    s_modbus_start_after_us = esp_timer_get_time() + 5000000ULL; /* 5 s warm-up */

    while (1) {
        gps_solar_update();

        uint64_t now = esp_timer_get_time();
        if (now >= s_modbus_start_after_us) {
            modbus_detect_if_needed();
        }

        if (s_last_telemetry_us == 0 ||
            (now - s_last_telemetry_us) >= (TELEMETRY_INTERVAL_MS * 1000ULL)) {
            publish_telemetry_now();
            s_last_telemetry_us = now;
        }
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
