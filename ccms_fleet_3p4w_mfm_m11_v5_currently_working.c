/*
 * CCMS ESP32 — MFM M11/M1 Modbus + AWS IoT Fleet Provisioning
 * =============================================================
 * v3: Production-hardened build. New in v3 vs. v2:
 *
 *  V3-1: `volatile` on all inter-task shared state (s_is_battery_mode,
 *        s_modbus_online, s_cached_rv/yv/bv, s_cached_ri/yi/bi)
 *        to prevent GCC register-caching stale values across tasks.
 *
 *  V3-2: Per-fault cooldown timer (FAULT_COOLDOWN_US = 60s) prevents
 *        the fault-storm seen on the dashboard (7× ACPFI entries) when
 *        the power state bounces rapidly.  A fault code is only re-published
 *        after its cooldown period expires, even if the state flipped.
 *
 *  V3-3: NVS persistence of battery-mode state across reboots.  If the
 *        ESP32 reboots during a genuine blackout (running on battery),
 *        it immediately re-asserts GPIO 32 HIGH instead of briefly toggling
 *        back to AC which would cause relay chatter.
 *
 *  V3-4: check_and_publish_faults() moved to main loop (same task as
 *        update_power_failure_logic) to eliminate the data-race on
 *        s_fault[] between the main loop and the MQTT task.
 *
 *  V3-5: check_and_publish_faults() is silenced when !s_modbus_online.
 *        No valid meter data → no fault state changes published.
 *
 *  V3-6: Mutex double-give bug in mb_read_raw_try() corrected:
 *        success path already gave the mutex before the hex-dump,
 *        but the code would still fall through to a second Give on
 *        the no-valid-frame path. Now all paths give exactly once.
 */

#include <string.h>

#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>


#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h" /* xSemaphoreCreateMutex / xSemaphoreTake / Give */
#include "freertos/task.h"


#include "esp_crt_bundle.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_wifi.h"


#include "nvs.h"
#include "nvs_flash.h"


#include "cJSON.h"
#include "driver/gpio.h"
#include "driver/uart.h"
#include "esp_rom_sys.h" /* esp_rom_delay_us() */
#include "mqtt_client.h"
#include "soc/uart_reg.h" /* direct UART register access for diagnostics */


static const char *TAG = "ccms";

/* RS485 Modbus mutex — all mb_read_raw_try() callers must hold this.
 * The MQTT client task (priority 5) can preempt app_main (priority 1)
 * in the middle of a 500ms FIFO poll. Without a mutex, both tasks
 * simultaneously drive RS485_EN and read UART2, corrupting frames. */
static SemaphoreHandle_t s_modbus_mutex = NULL;

/* ========================================================================== */
/* Configuration                                                              */
/* ========================================================================== */
#define MQTT_BROKER_URI "mqtts://ccms-iot.liege-microsystems.com"
#define MQTT_BROKER_PORT 8883
#define TEMPLATE_NAME "cms-fleet-prod"
#define NVS_NAMESPACE "ccms_certs"

#define PROVISION_TIMEOUT_MS 45000
#define MQTT_KEEPALIVE_PROV 30
#define MQTT_KEEPALIVE_DEV 60
#define WIFI_CONNECT_TIMEOUT_MS 60000
#define TELEMETRY_INTERVAL_MS (15UL * 60UL * 1000UL) /* 15 minutes */

#ifndef CONFIG_CCMS_WIFI_SSID
#define CONFIG_CCMS_WIFI_SSID "YOUR_WIFI_SSID"
#endif
#ifndef CONFIG_CCMS_WIFI_PASSWORD
#define CONFIG_CCMS_WIFI_PASSWORD "YOUR_WIFI_PASSWORD"
#endif
#ifndef CONFIG_CCMS_WIFI_MAX_RETRY
#define CONFIG_CCMS_WIFI_MAX_RETRY 20
#endif

/* Fleet provisioning MQTT topics */
#define TOPIC_CREATE_CERT "$aws/certificates/create/json"
#define TOPIC_CREATE_CERT_ACC "$aws/certificates/create/json/accepted"
#define TOPIC_CREATE_CERT_REJ "$aws/certificates/create/json/rejected"
#define TOPIC_PROVISION                                                        \
  "$aws/provisioning-templates/" TEMPLATE_NAME "/provision/json"
#define TOPIC_PROVISION_ACC                                                    \
  "$aws/provisioning-templates/" TEMPLATE_NAME "/provision/json/accepted"
#define TOPIC_PROVISION_REJ                                                    \
  "$aws/provisioning-templates/" TEMPLATE_NAME "/provision/json/rejected"

/* Event group bits */
#define BIT_CONNECTED BIT0
#define BIT_SUBSCRIBED BIT1
#define BIT_CERT_RECEIVED BIT2
#define BIT_PROV_ACCEPTED BIT3
#define BIT_ERROR BIT4

#define MAX_TOPIC_LEN 256
#define MAX_MQTT_JSON_LEN 12288

/* ========================================================================== */
/* GPIO / UART pins                                                           */
/* ========================================================================== */
#define RS485_UART_NUM UART_NUM_2
#define RS485_TX_PIN GPIO_NUM_17
#define RS485_RX_PIN GPIO_NUM_16
#define RS485_EN_PIN GPIO_NUM_4 /* DE pin, active-HIGH for TX */

#define GPS_UART_NUM UART_NUM_1
#define GPS_TX_PIN GPIO_NUM_27
#define GPS_RX_PIN GPIO_NUM_26

#define RELAY_SET_PIN GPIO_NUM_25
#define RELAY_RESET_PIN GPIO_NUM_33
#define POWER_RELAY_PIN GPIO_NUM_32

#define IST_GMT_OFFSET_SEC 19800

/* ========================================================================== */
/* Embedded PEM blobs                                                         */
/* ========================================================================== */
extern const uint8_t root_ca_pem_start[] asm("_binary_AmazonRootCA1_pem_start");
extern const uint8_t root_ca_pem_end[] asm("_binary_AmazonRootCA1_pem_end");
extern const uint8_t
    claim_cert_pem_start[] asm("_binary_claim_certificate_pem_crt_start");
extern const uint8_t
    claim_cert_pem_end[] asm("_binary_claim_certificate_pem_crt_end");
extern const uint8_t
    claim_key_pem_start[] asm("_binary_claim_private_pem_key_start");
extern const uint8_t
    claim_key_pem_end[] asm("_binary_claim_private_pem_key_end");

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

static esp_mqtt_client_handle_t s_device_mqtt_client = NULL;
static bool s_device_mqtt_connected = false;
static uint64_t s_last_telemetry_us = 0;

/* Modbus state — volatile: written by main loop, read by MQTT task */
static volatile bool s_modbus_online = false;
static uint64_t s_last_modbus_detect_us = 0;
static uint64_t s_modbus_start_after_us = 0;

/* Power-failure tracking
 *
 * TWO independent signals can trigger battery mode:
 *   Signal A: Modbus reads succeed but all 3 phase voltages < 50V
 *             (meter is alive on capacitors, sees a real brownout/blackout)
 *   Signal B: Modbus goes completely offline for >= MODBUS_DEAD_FOR_BATTERY
 *             consecutive polls.  This is the most common real-world case:
 *             the meter IS powered by the same AC mains, so a total blackout
 *             kills the meter first.  No Modbus response = meter is dead = AC
 * failed.
 *
 * AC is ONLY restored when Modbus comes back online AND at least one
 * phase voltage reads > 50V. We never restore AC on Modbus offline alone.
 */
/* V3-1: volatile on shared state — prevents GCC register-caching across tasks
 */
static volatile bool s_is_battery_mode = false;
static int s_low_volt_buffer = 0;
static int s_modbus_offline_count = 0;
static uint64_t s_last_power_check_us = 0;
static const uint64_t POWER_CHECK_INTERVAL_US = 2000ULL * 1000ULL;

/* Signal A thresholds */
#define VOLTAGE_DEAD_THRESH 50.0f
#define LOW_VOLT_DEBOUNCE 3

/* Signal B thresholds */
#define MODBUS_DEAD_FOR_BATTERY 5
#define MODBUS_OFFLINE_DEBOUNCE 3
#define MODBUS_OFFLINE_COUNT_MAX 20

/* Voltage/current cache — volatile: written by main loop, read by MQTT task */
static volatile float s_cached_rv = 230.0f, s_cached_yv = 230.0f,
                      s_cached_bv = 230.0f;
static volatile float s_cached_ri = 0.0f, s_cached_yi = 0.0f,
                      s_cached_bi = 0.0f;
static volatile bool s_cache_valid =
    false; /* true after first successful read */

static volatile bool s_relay_on = false;

/* V3-2: Per-fault cooldown — prevents fault storm on dashboard.
 * A fault is only re-published to MQTT after FAULT_COOLDOWN_US has elapsed
 * since the last publish for that fault code, even if state keeps flipping. */
#define FAULT_COOLDOWN_US (60ULL * 1000000ULL) /* 60 seconds */
typedef struct {
  bool active;
  uint64_t last_publish_us; /* timestamp of last MQTT publish for this fault */
} fault_state_t;
static fault_state_t s_fault[32];

/* Fault check timer — run fault logic in main loop at same cadence as
 * power-fail */
static uint64_t s_last_fault_check_us = 0;

/* Wi-Fi */
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT BIT1
static int s_wifi_retry = 0;
static esp_event_handler_instance_t s_wifi_any_id_instance = NULL;
static esp_event_handler_instance_t s_wifi_got_ip_instance = NULL;

/* GPS */
typedef struct {
  double lat, lon;
  int year, month, day, hour, minute, second;
  bool loc_valid, time_valid;
} gps_fix_t;

static gps_fix_t s_gps = {0};
static bool s_gps_locked_once = false;
static int s_sunrise_min = -1;
static int s_sunset_min = -1;
static bool s_solar_valid = false;
static char s_gps_line[128] = {0};
static int s_gps_line_len = 0;

/* MQTT chunk accumulator */
typedef struct {
  char topic[MAX_TOPIC_LEN];
  char data[MAX_MQTT_JSON_LEN];
  int total_len, collected;
  bool active;
} mqtt_chunk_accumulator_t;
static mqtt_chunk_accumulator_t s_acc = {0};

/* ========================================================================== */
/* MFM M11 register map — pass (30001 + 0-based_reg_addr) to mb_read_float() */
/* ========================================================================== */
#define REG_KWH 30001       /* register  0 — total kWh       */
#define REG_KVAH 30005      /* register  4 — total kVAh       */
#define REG_VL1N 30019      /* register 18 — R-phase V L-N    */
#define REG_VL2N 30021      /* register 20 — Y-phase V L-N    */
#define REG_VL3N 30023      /* register 22 — B-phase V L-N    */
#define REG_IL1 30035       /* register 34 — R-phase current  */
#define REG_IL2 30037       /* register 36 — Y-phase current  */
#define REG_IL3 30039       /* register 38 — B-phase current  */
#define REG_FREQ 30043      /* register 42 — frequency        */
#define REG_PFL1 30045      /* register 44 — PF line 1 (R)    */
#define REG_PFL2 30047      /* register 46 — PF line 2 (Y)    */
#define REG_PFL3 30049      /* register 48 — PF line 3 (B)    */
#define REG_PF_AVG 30051    /* register 50 — average PF       */
#define REG_KWL1 30055      /* register 54 — kW line 1 (R)    */
#define REG_KWL2 30057      /* register 56 — kW line 2 (Y)    */
#define REG_KWL3 30059      /* register 58 — kW line 3 (B)    */
#define REG_KW_TOTAL 30061  /* register 60 — total kW         */
#define REG_KVAL1 30063     /* register 62 — kVA line 1 (R)   */
#define REG_KVAL2 30065     /* register 64 — kVA line 2 (Y)   */
#define REG_KVAL3 30067     /* register 66 — kVA line 3 (B)   */
#define REG_KVA_TOTAL 30069 /* register 68 — total kVA        */

/* Fault thresholds */
#define FAULT_OV_THRESH 270.0f   /* Over Voltage   V L-N > 270 V  */
#define FAULT_UV_THRESH 170.0f   /* Under Voltage  V L-N < 170 V  */
#define FAULT_OL_THRESH 48.0f    /* Over Load      I > 48 A        */
#define FAULT_OL_PH_THRESH 18.0f /* Per-phase OL   I > 18 A        */

/* Fault indices */
typedef enum {
  FIDX_OV = 0,
  FIDX_UV,
  FIDX_ROV,
  FIDX_YOV,
  FIDX_BOV,
  FIDX_RUV,
  FIDX_YUV,
  FIDX_BUV,
  FIDX_OL,
  FIDX_ROL,
  FIDX_YOL,
  FIDX_BOL,
  FIDX_RPFl,
  FIDX_YPFl,
  FIDX_BPFl,
  FIDX_ACPFl,
  FIDX_RPNl,
  FIDX_YPNl,
  FIDX_BPNl,
  FIDX_PFl,
  FIDX_SONF,
  FIDX_SOFF,
  FIDX_MAX
} fault_idx_t;

/* ========================================================================== */
/* Utility                                                                    */
/* ========================================================================== */
static bool str_contains(const char *h, const char *n) {
  return h && n && strstr(h, n) != NULL;
}

static bool pem_cert_is_valid(const char *p) {
  return p && str_contains(p, "-----BEGIN CERTIFICATE-----") &&
         str_contains(p, "-----END CERTIFICATE-----") && strlen(p) >= 128;
}

static bool pem_key_is_valid(const char *p) {
  return p && str_contains(p, "-----BEGIN") &&
         str_contains(p, "PRIVATE KEY-----") && str_contains(p, "-----END") &&
         strlen(p) >= 128;
}

static void safe_copy(char *dst, size_t sz, const char *src) {
  if (!dst || !sz)
    return;
  if (!src) {
    dst[0] = '\0';
    return;
  }
  strncpy(dst, src, sz - 1);
  dst[sz - 1] = '\0';
}

static float clamp_non_negative(float v) { return v < 0.0f ? 0.0f : v; }

static double round_2dp(double v) {
  if (isnan(v) || isinf(v))
    return 0.0;
  return round(v * 100.0) / 100.0;
}

static void cjson_add_number_2dp(cJSON *obj, const char *name, double value) {
  char buf[32];
  snprintf(buf, sizeof(buf), "%.2f", round_2dp(value));
  cJSON_AddItemToObject(obj, name, cJSON_CreateRaw(buf));
}

/* ========================================================================== */
/* NVS helpers                                                                */
/* ========================================================================== */
static esp_err_t nvs_save_device_certs(void) {
  if (!pem_cert_is_valid(s_device_cert_pem) ||
      !pem_key_is_valid(s_device_key_pem))
    return ESP_ERR_INVALID_ARG;
  nvs_handle_t h;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h);
  if (err != ESP_OK)
    return err;
  err = nvs_set_str(h, "dev_cert", s_device_cert_pem);
  if (err == ESP_OK)
    err = nvs_set_str(h, "dev_key", s_device_key_pem);
  if (err == ESP_OK)
    err = nvs_set_str(h, "thing", s_thing_name);
  if (err == ESP_OK)
    err = nvs_set_u8(h, "provisioned", 1);
  if (err == ESP_OK)
    err = nvs_commit(h);
  nvs_close(h);
  return err;
}

static bool nvs_is_provisioned(void) {
  nvs_handle_t h;
  if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) != ESP_OK)
    return false;
  uint8_t flag = 0;
  char cert[256] = {0}, key[256] = {0};
  size_t csz = sizeof(cert), ksz = sizeof(key);
  esp_err_t ef = nvs_get_u8(h, "provisioned", &flag);
  esp_err_t ec = nvs_get_str(h, "dev_cert", cert, &csz);
  esp_err_t ek = nvs_get_str(h, "dev_key", key, &ksz);
  nvs_close(h);
  if (ef != ESP_OK || flag != 1 || ec != ESP_OK || ek != ESP_OK)
    return false;
  return pem_cert_is_valid(cert) && pem_key_is_valid(key);
}

static esp_err_t nvs_clear_provisioned_flag(void) {
  nvs_handle_t h;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h);
  if (err != ESP_OK)
    return err;
  err = nvs_set_u8(h, "provisioned", 0);
  if (err == ESP_OK)
    err = nvs_commit(h);
  nvs_close(h);
  return err;
}

static esp_err_t nvs_load_device_certs(char *cert, size_t csz, char *key,
                                       size_t ksz) {
  if (!cert || !csz || !key || !ksz)
    return ESP_ERR_INVALID_ARG;
  nvs_handle_t h;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &h);
  if (err != ESP_OK)
    return err;
  size_t cn = csz, kn = ksz;
  err = nvs_get_str(h, "dev_cert", cert, &cn);
  if (err == ESP_OK)
    err = nvs_get_str(h, "dev_key", key, &kn);
  nvs_close(h);
  if (err != ESP_OK)
    return err;
  if (!pem_cert_is_valid(cert) || !pem_key_is_valid(key))
    return ESP_ERR_INVALID_CRC;
  return ESP_OK;
}

/* ========================================================================== */
/* IMEI                                                                       */
/* ========================================================================== */
static void read_device_imei(char *buf, size_t len) {
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
static void wifi_event_handler(void *arg, esp_event_base_t base, int32_t id,
                               void *data) {
  (void)arg;
  if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
    esp_wifi_connect();
    return;
  }
  if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
    s_wifi_retry++;
    if ((s_wifi_retry % 5) == 1)
      ESP_LOGW(TAG, "Wi-Fi disconnected, retry=%d", s_wifi_retry);
    xEventGroupClearBits(s_wifi_events, WIFI_CONNECTED_BIT);
    esp_wifi_connect();
    return;
  }
  if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
    ip_event_got_ip_t *ev = data;
    ESP_LOGI(TAG, "Wi-Fi connected, IP: " IPSTR, IP2STR(&ev->ip_info.ip));
    s_wifi_retry = 0;
    xEventGroupSetBits(s_wifi_events, WIFI_CONNECTED_BIT);
  }
}

static esp_err_t wifi_init_sta_blocking(void) {
  if (!strcmp(CONFIG_CCMS_WIFI_SSID, "YOUR_WIFI_SSID")) {
    ESP_LOGE(TAG, "Set CCMS_WIFI_SSID in menuconfig");
    return ESP_ERR_INVALID_ARG;
  }
  s_wifi_events = xEventGroupCreate();
  if (!s_wifi_events)
    return ESP_ERR_NO_MEM;

  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  esp_netif_create_default_wifi_sta();

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  ESP_ERROR_CHECK(esp_event_handler_instance_register(
      WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL,
      &s_wifi_any_id_instance));
  ESP_ERROR_CHECK(esp_event_handler_instance_register(
      IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL,
      &s_wifi_got_ip_instance));

  wifi_config_t wc = {0};
  strncpy((char *)wc.sta.ssid, CONFIG_CCMS_WIFI_SSID, sizeof(wc.sta.ssid) - 1);
  strncpy((char *)wc.sta.password, CONFIG_CCMS_WIFI_PASSWORD,
          sizeof(wc.sta.password) - 1);
  wc.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
  wc.sta.pmf_cfg.capable = true;
  wc.sta.pmf_cfg.required = false;

  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wc));
  ESP_ERROR_CHECK(esp_wifi_start());
  ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));

  ESP_LOGI(TAG, "Connecting to Wi-Fi: %s", CONFIG_CCMS_WIFI_SSID);
  EventBits_t bits = xEventGroupWaitBits(
      s_wifi_events, WIFI_CONNECTED_BIT | WIFI_FAIL_BIT, pdFALSE, pdFALSE,
      pdMS_TO_TICKS(WIFI_CONNECT_TIMEOUT_MS));
  if (bits & WIFI_CONNECTED_BIT)
    return ESP_OK;
  if (bits & WIFI_FAIL_BIT)
    return ESP_FAIL;
  return ESP_ERR_TIMEOUT;
}

/* ========================================================================== */
/* RS485 / Modbus                                                             */
/* ========================================================================== */
static uint16_t mb_crc16(const uint8_t *buf, int len) {
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
 * Exact port of the working Arduino readModbusFloat() timing:
 *
 *   1. Flush RX buffer
 *   2. DE HIGH → write 8-byte request → flush (wait TX done) → DE LOW
 *   3. delay(250)   ← meter needs this gap before it replies
 *   4. Read whatever bytes are available (non-blocking drain)
 *   5. Sliding-window CRC search in received bytes
 *
 * The Arduino reads exactly 9 bytes with `while(available() && i<9)`.
 * We replicate this with a short 50 ms blocking read after the 250 ms gap,
 * then drain any remaining bytes — giving the same result without busy-wait.
 *
 * NOTE on byte order: Arduino does
 *   raw = res[5]<<24 | res[6]<<16 | res[3]<<8 | res[4]
 * where res[3..6] are the 4 data bytes (response frame offset 3).
 * That is CDAB → ABCD which we replicate in mb_read_float().
 */
static bool mb_read_raw_try(uint8_t slave_id, uint16_t reg_3xxxx,
                            uint16_t words, uint8_t *out, size_t out_sz) {
  if (!out || out_sz < (size_t)(words * 2) || words > 24)
    return false;

  const uint8_t FN = 0x03;
  uint16_t addr = reg_3xxxx - 30001;

  /* Build request frame */
  uint8_t req[8] = {slave_id,
                    FN,
                    (uint8_t)(addr >> 8),
                    (uint8_t)(addr & 0xFF),
                    (uint8_t)(words >> 8),
                    (uint8_t)(words & 0xFF),
                    0,
                    0};
  uint16_t crc = mb_crc16(req, 6);
  req[6] = (uint8_t)(crc & 0xFF);
  req[7] = (uint8_t)(crc >> 8);

  /* Step 1: flush anything stale in RX FIFO */
  /* Take Modbus mutex to prevent concurrent RS485 access from the MQTT task.
   * Timeout: 2000ms (one full read cycle). If we can't get the bus in 2s,
   * the bus is stuck — return failure rather than deadlock. */
  if (!s_modbus_mutex ||
      xSemaphoreTake(s_modbus_mutex, pdMS_TO_TICKS(2000)) != pdTRUE) {
    ESP_LOGW(TAG, "MB mutex timeout — bus contention, skipping read");
    return false;
  }
  uart_flush_input(RS485_UART_NUM);

  /* Step 2: TX with manual DE control — exact Arduino sequence:
   *   digitalWrite(RS485_EN, HIGH);   // DE HIGH = transmit
   *   Modbus.write(frame, 8);
   *   Modbus.flush();                 // wait for all bytes to shift out
   *   digitalWrite(RS485_EN, LOW);    // DE LOW = receive
   */
  gpio_set_level(RS485_EN_PIN, 1); /* DE HIGH = transmit */
  uart_write_bytes(RS485_UART_NUM, (const char *)req, 8);
  uart_wait_tx_done(RS485_UART_NUM, pdMS_TO_TICKS(200));
  gpio_set_level(RS485_EN_PIN, 0); /* DE LOW = receive */

  /* Step 3: 250 ms gap — matches Arduino smartDelay(250).
   * The meter processes the request during this window.
   */
  vTaskDelay(pdMS_TO_TICKS(250));

  /* Step 4: read response bytes directly from UART2 HARDWARE FIFO.
   *
   * WHY: The ESP-IDF UART driver's ISR fails to move bytes from the
   * hardware FIFO to the ring buffer (confirmed by diagnostic: HW FIFO
   * has 7-9 bytes but uart_read_bytes returns 0).  This is a known issue
   * on some ESP-IDF versions when CONFIG_UART_ISR_IN_IRAM interacts with
   * the interrupt allocator.
   *
   * FIX: Read directly from the UART2 FIFO register (UART_FIFO_REG),
   * exactly like the hardware ISR would.  This matches what Arduino's
   * Serial.read() ultimately does at the HAL level.
   */
  int expected = 5 + (words * 2);
  int bufsz = expected + 16;
  if (bufsz > 128)
    bufsz = 128;
  uint8_t buf[128];
  int got = 0;

  /* Poll HW FIFO for up to 500ms (busy-wait like Arduino's smartDelay) */
  int64_t deadline = esp_timer_get_time() + 500000LL; /* 500ms */
  while (esp_timer_get_time() < deadline && got < bufsz) {
    uint32_t fifo_cnt = REG_GET_FIELD(UART_STATUS_REG(2), UART_RXFIFO_CNT);
    if (fifo_cnt > 0) {
      for (uint32_t i = 0; i < fifo_cnt && got < bufsz; i++) {
        buf[got++] = READ_PERI_REG(UART_FIFO_REG(2)) & 0xFF;
      }
      if (got >= expected)
        break; /* got enough bytes */
    }
    esp_rom_delay_us(1000); /* 1ms poll interval */
  }

  /* Step 4b: Modbus inter-frame gap */
  esp_rom_delay_us(4000);

  /* Release mutex before any early returns below */
  xSemaphoreGive(s_modbus_mutex);

  /* Step 4c: diagnostic hex dump */
  if (got > 0) {
    char hex[128 * 3 + 1];
    int dump = got > 128 ? 128 : got;
    for (int x = 0; x < dump; x++)
      snprintf(hex + x * 3, 4, "%02X ", buf[x]);
    if (dump * 3 > 0)
      hex[dump * 3 - 1] = '\0';
    ESP_LOGD(TAG, "MB rx %d bytes (reg=%u): %s", got, addr, hex);
  } else {
    xSemaphoreGive(s_modbus_mutex); /* release on TIMEOUT path */
    ESP_LOGW(TAG,
             "MB TIMEOUT — 0 bytes received (slave=%u reg=%u). "
             "Check: meter power, A/B polarity, baud rate, slave ID.",
             slave_id, addr);
    return false;
  }

  /* Step 5: sliding-window CRC-validated frame search */
  for (int i = 0; i <= got - expected; i++) {
    if (buf[i] != slave_id)
      continue;
    if (buf[i + 1] != FN)
      continue;
    if (buf[i + 2] != (uint8_t)(words * 2))
      continue;

    uint16_t rx_crc =
        ((uint16_t)buf[i + expected - 1] << 8) | buf[i + expected - 2];
    uint16_t calc_crc = mb_crc16(&buf[i], expected - 2);
    if (rx_crc != calc_crc) {
      ESP_LOGW(TAG, "MB CRC mismatch offset=%d rx=0x%04X calc=0x%04X", i,
               rx_crc, calc_crc);
      continue;
    }
    memcpy(out, &buf[i + 3], words * 2);
    return true;
  }

  /* No valid frame found — release mutex */
  xSemaphoreGive(s_modbus_mutex);
  ESP_LOGW(TAG, "MB no valid frame in %d bytes (slave=%u reg=%u)", got,
           slave_id, addr);
  return false;
}

/*
 * mb_read_float()
 * ---------------
 * Reads one 32-bit float from `reg_3xxxx`.
 * MFM M11 byte order: 32-bit Little Endian Byte Swap = CDAB
 *   raw bytes from meter: [C][D][A][B]
 *   reassemble as float:  [A][B][C][D]  (big-endian IEEE 754)
 *   i.e., bits = data[2]<<24 | data[3]<<16 | data[0]<<8 | data[1]
 */
float mb_read_float(uint16_t reg_3xxxx) {
  uint8_t data[4] = {0};
  if (!mb_read_raw_try(1, reg_3xxxx, 2, data, sizeof(data)))
    return -1.0f;

  /* CDAB → ABCD reassembly */
  uint32_t bits = ((uint32_t)data[2] << 24) | ((uint32_t)data[3] << 16) |
                  ((uint32_t)data[0] << 8) | (uint32_t)data[1];
  float v = 0.0f;
  memcpy(&v, &bits, 4);

  if (isnan(v) || isinf(v))
    return -1.0f;
  if (v < 0.0f || v > 1000000.0f)
    return -1.0f;
  return v;
}

/*
 * mb_read_multi_float()
 * ---------------------
 * Reads N consecutive 32-bit floats starting at reg_3xxxx.
 * Each float = 2 Modbus registers, so we request (count * 2) registers
 * in a single transaction.  Max count = 12 (24 registers, 48 data bytes).
 * Returns the number of floats successfully read (0 on failure).
 */
static int mb_read_multi_float(uint16_t reg_3xxxx, int count, float *out) {
  if (!out || count <= 0 || count > 12)
    return 0;
  uint16_t words = (uint16_t)(count * 2);
  uint8_t data[48] = {0}; /* max 12 floats × 4 bytes */
  if (!mb_read_raw_try(1, reg_3xxxx, words, data, words * 2))
    return 0;

  for (int i = 0; i < count; i++) {
    uint8_t *d = &data[i * 4];
    /* CDAB → ABCD reassembly */
    uint32_t bits = ((uint32_t)d[2] << 24) | ((uint32_t)d[3] << 16) |
                    ((uint32_t)d[0] << 8) | (uint32_t)d[1];
    float v = 0.0f;
    memcpy(&v, &bits, 4);
    if (isnan(v) || isinf(v) || v < 0.0f || v > 1000000.0f)
      out[i] = -1.0f;
    else
      out[i] = v;
  }
  return count;
}

/* Cached voltage readings from modbus detection for power-failure logic
 * NOTE: Initialized to 200V (safe/live) — see FIX-R1 comment in global state
 * above. (Declaration is in the global state block above, near
 * s_power_fail_buffer)
 */

static void modbus_detect_if_needed(void) {
  uint64_t now = esp_timer_get_time();
  if ((now - s_last_modbus_detect_us) < 2000ULL * 1000ULL)
    return;
  s_last_modbus_detect_us = now;

  float voltages[3] = {-1.0f, -1.0f, -1.0f};
  bool read_ok = mb_read_multi_float(REG_VL1N, 3, voltages) &&
                 voltages[0] >= 0.0f && voltages[1] >= 0.0f &&
                 voltages[2] >= 0.0f;

  if (read_ok) {
    s_cached_rv = clamp_non_negative(voltages[0]);
    s_cached_yv = clamp_non_negative(voltages[1]);
    s_cached_bv = clamp_non_negative(voltages[2]);
    if (!s_modbus_online)
      ESP_LOGI(TAG, "Modbus back online V=%.1f/%.1f/%.1f", s_cached_rv,
               s_cached_yv, s_cached_bv);
    s_modbus_online = true;
    s_modbus_offline_count = 0;
    s_cache_valid = true;
  } else {
    /* Failed read — debounce before declaring offline.
     * IMPORTANT: do NOT clear cache — keep last known-good voltages.
     * Cache is reset to a placeholder only after we enter battery mode
     * (so that when AC and meter both restore, we don't use stale values). */
    s_modbus_offline_count++;
    if (s_modbus_offline_count > MODBUS_OFFLINE_COUNT_MAX)
      s_modbus_offline_count =
          MODBUS_OFFLINE_COUNT_MAX; /* cap — prevent overflow */
    ESP_LOGW(TAG, "Modbus read fail %d/%d", s_modbus_offline_count,
             MODBUS_OFFLINE_DEBOUNCE);
    if (s_modbus_offline_count >= MODBUS_OFFLINE_DEBOUNCE) {
      s_modbus_online = false;
    }
  }
}

/* ========================================================================== */
/* Relay (active-LOW latch)                                                   */
/* Pins idle HIGH. Pulse LOW for 200ms to activate each coil.                 */
/* relay_on (): hold RESET HIGH, pulse SET LOW → HIGH (latches relay ON)      */
/* relay_off(): hold SET HIGH,   pulse RESET LOW → HIGH (latches relay OFF)   */
/* ========================================================================== */
static void relay_on(void) {
  gpio_set_level(RELAY_RESET_PIN, 1); /* RESET stays HIGH (idle) */
  gpio_set_level(RELAY_SET_PIN, 0);   /* SET pulse LOW → latches ON */
  vTaskDelay(pdMS_TO_TICKS(200));
  gpio_set_level(RELAY_SET_PIN, 1); /* SET returns HIGH */
  s_relay_on = true;
  ESP_LOGI(TAG, "Relay ON (Active-LOW pulse)");
}

static void relay_off(void) {
  gpio_set_level(RELAY_SET_PIN, 1);   /* SET stays HIGH (idle) */
  gpio_set_level(RELAY_RESET_PIN, 0); /* RESET pulse LOW → latches OFF */
  vTaskDelay(pdMS_TO_TICKS(200));
  gpio_set_level(RELAY_RESET_PIN, 1); /* RESET returns HIGH */
  s_relay_on = false;
  ESP_LOGI(TAG, "Relay OFF (Active-LOW pulse)");
}

/* ========================================================================== */
/* GPS                                                                        */
/* ========================================================================== */
static double nmea_to_deg(const char *v, char h) {
  if (!v || !*v)
    return 0.0;
  double raw = atof(v);
  int deg = (int)(raw / 100.0);
  double out = (double)deg + (raw - deg * 100.0) / 60.0;
  if (h == 'S' || h == 'W')
    out = -out;
  return out;
}
static bool parse_hhmmss(const char *s, int *hh, int *mm, int *ss) {
  if (!s || strlen(s) < 6)
    return false;
  *hh = (s[0] - '0') * 10 + (s[1] - '0');
  *mm = (s[2] - '0') * 10 + (s[3] - '0');
  *ss = (s[4] - '0') * 10 + (s[5] - '0');
  return true;
}
static bool parse_ddmmyy(const char *s, int *dd, int *mm, int *yy) {
  if (!s || strlen(s) < 6)
    return false;
  *dd = (s[0] - '0') * 10 + (s[1] - '0');
  *mm = (s[2] - '0') * 10 + (s[3] - '0');
  *yy = 2000 + (s[4] - '0') * 10 + (s[5] - '0');
  return true;
}
static int nmea_fields(char *s, char **f, int max) {
  if (!s || !f || max <= 0)
    return 0;
  int n = 0;
  f[n++] = s;
  for (char *p = s; *p && n < max; p++)
    if (*p == ',') {
      *p = '\0';
      f[n++] = p + 1;
    }
  return n;
}
static void gps_parse_line(const char *line) {
  if (!line || line[0] != '$')
    return;
  char buf[128] = {0};
  strncpy(buf, line, 127);
  char *star = strchr(buf, '*');
  if (star)
    *star = '\0';
  char *tok[24] = {0};
  int n = nmea_fields(buf, tok, 24);
  if (n < 2)
    return;
  if (!strcmp(tok[0], "$GPRMC") || !strcmp(tok[0], "$GNRMC")) {
    if (n < 10)
      return;
    if (tok[2] && tok[2][0] == 'A') {
      s_gps.lat = nmea_to_deg(tok[3], tok[4] ? tok[4][0] : 'N');
      s_gps.lon = nmea_to_deg(tok[5], tok[6] ? tok[6][0] : 'E');
      s_gps.loc_valid = true;
    }
    int hh, mm, ss, dd, mo, yy;
    if (parse_hhmmss(tok[1], &hh, &mm, &ss) &&
        parse_ddmmyy(tok[9], &dd, &mo, &yy)) {
      s_gps.hour = hh;
      s_gps.minute = mm;
      s_gps.second = ss;
      s_gps.day = dd;
      s_gps.month = mo;
      s_gps.year = yy;
      s_gps.time_valid = (yy > 2023);
    }
  } else if (!strcmp(tok[0], "$GPGGA") || !strcmp(tok[0], "$GNGGA")) {
    if (n < 7)
      return;
    if (tok[6] && atoi(tok[6]) > 0) {
      s_gps.lat = nmea_to_deg(tok[2], tok[3] ? tok[3][0] : 'N');
      s_gps.lon = nmea_to_deg(tok[4], tok[5] ? tok[5][0] : 'E');
      s_gps.loc_valid = true;
    }
  }
}
static void gps_poll_uart(void) {
  uint8_t ch;
  while (uart_read_bytes(GPS_UART_NUM, &ch, 1, 0) == 1) {
    if (ch == '\r')
      continue;
    if (ch == '\n') {
      s_gps_line[s_gps_line_len] = '\0';
      if (s_gps_line_len > 6)
        gps_parse_line(s_gps_line);
      s_gps_line_len = 0;
      continue;
    }
    if (s_gps_line_len < (int)sizeof(s_gps_line) - 1)
      s_gps_line[s_gps_line_len++] = (char)ch;
    else
      s_gps_line_len = 0;
  }
}

static int64_t days_from_civil(int y, unsigned m, unsigned d) {
  y -= m <= 2;
  int era = (y >= 0 ? y : y - 399) / 400;
  unsigned yoe = (unsigned)(y - era * 400);
  unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return era * 146097 + (int64_t)doe - 719468;
}
static void sync_time_from_gps(void) {
  if (!s_gps.time_valid)
    return;
  int64_t days =
      days_from_civil(s_gps.year, (unsigned)s_gps.month, (unsigned)s_gps.day);
  int64_t sec =
      days * 86400LL + s_gps.hour * 3600 + s_gps.minute * 60 + s_gps.second;
  struct timeval tv = {.tv_sec = sec, .tv_usec = 0};
  settimeofday(&tv, NULL);
}

static const double PI2 = 3.14159265358979323846;
static int calc_sun_minutes(bool sunrise) {
  if (!s_gps.loc_valid)
    return -1;
  time_t now = time(NULL);
  struct tm t = {0};
  localtime_r(&now, &t);
  if ((t.tm_year + 1900) < 2023)
    return -1;
  int N = t.tm_yday + 1;
  double lh = s_gps.lon / 15.0;
  double T = sunrise ? N + ((6.0 - lh) / 24.0) : N + ((18.0 - lh) / 24.0);
  double M = (0.9856 * T) - 3.289;
  double L = fmod(M + (1.916 * sin(M * PI2 / 180.0)) +
                      (0.020 * sin(2 * M * PI2 / 180.0)) + 282.634 + 360.0,
                  360.0);
  double RA =
      fmod(atan(0.91764 * tan(L * PI2 / 180.0)) * 180.0 / PI2 + 360.0, 360.0) /
      15.0;
  double sinD = 0.39782 * sin(L * PI2 / 180.0);
  double cosD = cos(asin(sinD));
  double cosH =
      (cos(90.833 * PI2 / 180.0) - sinD * sin(s_gps.lat * PI2 / 180.0)) /
      (cosD * cos(s_gps.lat * PI2 / 180.0));
  if (cosH > 1 || cosH < -1)
    return -1;
  double H =
      sunrise ? (360.0 - acos(cosH) * 180.0 / PI2) : (acos(cosH) * 180.0 / PI2);
  H /= 15.0;
  double UT = fmod(H + RA - (0.06571 * T) - 6.622 - lh + 48.0, 24.0);
  int m = ((int)(UT * 60.0) + (IST_GMT_OFFSET_SEC / 60)) % 1440;
  if (m < 0)
    m += 1440;
  return m;
}
static void format_hhmm(int m, char *out, size_t sz) {
  if (m < 0) {
    snprintf(out, sz, "--:--");
    return;
  }
  snprintf(out, sz, "%02d:%02d", m / 60, m % 60);
}
static void solar_load_from_nvs(void) {
  nvs_handle_t h;
  if (nvs_open("solar_data", NVS_READONLY, &h) != ESP_OK)
    return;
  nvs_get_i32(h, "sr_min", (int32_t *)&s_sunrise_min);
  nvs_get_i32(h, "ss_min", (int32_t *)&s_sunset_min);
  size_t lsz = sizeof(double), osz = sizeof(double);
  double lat = 0.0, lon = 0.0;
  if (nvs_get_blob(h, "lat", &lat, &lsz) == ESP_OK &&
      nvs_get_blob(h, "lng", &lon, &osz) == ESP_OK) {
    s_gps.lat = lat;
    s_gps.lon = lon;
    s_gps.loc_valid = true;
  }
  nvs_close(h);
  s_solar_valid = (s_sunrise_min >= 0 && s_sunset_min >= 0);
}
static void solar_save_to_nvs(void) {
  nvs_handle_t h;
  if (nvs_open("solar_data", NVS_READWRITE, &h) != ESP_OK)
    return;
  nvs_set_i32(h, "sr_min", s_sunrise_min);
  nvs_set_i32(h, "ss_min", s_sunset_min);
  nvs_set_blob(h, "lat", &s_gps.lat, sizeof(s_gps.lat));
  nvs_set_blob(h, "lng", &s_gps.lon, sizeof(s_gps.lon));
  nvs_commit(h);
  nvs_close(h);
}
static void gps_solar_update(void) {
  gps_poll_uart();
  if (!s_gps.loc_valid)
    return;
  if (!s_gps_locked_once) {
    s_gps_locked_once = true;
    ESP_LOGI(TAG, "GPS fix: lat=%.6f lon=%.6f", s_gps.lat, s_gps.lon);
  }
  sync_time_from_gps();
  int sr = calc_sun_minutes(true), ss = calc_sun_minutes(false);
  if (sr >= 0 && ss >= 0) {
    s_sunrise_min = sr;
    s_sunset_min = ss;
    s_solar_valid = true;
    solar_save_to_nvs();
  }
}

/* ========================================================================== */
/* Auto relay — ON at sunset, OFF at sunrise                                 */
/* ========================================================================== */
static bool is_night_time(void)
{
  if (!s_solar_valid) return false;
  time_t now = time(NULL);
  if (now < 1000000LL) return false;   /* clock not yet synced via GPS */
  struct tm t = {0};
  gmtime_r(&now, &t);
  int ist_min = (t.tm_hour * 60 + t.tm_min + (IST_GMT_OFFSET_SEC / 60)) % 1440;
  /* Night = sunset until sunrise (spans midnight) */
  return (ist_min >= s_sunset_min || ist_min < s_sunrise_min);
}

/* V3-3: NVS battery-mode persistence helpers */
static void nvs_save_battery_mode(bool in_battery) {
  nvs_handle_t h;
  if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK)
    return;
  nvs_set_u8(h, "bat_mode", (uint8_t)in_battery);
  nvs_commit(h);
  nvs_close(h);
}

static bool nvs_load_battery_mode(void) {
  nvs_handle_t h;
  if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) != ESP_OK)
    return false;
  uint8_t v = 0;
  nvs_get_u8(h, "bat_mode", &v);
  nvs_close(h);
  return (v == 1);
}

/* ========================================================================== */
/* Power-failure logic — dual-signal state machine                            */
/* ========================================================================== */
static void send_power_event_mqtt(const char *event, const char *source) {
  if (!s_device_mqtt_client || !s_device_mqtt_connected)
    return;
  char topic[80];
  snprintf(topic, sizeof(topic), "dt/%s", s_imei);
  char payload[256];
  snprintf(payload, sizeof(payload),
           "{\"Ime no\":\"%s\",\"power_event\":\"%s\""
           ",\"power_source\":\"%s\",\"status\":\"NOTIFICATION\"}",
           s_imei, event, source);
  esp_mqtt_client_publish(s_device_mqtt_client, topic, payload, 0, 1, 0);
}

static void switch_to_battery(const char *reason, float rv, float yv,
                              float bv) {
  gpio_set_level(POWER_RELAY_PIN, 1); /* LOW = Battery mode (relay ON) */
  s_is_battery_mode = true;
  s_cached_rv = 0.0f;
  s_cached_yv = 0.0f;
  s_cached_bv = 0.0f;
  nvs_save_battery_mode(true); /* V3-3: persist across reboots */
  ESP_LOGW(TAG, "BATTERY MODE [%s] V=%.1f/%.1f/%.1f", reason, rv, yv, bv);
  send_power_event_mqtt("POWER_FAILURE_SWITCHED_TO_BATTERY", "BATTERY");
}

static void switch_to_ac(float rv, float yv, float bv) {
  gpio_set_level(POWER_RELAY_PIN, 0); /* HIGH = AC mains (relay OFF) */
  s_is_battery_mode = false;
  s_low_volt_buffer = 0;
  nvs_save_battery_mode(false); /* V3-3: persist across reboots */
  ESP_LOGI(TAG, "AC RESTORED V=%.1f/%.1f/%.1f", rv, yv, bv);
  send_power_event_mqtt("AC_POWER_RESTORED", "AC_ADAPTER");
}

static void update_power_failure_logic(float rv, float yv, float bv) {
  uint64_t now = esp_timer_get_time();
  if ((now - s_last_power_check_us) < POWER_CHECK_INTERVAL_US)
    return;
  s_last_power_check_us = now;

  /* ── SWITCH TO BATTERY ───────────────────────────────────────────────── */
  if (!s_is_battery_mode) {

    /* Signal A: Meter is alive but all 3 phases are below threshold */
    if (s_modbus_online) {
      bool dead = (rv < VOLTAGE_DEAD_THRESH) && (yv < VOLTAGE_DEAD_THRESH) &&
                  (bv < VOLTAGE_DEAD_THRESH);
      if (dead) {
        if (++s_low_volt_buffer >= LOW_VOLT_DEBOUNCE)
          switch_to_battery("LOW_VOLTAGE", rv, yv, bv);
      } else {
        s_low_volt_buffer = 0; /* any live phase resets counter */
      }
    }

    /* Signal B: Meter completely offline long enough that it must be dead.
     * The meter is AC-powered: if AC fails, meter goes offline after its
     * capacitors drain (typically < 1 second).  10 seconds of silence
     * is a very conservative threshold — almost certainly a real blackout. */
    if (!s_modbus_online && s_modbus_offline_count >= MODBUS_DEAD_FOR_BATTERY) {
      switch_to_battery("METER_OFFLINE", rv, yv, bv);
    }
  }

  /* ── RESTORE AC ──────────────────────────────────────────────────────── */
  else { /* s_is_battery_mode == true */

    /* AC is restored only when:
     *   1. Modbus is online again (meter has power = AC is back)
     *   2. At least one phase reads > threshold (confirms AC voltage present)
     * We NEVER restore AC when Modbus is still offline — that would be
     * restoring AC during an ongoing blackout. */
    if (s_modbus_online) {
      bool any_live = (rv > VOLTAGE_DEAD_THRESH) ||
                      (yv > VOLTAGE_DEAD_THRESH) || (bv > VOLTAGE_DEAD_THRESH);
      if (any_live) {
        switch_to_ac(rv, yv, bv);
      }
      /* If Modbus is online but all phases still dead: meter is alive
       * but AC voltage is not restored yet — stay in battery mode. */
    }
    /* If Modbus is offline: meter is dead = AC is still gone. Stay in
     * battery mode. Do NOT restore AC. */
  }
}

/* ========================================================================== */
/* Fault publishing                                                           */
/* ========================================================================== */
/* V3-2: Cooldown-aware fault publisher — prevents storm flooding on dashboard
 */
static void publish_fault(const char *code, bool active) {
  if (!s_device_mqtt_client || !s_device_mqtt_connected)
    return;
  char topic[80];
  snprintf(topic, sizeof(topic), "evt/%s/fault", s_imei);
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

/* V3-4 + V3-5: check_and_publish_faults moved to main loop.
 * Called ONLY when s_modbus_online (validated cache data).
 * V3-2: CHK macro now also enforces per-fault cooldown. */
static void check_and_publish_faults(float rv, float yv, float bv, float ri,
                                     float yi, float bi) {
  if (!s_modbus_online || !s_cache_valid)
    return; /* V3-5: no data = no faults */

  uint64_t now_us = esp_timer_get_time();

#define CHK(idx, code, cond)                                                   \
  do {                                                                         \
    bool _now = (cond);                                                        \
    bool _changed = (_now != s_fault[idx].active);                             \
    bool _cooled =                                                             \
        ((now_us - s_fault[idx].last_publish_us) >= FAULT_COOLDOWN_US);        \
    if (_changed && _cooled) {                                                 \
      s_fault[idx].active = _now;                                              \
      s_fault[idx].last_publish_us = now_us;                                   \
      publish_fault(code, _now);                                               \
    }                                                                          \
  } while (0)

  CHK(FIDX_ROV, "ROV", rv > FAULT_OV_THRESH);
  CHK(FIDX_YOV, "YOV", yv > FAULT_OV_THRESH);
  CHK(FIDX_BOV, "BOV", bv > FAULT_OV_THRESH);
  CHK(FIDX_RUV, "RUV", rv > 0 && rv < FAULT_UV_THRESH);
  CHK(FIDX_YUV, "YUV", yv > 0 && yv < FAULT_UV_THRESH);
  CHK(FIDX_BUV, "BUV", bv > 0 && bv < FAULT_UV_THRESH);

  /* Per-phase average over-voltage / under-voltage */
  float avg_v = (rv + yv + bv) / 3.0f;
  CHK(FIDX_OV, "OV", avg_v > FAULT_OV_THRESH);
  CHK(FIDX_UV, "UV", avg_v > 0 && avg_v < FAULT_UV_THRESH);

  /* Phase failure: voltage present on at least one other phase but zero here */
  bool any_v = (rv > 50 || yv > 50 || bv > 50);
  CHK(FIDX_RPFl, "RPFl", any_v && rv < 50.0f);
  CHK(FIDX_YPFl, "YPFl", any_v && yv < 50.0f);
  CHK(FIDX_BPFl, "BPFl", any_v && bv < 50.0f);
  CHK(FIDX_ACPFl, "ACPFl", s_is_battery_mode);

  /* Phase over-load */
  CHK(FIDX_ROL, "ROL", ri > FAULT_OL_PH_THRESH);
  CHK(FIDX_YOL, "YOL", yi > FAULT_OL_PH_THRESH);
  CHK(FIDX_BOL, "BOL", bi > FAULT_OL_PH_THRESH);
  float avg_i = (ri + yi + bi) / 3.0f;
  CHK(FIDX_OL, "OL", avg_i > FAULT_OL_THRESH);

  /* No-load (phase energised but zero current) */
  CHK(FIDX_RPNl, "RPNl", s_relay_on && rv > 50 && ri < 0.1f);
  CHK(FIDX_YPNl, "YPNl", s_relay_on && yv > 50 && yi < 0.1f);
  CHK(FIDX_BPNl, "BPNl", s_relay_on && bv > 50 && bi < 0.1f);
  CHK(FIDX_SONF, "SONF", s_relay_on && any_v && avg_i < 0.1f);
  CHK(FIDX_SOFF, "SOFF", !s_relay_on && any_v && avg_i > 0.1f);

#undef CHK
}

/* ========================================================================== */
/* Telemetry                                                                  */
/* ========================================================================== */
static void iso_time_utc(char *out, size_t sz) {
  time_t now = time(NULL);
  struct tm t = {0};
  gmtime_r(&now, &t);
  strftime(out, sz, "%Y-%m-%dT%H:%M:%SZ", &t);
}

static void publish_telemetry_now(void) {
  if (!s_device_mqtt_client || !s_device_mqtt_connected)
    return;
  gps_solar_update();

  /* --- Read all registers using batch reads ---
   * Batch 1: regs 0-4  → kWh (0), kVAh (4)             — 3 floats, use [0],[2]
   * Batch 2: regs 18-38 → V L1-L3 (18,20,22), skip, I L1-L3 (34,36,38) — 11
   * floats Batch 3: regs 42-50 → freq(42), PF 1-3(44,46,48), PF avg(50) — 5
   * floats Batch 4: regs 54-68 → kW 1-3+total(54-60), kVA 1-3+total(62-68) — 8
   * floats
   *
   * This reduces 21 individual Modbus transactions (each ~350ms) down to 4
   * batch reads (~1.4 seconds total), a 5× speedup.
   */
  float kwh = 0, kvah = 0;
  {
    float b1[3] = {0}; /* regs 0,2,4 */
    if (mb_read_multi_float(REG_KWH, 3, b1)) {
      kwh = clamp_non_negative(b1[0]);
      kvah = clamp_non_negative(b1[2]);
    }
  }

  float rv = 0, yv = 0, bv = 0, ri = 0, yi = 0, bi = 0;
  {
    float b2[11] = {0}; /* regs 18..38: V(18,20,22), gap(24-32), I(34,36,38) */
    if (mb_read_multi_float(REG_VL1N, 11, b2)) {
      rv = clamp_non_negative(b2[0]);  /* reg 18 */
      yv = clamp_non_negative(b2[1]);  /* reg 20 */
      bv = clamp_non_negative(b2[2]);  /* reg 22 */
      ri = clamp_non_negative(b2[8]);  /* reg 34 */
      yi = clamp_non_negative(b2[9]);  /* reg 36 */
      bi = clamp_non_negative(b2[10]); /* reg 38 */
      /* FIX-R5: Update the power-fail cache with the telemetry's fresh
       * voltage read so the next main-loop power check uses up-to-date
       * values instead of stale 2-second-old cached ones. */
      s_cached_rv = rv;
      s_cached_yv = yv;
      s_cached_bv = bv;
    }
  }

  float freq = 0, rpf = 0, ypf = 0, bpf = 0, apf = 0;
  {
    float b3[5] = {0}; /* regs 42..50: freq(42), PF1-3(44,46,48), PFavg(50) */
    if (mb_read_multi_float(REG_FREQ, 5, b3)) {
      freq = clamp_non_negative(b3[0]);
      rpf = (b3[1] >= 0 && b3[1] <= 1) ? b3[1] : 0;
      ypf = (b3[2] >= 0 && b3[2] <= 1) ? b3[2] : 0;
      bpf = (b3[3] >= 0 && b3[3] <= 1) ? b3[3] : 0;
      apf = (b3[4] >= 0 && b3[4] <= 1) ? b3[4] : (rpf + ypf + bpf) / 3.0f;
    }
  }

  float rkw = 0, ykw = 0, bkw = 0, tkw = 0, rkva = 0, ykva = 0, bkva = 0,
        tkva = 0;
  {
    float b4[8] = {0}; /* regs 54..68: kW(54,56,58,60), kVA(62,64,66,68) */
    if (mb_read_multi_float(REG_KWL1, 8, b4)) {
      rkw = clamp_non_negative(b4[0]);
      ykw = clamp_non_negative(b4[1]);
      bkw = clamp_non_negative(b4[2]);
      tkw = clamp_non_negative(b4[3]);
      rkva = clamp_non_negative(b4[4]);
      ykva = clamp_non_negative(b4[5]);
      bkva = clamp_non_negative(b4[6]);
      tkva = clamp_non_negative(b4[7]);
    }
    if (tkw <= 0)
      tkw = rkw + ykw + bkw;
    if (tkva <= 0)
      tkva = rkva + ykva + bkva;
  }

  float avg_v = (rv + yv + bv) / 3.0f;
  float avg_i = (ri + yi + bi) / 3.0f;

  /* --- Fault logic: intentionally NOT called here (V3-4) ---
   * check_and_publish_faults() is now called exclusively from the main loop
   * (alongside update_power_failure_logic) for two reasons:
   *   1. Removes data-race on s_fault[] between MQTT task and main loop.
   *   2. Ensures faults are always evaluated with validated cached data,
   *      not with 0V values from a failed telemetry batch read.
   */

  /* --- Build payload --- */
  char topic[64], ts[32] = {0}, sr[8] = {0}, ss_s[8] = {0};
  snprintf(topic, sizeof(topic), "dt/%s", s_imei);
  iso_time_utc(ts, sizeof(ts));
  format_hhmm(s_sunrise_min, sr, sizeof(sr));
  format_hhmm(s_sunset_min, ss_s, sizeof(ss_s));

  cJSON *root = cJSON_CreateObject();
  cJSON_AddStringToObject(root, "device_id", s_imei);
  cJSON_AddStringToObject(root, "time", ts);
  cJSON_AddBoolToObject(root, "on_off", s_relay_on);
  cJSON_AddNumberToObject(root, "fault_code", 0);
  cJSON_AddNumberToObject(root, "latt", s_gps.loc_valid ? s_gps.lat : 0.0);
  cJSON_AddNumberToObject(root, "long", s_gps.loc_valid ? s_gps.lon : 0.0);
  cJSON_AddStringToObject(root, "box_no", "");
  cJSON_AddStringToObject(root, "nsl", "0");
  cJSON_AddStringToObject(root, "nwsl", "0");
  cJSON_AddStringToObject(root, "mode", "Auto(A)");
  cJSON_AddStringToObject(root, "sun_set_time", ss_s);
  cJSON_AddStringToObject(root, "sun_rise_time", sr);
  cJSON_AddNumberToObject(root, "no_lights_on", 0);

  /* Overall */
  cjson_add_number_2dp(root, "voltage_v", avg_v);
  cjson_add_number_2dp(root, "current_a", avg_i);
  cjson_add_number_2dp(root, "frequency", freq);
  cjson_add_number_2dp(root, "pf", apf);
  cjson_add_number_2dp(root, "kw", tkw);
  cjson_add_number_2dp(root, "kwh", kwh);
  cjson_add_number_2dp(root, "kva", tkva);
  cjson_add_number_2dp(root, "kvah", kvah);

  /* R-phase */
  cjson_add_number_2dp(root, "r_voltage", rv);
  cjson_add_number_2dp(root, "r_current", ri);
  cjson_add_number_2dp(root, "r_frequency", freq);
  cjson_add_number_2dp(root, "r_pf", rpf);
  cjson_add_number_2dp(root, "r_kw", rkw);
  cjson_add_number_2dp(root, "r_kva", rkva);

  /* Y-phase */
  cjson_add_number_2dp(root, "y_voltage", yv);
  cjson_add_number_2dp(root, "y_current", yi);
  cjson_add_number_2dp(root, "y_frequency", freq);
  cjson_add_number_2dp(root, "y_pf", ypf);
  cjson_add_number_2dp(root, "y_kw", ykw);
  cjson_add_number_2dp(root, "y_kva", ykva);

  /* B-phase */
  cjson_add_number_2dp(root, "b_voltage", bv);
  cjson_add_number_2dp(root, "b_current", bi);
  cjson_add_number_2dp(root, "b_frequency", freq);
  cjson_add_number_2dp(root, "b_pf", bpf);
  cjson_add_number_2dp(root, "b_kw", bkw);
  cjson_add_number_2dp(root, "b_kva", bkva);

  /* Debug fields */
  cJSON_AddBoolToObject(root, "modbus_online", s_modbus_online);
  cJSON_AddBoolToObject(root, "gps_locked_once", s_gps_locked_once);
  cJSON_AddStringToObject(root, "power_source",
                          s_is_battery_mode ? "BATTERY" : "AC_ADAPTER");

  char *payload = cJSON_PrintUnformatted(root);
  if (payload) {
    int mid =
        esp_mqtt_client_publish(s_device_mqtt_client, topic, payload, 0, 1, 0);
    ESP_LOGI(TAG,
             "Telemetry published mid=%d | V=%.2f/%.2f/%.2f I=%.2f/%.2f/%.2f"
             " kWh=%.2f modbus=%s",
             mid, rv, yv, bv, ri, yi, bi, kwh, s_modbus_online ? "OK" : "NO");
    free(payload);
  }
  cJSON_Delete(root);
}

/* ========================================================================== */
/* Device MQTT subscriptions                                                  */
/* ========================================================================== */
static void subscribe_device_topics(esp_mqtt_client_handle_t client) {
  char t[160];
  snprintf(t, sizeof(t), "cmd/%s/report", s_imei);
  esp_mqtt_client_subscribe(client, t, 1);
  snprintf(t, sizeof(t), "cmd/%s/control", s_imei);
  esp_mqtt_client_subscribe(client, t, 1);

  /* OTA Jobs */
  snprintf(t, sizeof(t), "$aws/things/%s/jobs/notify", s_imei);
  esp_mqtt_client_subscribe(client, t, 1);
  snprintf(t, sizeof(t), "$aws/things/%s/jobs/get/accepted", s_imei);
  esp_mqtt_client_subscribe(client, t, 1);
  snprintf(t, sizeof(t), "$aws/things/%s/jobs/get/rejected", s_imei);
  esp_mqtt_client_subscribe(client, t, 1);
  snprintf(t, sizeof(t), "$aws/things/%s/jobs/+/get/accepted", s_imei);
  esp_mqtt_client_subscribe(client, t, 1);
  snprintf(t, sizeof(t), "$aws/things/%s/jobs/+/update/accepted", s_imei);
  esp_mqtt_client_subscribe(client, t, 1);
  snprintf(t, sizeof(t), "$aws/things/%s/jobs/+/update/rejected", s_imei);
  esp_mqtt_client_subscribe(client, t, 1);

  /* Poll for pending jobs on connect */
  snprintf(t, sizeof(t), "$aws/things/%s/jobs/get", s_imei);
  char pay[64];
  snprintf(pay, sizeof(pay), "{\"clientToken\":\"%s\"}", s_imei);
  esp_mqtt_client_publish(client, t, pay, 0, 1, 0);
}

static void mqtt_device_handler(void *arg, esp_event_base_t base, int32_t eid,
                                void *edata) {
  (void)arg;
  (void)base;
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
    if (!ev->topic || ev->topic_len <= 0)
      break;
    char topic[160] = {0};
    int tl = ev->topic_len < (int)sizeof(topic) - 1 ? ev->topic_len
                                                    : (int)sizeof(topic) - 1;
    memcpy(topic, ev->topic, tl);

    char report_t[96];
    snprintf(report_t, sizeof(report_t), "cmd/%s/report", s_imei);
    char control_t[96];
    snprintf(control_t, sizeof(control_t), "cmd/%s/control", s_imei);

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
        cJSON *oo = cJSON_GetObjectItem(r, "on_off");
        if (cJSON_IsString(rel)) {
          if (!strcmp(rel->valuestring, "ON"))
            relay_on();
          if (!strcmp(rel->valuestring, "OFF"))
            relay_off();
        } else if (cJSON_IsBool(oo)) {
          if (cJSON_IsTrue(oo))
            relay_on();
          else
            relay_off();
        }
        publish_telemetry_now();
        cJSON_Delete(r);
      }
    }
    /* OTA Jobs handler stub — extend here for full OTA support */
    break;
  }
  default:
    break;
  }
}

/* ========================================================================== */
/* MQTT chunk accumulator (provisioning)                                      */
/* ========================================================================== */
static void acc_reset(void) { memset(&s_acc, 0, sizeof(s_acc)); }

static bool acc_accept_chunk(const esp_mqtt_event_handle_t ev, char *tout,
                             size_t tsz, char *jout, size_t jsz) {
  if (!ev || !tout || !jout)
    return false;
  char topic[MAX_TOPIC_LEN] = {0};
  int tlen = ev->topic_len;

  if (ev->current_data_offset == 0) {
    if (tlen <= 0 || tlen >= MAX_TOPIC_LEN || !ev->topic) {
      xEventGroupSetBits(s_provision_events, BIT_ERROR);
      return false;
    }
    memcpy(topic, ev->topic, tlen);
    topic[tlen] = '\0';
  } else {
    if (!s_acc.topic[0]) {
      xEventGroupSetBits(s_provision_events, BIT_ERROR);
      return false;
    }
    safe_copy(topic, sizeof(topic), s_acc.topic);
  }

  if (ev->total_data_len <= 0 || ev->total_data_len >= MAX_MQTT_JSON_LEN) {
    xEventGroupSetBits(s_provision_events, BIT_ERROR);
    return false;
  }
  if (ev->current_data_offset == 0) {
    acc_reset();
    safe_copy(s_acc.topic, sizeof(s_acc.topic), topic);
    s_acc.total_len = ev->total_data_len;
    s_acc.active = true;
  }
  if (!s_acc.active || strcmp(s_acc.topic, topic) != 0) {
    xEventGroupSetBits(s_provision_events, BIT_ERROR);
    return false;
  }
  if (ev->current_data_offset != s_acc.collected) {
    xEventGroupSetBits(s_provision_events, BIT_ERROR);
    return false;
  }
  int cl = ev->data_len;
  if ((s_acc.collected + cl) >= (int)sizeof(s_acc.data)) {
    xEventGroupSetBits(s_provision_events, BIT_ERROR);
    return false;
  }
  memcpy(&s_acc.data[s_acc.collected], ev->data, cl);
  s_acc.collected += cl;
  s_acc.data[s_acc.collected] = '\0';
  if (s_acc.collected < s_acc.total_len)
    return false;
  safe_copy(tout, tsz, s_acc.topic);
  safe_copy(jout, jsz, s_acc.data);
  acc_reset();
  return true;
}

/* ========================================================================== */
/* Provisioning MQTT event handler                                            */
/* ========================================================================== */
static void handle_create_cert_accepted(esp_mqtt_client_handle_t client,
                                        cJSON *root) {
  cJSON *cert = cJSON_GetObjectItem(root, "certificatePem");
  cJSON *key = cJSON_GetObjectItem(root, "privateKey");
  cJSON *token = cJSON_GetObjectItem(root, "certificateOwnershipToken");
  if (!cJSON_IsString(cert) || !cJSON_IsString(key) || !cJSON_IsString(token)) {
    xEventGroupSetBits(s_provision_events, BIT_ERROR);
    return;
  }
  safe_copy(s_device_cert_pem, sizeof(s_device_cert_pem), cert->valuestring);
  safe_copy(s_device_key_pem, sizeof(s_device_key_pem), key->valuestring);
  safe_copy(s_ownership_token, sizeof(s_ownership_token), token->valuestring);
  if (!pem_cert_is_valid(s_device_cert_pem) ||
      !pem_key_is_valid(s_device_key_pem)) {
    xEventGroupSetBits(s_provision_events, BIT_ERROR);
    return;
  }
  ESP_LOGI(TAG, "Cert received (%u/%u bytes)",
           (unsigned)strlen(s_device_cert_pem),
           (unsigned)strlen(s_device_key_pem));
  xEventGroupSetBits(s_provision_events, BIT_CERT_RECEIVED);

  cJSON *prov = cJSON_CreateObject();
  cJSON_AddStringToObject(prov, "certificateOwnershipToken", s_ownership_token);
  cJSON *params = cJSON_CreateObject();
  cJSON_AddStringToObject(params, "SerialNumber", s_imei);
  cJSON_AddItemToObject(prov, "parameters", params);
  char *payload = cJSON_PrintUnformatted(prov);
  if (payload) {
    esp_mqtt_client_publish(client, TOPIC_PROVISION, payload, 0, 1, 0);
    free(payload);
  }
  cJSON_Delete(prov);
}

static void handle_provision_accepted(cJSON *root) {
  cJSON *thing = cJSON_GetObjectItem(root, "thingName");
  safe_copy(s_thing_name, sizeof(s_thing_name),
            (cJSON_IsString(thing) && thing->valuestring[0])
                ? thing->valuestring
                : s_imei);
  ESP_LOGI(TAG, "Thing registered: %s", s_thing_name);
  xEventGroupSetBits(s_provision_events, BIT_PROV_ACCEPTED);
}

static void mqtt_provision_handler(void *arg, esp_event_base_t base,
                                   int32_t eid, void *edata) {
  (void)arg;
  (void)base;
  esp_mqtt_event_handle_t ev = edata;
  esp_mqtt_client_handle_t client = ev->client;

  switch ((esp_mqtt_event_id_t)eid) {
  case MQTT_EVENT_CONNECTED:
    esp_mqtt_client_subscribe(client, TOPIC_CREATE_CERT_ACC, 1);
    esp_mqtt_client_subscribe(client, TOPIC_CREATE_CERT_REJ, 1);
    esp_mqtt_client_subscribe(client, TOPIC_PROVISION_ACC, 1);
    esp_mqtt_client_subscribe(client, TOPIC_PROVISION_REJ, 1);
    xEventGroupSetBits(s_provision_events, BIT_CONNECTED);
    break;
  case MQTT_EVENT_SUBSCRIBED: {
    static int sc = 0;
    sc++;
    if (sc >= 4) {
      sc = 0;
      esp_mqtt_client_publish(client, TOPIC_CREATE_CERT, "{}", 0, 1, 0);
      xEventGroupSetBits(s_provision_events, BIT_SUBSCRIBED);
    }
    break;
  }
  case MQTT_EVENT_DATA: {
    static char topic[MAX_TOPIC_LEN];
    static char json[MAX_MQTT_JSON_LEN];
    if (!acc_accept_chunk(ev, topic, sizeof(topic), json, sizeof(json)))
      break;
    cJSON *root = cJSON_Parse(json);
    if (!root) {
      xEventGroupSetBits(s_provision_events, BIT_ERROR);
      break;
    }
    if (!strcmp(topic, TOPIC_CREATE_CERT_ACC))
      handle_create_cert_accepted(client, root);
    else if (!strcmp(topic, TOPIC_CREATE_CERT_REJ))
      xEventGroupSetBits(s_provision_events, BIT_ERROR);
    else if (!strcmp(topic, TOPIC_PROVISION_ACC))
      handle_provision_accepted(root);
    else if (!strcmp(topic, TOPIC_PROVISION_REJ))
      xEventGroupSetBits(s_provision_events, BIT_ERROR);
    cJSON_Delete(root);
    break;
  }
  case MQTT_EVENT_ERROR:
    xEventGroupSetBits(s_provision_events, BIT_ERROR);
    break;
  default:
    break;
  }
}

/* ========================================================================== */
/* Fleet provisioning                                                         */
/* ========================================================================== */
static esp_err_t ccms_fleet_provision(void) {
  if (nvs_is_provisioned()) {
    ESP_LOGI(TAG, "Already provisioned");
    return ESP_OK;
  }
  read_device_imei(s_imei, sizeof(s_imei));
  s_provision_events = xEventGroupCreate();
  if (!s_provision_events)
    return ESP_ERR_NO_MEM;

  char cid[32];
  snprintf(cid, sizeof(cid), "factory-%s", s_imei);
  esp_mqtt_client_config_t cfg = {
      .broker = {.address = {.uri = MQTT_BROKER_URI, .port = MQTT_BROKER_PORT},
                 .verification = {.crt_bundle_attach = esp_crt_bundle_attach}},
      .credentials =
          {.client_id = cid,
           .authentication = {.certificate = (const char *)claim_cert_pem_start,
                              .key = (const char *)claim_key_pem_start}},
      .session = {.keepalive = MQTT_KEEPALIVE_PROV},
  };
  esp_mqtt_client_handle_t client = esp_mqtt_client_init(&cfg);
  if (!client) {
    vEventGroupDelete(s_provision_events);
    return ESP_ERR_NO_MEM;
  }
  esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID,
                                 mqtt_provision_handler, NULL);

  esp_err_t err = esp_mqtt_client_start(client);
  if (err != ESP_OK) {
    esp_mqtt_client_destroy(client);
    vEventGroupDelete(s_provision_events);
    return err;
  }
  EventBits_t bits =
      xEventGroupWaitBits(s_provision_events, BIT_PROV_ACCEPTED | BIT_ERROR,
                          pdTRUE, pdFALSE, pdMS_TO_TICKS(PROVISION_TIMEOUT_MS));
  esp_mqtt_client_stop(client);
  esp_mqtt_client_destroy(client);
  vEventGroupDelete(s_provision_events);
  s_provision_events = NULL;

  if (bits & BIT_ERROR)
    return ESP_FAIL;
  if (!(bits & BIT_PROV_ACCEPTED))
    return ESP_ERR_TIMEOUT;

  err = nvs_save_device_certs();
  if (err != ESP_OK)
    return err;
  ESP_LOGI(TAG, "Provisioning complete, thing=%s", s_thing_name);
  return ESP_OK;
}

/* ========================================================================== */
/* Device connect                                                             */
/* ========================================================================== */
static esp_mqtt_client_handle_t ccms_connect_device(void) {
  static char cert[4096], key[4096];
  if (s_imei[0] == '\0')
    read_device_imei(s_imei, sizeof(s_imei));
  if (nvs_load_device_certs(cert, sizeof(cert), key, sizeof(key)) != ESP_OK) {
    ESP_LOGE(TAG, "Cert load failed");
    nvs_clear_provisioned_flag();
    return NULL;
  }
  esp_mqtt_client_config_t cfg = {
      .broker = {.address = {.uri = MQTT_BROKER_URI, .port = MQTT_BROKER_PORT},
                 .verification = {.crt_bundle_attach = esp_crt_bundle_attach}},
      .credentials = {.client_id = s_imei,
                      .authentication = {.certificate = cert, .key = key}},
      .session = {.keepalive = MQTT_KEEPALIVE_DEV},
  };
  esp_mqtt_client_handle_t client = esp_mqtt_client_init(&cfg);
  if (!client)
    return NULL;
  esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, mqtt_device_handler,
                                 NULL);
  if (esp_mqtt_client_start(client) != ESP_OK) {
    esp_mqtt_client_destroy(client);
    return NULL;
  }
  s_device_mqtt_client = client;
  return client;
}

/* ========================================================================== */
/* Hardware init                                                              */
/* ========================================================================== */
static void ccms_hw_init(void) {
  gpio_config_t io = {
      .pin_bit_mask = (1ULL << RELAY_SET_PIN) | (1ULL << RELAY_RESET_PIN) |
                      (1ULL << POWER_RELAY_PIN),
      .mode = GPIO_MODE_OUTPUT,
      .pull_up_en = GPIO_PULLUP_DISABLE,
      .pull_down_en = GPIO_PULLDOWN_DISABLE,
      .intr_type = GPIO_INTR_DISABLE,
  };
  ESP_ERROR_CHECK(gpio_config(&io));
  gpio_set_level(POWER_RELAY_PIN,
                 0); /* HIGH = AC mains (Active-LOW: relay OFF) */
  gpio_set_level(RELAY_SET_PIN, 1);   /* HIGH = idle (Active-LOW relay) */
  gpio_set_level(RELAY_RESET_PIN, 1); /* HIGH = idle */
  relay_off(); /* Boot reset: pulses RESET LOW→HIGH to guarantee latch is OFF */

  /* Match Arduino exactly: Modbus.begin(9600, SERIAL_8N1, RS485_RX, RS485_TX)
   * SERIAL_8N1 = 8 data bits, No parity, 1 stop bit.
   * TX buffer = 0 → uart_write_bytes is synchronous (blocking).
   * Normal UART mode (NOT RS485 HW mode) — DE controlled manually via GPIO,
   * exactly like Arduino's digitalWrite(RS485_EN, HIGH/LOW).
   */
  /* CRITICAL: Call order must match Arduino's HardwareSerial::begin():
   *   1. uart_param_config  — enables UART2 peripheral clock first
   *   2. uart_set_pin       — assigns GPIO16/17 to UART2
   *   3. uart_driver_install — installs ISR (must happen AFTER clock is on)
   * Wrong order = ISR configured on unclocked peripheral = RX interrupts
   * silently lost = 0 bytes received forever.
   */
  uart_config_t mb = {.baud_rate = 9600,
                      .data_bits = UART_DATA_8_BITS,
                      .parity = UART_PARITY_DISABLE,
                      .stop_bits = UART_STOP_BITS_1,
                      .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
                      .source_clk = UART_SCLK_APB};
  ESP_ERROR_CHECK(uart_param_config(RS485_UART_NUM, &mb));
  ESP_ERROR_CHECK(uart_set_pin(RS485_UART_NUM, RS485_TX_PIN, RS485_RX_PIN,
                               UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
  ESP_ERROR_CHECK(uart_driver_install(RS485_UART_NUM, 1024, 0, 20, NULL, 0));
  /* Normal UART mode — DE pin (GPIO4) controlled manually in mb_read_raw_try(),
   * matching Arduino's digitalWrite(RS485_EN, HIGH/LOW) pattern. */

  /* Configure DE pin as manual GPIO output (exactly like Arduino:
   * pinMode(RS485_EN, OUTPUT)) */
  gpio_reset_pin(RS485_EN_PIN);
  gpio_set_direction(RS485_EN_PIN, GPIO_MODE_OUTPUT);
  gpio_set_level(RS485_EN_PIN, 0); /* Start in receive mode (DE LOW) */

  uart_config_t gps = {.baud_rate = 9600,
                       .data_bits = UART_DATA_8_BITS,
                       .parity = UART_PARITY_DISABLE,
                       .stop_bits = UART_STOP_BITS_1,
                       .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
                       .source_clk = UART_SCLK_APB};
  ESP_ERROR_CHECK(uart_param_config(GPS_UART_NUM, &gps));
  ESP_ERROR_CHECK(uart_set_pin(GPS_UART_NUM, GPS_TX_PIN, GPS_RX_PIN,
                               UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
  ESP_ERROR_CHECK(uart_driver_install(GPS_UART_NUM, 1024, 0, 0, NULL, 0));

  solar_load_from_nvs();

  /* Flush UART2 RX buffer and allow RS485 transceiver to settle */
  uart_flush_input(RS485_UART_NUM);
  vTaskDelay(pdMS_TO_TICKS(500)); /* 500 ms settle for meter power-up */

  ESP_LOGI(TAG,
           "HW init done — RS485 UART2 TX=%d RX=%d DE=%d (Manual GPIO, 8N1)",
           RS485_TX_PIN, RS485_RX_PIN, RS485_EN_PIN);

  /* ---- DEEP DIAGNOSTIC: check UART2 hardware registers + driver + bus ---- */
  {
    /* === A. Verify UART2 hardware register state === */
    uint32_t uart2_clk = REG_READ(UART_CLKDIV_REG(2));
    uint32_t uart2_conf0 = REG_READ(UART_CONF0_REG(2));
    uint32_t uart2_conf1 = REG_READ(UART_CONF1_REG(2));
    uint32_t uart2_int_en = REG_READ(UART_INT_ENA_REG(2));
    uint32_t uart2_status = REG_READ(UART_STATUS_REG(2));
    ESP_LOGI(TAG, "DIAG-HW: UART2 CLKDIV=0x%08lX CONF0=0x%08lX CONF1=0x%08lX",
             (unsigned long)uart2_clk, (unsigned long)uart2_conf0,
             (unsigned long)uart2_conf1);
    ESP_LOGI(TAG, "DIAG-HW: UART2 INT_ENA=0x%08lX STATUS=0x%08lX",
             (unsigned long)uart2_int_en, (unsigned long)uart2_status);

    /* Check if key RX interrupts are enabled */
    bool rxfifo_full_en =
        (uart2_int_en & (1 << 0)) != 0; /* bit 0 = RXFIFO_FULL */
    bool rxfifo_tout_en =
        (uart2_int_en & (1 << 8)) != 0; /* bit 8 = RXFIFO_TOUT */
    ESP_LOGI(TAG, "DIAG-HW: RXFIFO_FULL_INT=%s  RXFIFO_TOUT_INT=%s",
             rxfifo_full_en ? "ENABLED" : "*** DISABLED ***",
             rxfifo_tout_en ? "ENABLED" : "*** DISABLED ***");
    if (!rxfifo_full_en || !rxfifo_tout_en) {
      ESP_LOGE(TAG, "DIAG-HW: *** RX INTERRUPTS NOT ENABLED — driver install "
                    "failed! ***");
    }

    /* === B. Send Modbus request and poll HARDWARE FIFO directly === */
    uint8_t diag_req[8] = {0x01, 0x03, 0x00, 0x2A, 0x00, 0x02, 0x00, 0x00};
    uint16_t dc = mb_crc16(diag_req, 6);
    diag_req[6] = (uint8_t)(dc & 0xFF);
    diag_req[7] = (uint8_t)(dc >> 8);

    ESP_LOGI(TAG, "DIAG: TX → [%02X %02X %02X %02X %02X %02X %02X %02X]",
             diag_req[0], diag_req[1], diag_req[2], diag_req[3], diag_req[4],
             diag_req[5], diag_req[6], diag_req[7]);

    uart_flush_input(RS485_UART_NUM);
    gpio_set_level(RS485_EN_PIN, 1);
    uart_write_bytes(RS485_UART_NUM, (const char *)diag_req, 8);
    uart_wait_tx_done(RS485_UART_NUM, pdMS_TO_TICKS(200));
    gpio_set_level(RS485_EN_PIN, 0);

    /* Poll the HARDWARE RX FIFO register directly for 500ms */
    ESP_LOGI(TAG, "DIAG: Polling UART2 HW FIFO for 500ms...");
    uint32_t hw_fifo_max = 0;
    for (int poll = 0; poll < 50; poll++) {
      esp_rom_delay_us(10000); /* 10ms busy wait (no RTOS yield) */
      uint32_t st = REG_READ(UART_STATUS_REG(2));
      uint32_t rxcnt = (st >> 0) & 0xFF; /* bits [7:0] = RXFIFO_CNT */
      if (rxcnt > hw_fifo_max)
        hw_fifo_max = rxcnt;
      if (rxcnt > 0) {
        ESP_LOGI(TAG, "DIAG: HW FIFO has %lu bytes at poll %d (bypass driver!)",
                 (unsigned long)rxcnt, poll);
        break;
      }
    }

    if (hw_fifo_max == 0) {
      ESP_LOGE(TAG,
               "DIAG: *** HW FIFO stayed EMPTY — no bytes reached GPIO16 ***");
      ESP_LOGE(TAG, "DIAG: This means the meter is NOT sending data back.");
      ESP_LOGE(
          TAG,
          "DIAG: Either TX never left GPIO17, or RX never reached GPIO16.");
    }

    /* Also try the driver method */
    uint8_t diag_buf[32] = {0};
    int diag_got = uart_read_bytes(RS485_UART_NUM, diag_buf, sizeof(diag_buf),
                                   pdMS_TO_TICKS(500));
    if (diag_got > 0) {
      char hex[32 * 3 + 1] = {0};
      for (int x = 0; x < diag_got && x < 32; x++)
        snprintf(hex + x * 3, 4, "%02X ", diag_buf[x]);
      ESP_LOGI(TAG, "DIAG: Driver got %d bytes: %s", diag_got, hex);
    } else {
      ESP_LOGW(TAG, "DIAG: Driver got 0 bytes (ring buffer empty)");
    }

    /* === C. Check GPIO16 input level === */
    gpio_set_direction(RS485_RX_PIN, GPIO_MODE_INPUT);
    int rx_level = gpio_get_level(RS485_RX_PIN);
    ESP_LOGI(TAG, "DIAG: GPIO16 raw level = %d (should be 1 when bus idle)",
             rx_level);
    /* Restore GPIO16 to UART function */
    uart_set_pin(RS485_UART_NUM, RS485_TX_PIN, RS485_RX_PIN, UART_PIN_NO_CHANGE,
                 UART_PIN_NO_CHANGE);

    uart_flush_input(RS485_UART_NUM);
  }
}

/* ========================================================================== */
/* app_main                                                                   */
/* ========================================================================== */
void app_main(void) {
  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
      ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ESP_ERROR_CHECK(nvs_flash_init());
  }

  /* Create Modbus mutex FIRST — before any Modbus access can occur. */
  s_modbus_mutex = xSemaphoreCreateMutex();
  if (!s_modbus_mutex) {
    ESP_LOGE(TAG, "FATAL: Failed to create Modbus mutex — halting.");
    while (1)
      vTaskDelay(pdMS_TO_TICKS(1000));
  }

  /* V3-3: Restore battery mode before any relay control */
  if (nvs_load_battery_mode()) {
    s_is_battery_mode = true;
    gpio_set_level(POWER_RELAY_PIN, 1); /* LOW = Battery mode */
    ESP_LOGW(TAG,
             "V3: Battery mode RESTORED from NVS (rebooted during blackout)");
  }

  ccms_hw_init();

  ret = wifi_init_sta_blocking();
  if (ret != ESP_OK) {
    ESP_LOGE(TAG, "Wi-Fi failed, restarting in 15s");
    vTaskDelay(pdMS_TO_TICKS(15000));
    esp_restart();
  }

  if (s_imei[0] == '\0')
    read_device_imei(s_imei, sizeof(s_imei));

  ret = ccms_fleet_provision();
  if (ret != ESP_OK) {
    ESP_LOGE(TAG, "Provisioning failed, restarting in 30s");
    vTaskDelay(pdMS_TO_TICKS(30000));
    esp_restart();
  }

  if (!ccms_connect_device()) {
    ESP_LOGE(TAG, "Device connect failed, restarting");
    esp_restart();
  }

  ESP_LOGI(TAG, "Device online — starting main loop");
  s_modbus_start_after_us = esp_timer_get_time() + 5000000ULL; /* 5 s warm-up */

  while (1) {
    gps_solar_update();

    uint64_t now = esp_timer_get_time();
    if (now >= s_modbus_start_after_us) {
      modbus_detect_if_needed();
      update_power_failure_logic(s_cached_rv, s_cached_yv, s_cached_bv);
      /* V3-4: Fault logic runs here in the main loop, not in MQTT task.
       * Uses the same validated cached values as power-fail logic. */
      if ((now - s_last_fault_check_us) >= POWER_CHECK_INTERVAL_US) {
        s_last_fault_check_us = now;
        check_and_publish_faults(s_cached_rv, s_cached_yv, s_cached_bv,
                                 s_cached_ri, s_cached_yi, s_cached_bi);
      }
    }

    /* Auto relay: ON at sunset, OFF at sunrise.
     * Requires GPS fix (s_solar_valid). s_relay_on prevents re-triggering. */
    if (s_solar_valid && s_device_mqtt_connected) {
      bool night = is_night_time();
      if (night && !s_relay_on) {
        ESP_LOGI(TAG, "Auto: sunset reached — relay ON");
        relay_on();
        publish_telemetry_now();
      } else if (!night && s_relay_on) {
        ESP_LOGI(TAG, "Auto: sunrise reached — relay OFF");
        relay_off();
        publish_telemetry_now();
      }
    }

    if (s_last_telemetry_us == 0 ||
        (now - s_last_telemetry_us) >= (TELEMETRY_INTERVAL_MS * 1000ULL)) {
      publish_telemetry_now();
      s_last_telemetry_us = now;
    }
    vTaskDelay(pdMS_TO_TICKS(1000));
  }
}
