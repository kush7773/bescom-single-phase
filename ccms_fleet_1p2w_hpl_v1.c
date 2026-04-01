/*
 * CCMS ESP32 — HPL Single-Phase Meter (1P2W) + AWS IoT Fleet Provisioning
 * =========================================================================
 * Adapted from ccms_fleet_3p4w_mfm_m11_v5 for the HPL single-phase energy
 * meter.  Y and B phase values are always 0; R phase carries all readings.
 *
 * Meter: HPL Single-Phase
 * Protocol: Modbus RTU, FC=0x04 (Read Input Registers), Slave ID=0x05
 * Baud: 9600, 8N1  |  RS485 TX=GPIO17 RX=GPIO16 DE=GPIO4
 *
 * Register map (base-1, 30000-series):
 *   30008  Voltage (V)       1 reg  × 0.1    → V
 *   30009  Current (A)       1 reg  × 0.01   → A
 *   30011  Active Power      1 reg  × 0.001  → kW
 *   30012  Power Factor      1 reg  × 0.01   → (0.00–1.00)
 *   30013  Frequency (Hz)    1 reg  × 0.1    → Hz
 *   30015  Total kWh         2 regs × 0.1    → kWh  (Big-Endian uint32)
 *   30017  Total kVAh        2 regs × 0.1    → kVAh (Big-Endian uint32)
 *   30025  Apparent Power    1 reg  × 0.001  → kVA
 *
 * Wire address = register - 30001  (e.g. 30008 → 0x0007)
 *
 * Hardening inherited from v5:
 *  V3-1  volatile on inter-task shared state
 *  V3-2  per-fault 60s cooldown (no dashboard flood)
 *  V3-3  NVS battery-mode persistence across reboots
 *  V3-4  fault logic in main loop (no MQTT-task data race)
 *  V3-5  faults silenced when modbus offline
 *  V3-6  mutex double-give fix in mb_read_raw_try()
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
#include "esp_http_client.h" /* esp_http_client_config_t */
#include "esp_https_ota.h"   /* esp_https_ota() */
#include "esp_ota_ops.h"     /* esp_ota_get_app_description() */
#include "esp_rom_sys.h"   /* esp_rom_delay_us() */
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

/* Street-light count config */
#ifndef CONFIG_CCMS_NSL
#define CONFIG_CCMS_NSL 0
#endif
#ifndef CONFIG_CCMS_NWSL
#define CONFIG_CCMS_NWSL 0
#endif
#ifndef CONFIG_CCMS_LAMP_CURRENT_MA
#define CONFIG_CCMS_LAMP_CURRENT_MA 500  /* milliamps per lamp */
#endif

/* Current firmware version reported in OTA version checks */
#ifndef CONFIG_FIRMWARE_VERSION
#define CONFIG_FIRMWARE_VERSION "1.0.0"
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

/* Voltage/current cache — volatile: written by main loop, read by MQTT task.
 * Single-phase: only R phase is real; Y and B are always 0. */
static volatile float s_cached_rv = 230.0f; /* R-phase voltage (single-phase) */
static volatile float s_cached_ri = 0.0f;   /* R-phase current                */
static volatile bool  s_cache_valid = false; /* true after first successful read */

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

/* Clock-aligned 15-min telemetry: last IST slot published (0–95, -1=never) */
static int  s_last_published_slot = -1;

/* Initial publish: deferred until modbus has stabilised after boot */
static bool s_initial_publish_due  = false;

/* GPS lock transition: triggers one immediate telemetry upload */
static bool s_gps_was_locked       = false;

/* OTA pending state — set by MQTT handler, consumed by main loop task spawn */
static char          s_ota_job_id[64]  = {0};
static char          s_ota_url[512]    = {0};
static volatile bool s_ota_pending     = false;

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
/* HPL Single-Phase meter — Modbus slave + register map                      */
/* ========================================================================== */
#define MB_SLAVE_ID 0x05  /* HPL meter slave address                          */
#define MB_FC       0x04  /* Function Code: Read Input Registers               */

/* Register map — base-1 (30000-series); wire addr = reg - 30001 */
#define REG_VOLTAGE  30008  /* 0x0007  1 reg  × 0.1    → V          */
#define REG_CURRENT  30009  /* 0x0008  1 reg  × 0.01   → A          */
#define REG_KW       30011  /* 0x000A  1 reg  × 0.001  → kW         */
#define REG_PF       30012  /* 0x000B  1 reg  × 0.01   → PF         */
#define REG_FREQ     30013  /* 0x000C  1 reg  × 0.1    → Hz         */
#define REG_KWH      30015  /* 0x000E  2 regs × 0.1    → kWh BE u32 */
#define REG_KVAH     30017  /* 0x0010  2 regs × 0.1    → kVAh BE u32*/
#define REG_KVA      30025  /* 0x0018  1 reg  × 0.001  → kVA        */

/* Fault thresholds */
#define FAULT_OV_THRESH  270.0f  /* Over Voltage  V > 270 V */
#define FAULT_UV_THRESH  170.0f  /* Under Voltage V < 170 V */
#define FAULT_OL_THRESH   18.0f  /* Over Load     I > 18 A  */

/* Fault indices — single-phase only; Y/B phase faults not applicable */
typedef enum {
  FIDX_ROV = 0,  /* R-phase Over Voltage               */
  FIDX_RUV,      /* R-phase Under Voltage              */
  FIDX_ROL,      /* R-phase Over Load                  */
  FIDX_OL,       /* Total Over Load (same as ROL here) */
  FIDX_ACPFl,    /* AC Power Failure                   */
  FIDX_RPNl,     /* No Load (relay ON, V present, I≈0) */
  FIDX_SONF,     /* Street ON No Feed (relay ON, V=0)  */
  FIDX_SOFF,     /* Street OFF, Feed present (V ok, I>0 but relay OFF) */
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
/* Clock-aligned 15-min telemetry                                             */
/* ========================================================================== */
/*
 * get_ist_15min_slot()
 * Returns the current IST 15-minute slot index (0–95).
 *   slot 0  = 00:00–00:14 IST
 *   slot 57 = 14:15–14:29 IST
 *   slot 95 = 23:45–23:59 IST
 * Returns -1 if wall-clock time has not yet been synced (year < 2020).
 */
static int get_ist_15min_slot(void) {
  time_t t = time(NULL);
  if (t < 1577836800LL) return -1; /* pre-2020 → time not synced */
  struct tm tm;
  gmtime_r(&t, &tm);
  int ist_min = (tm.tm_hour * 60 + tm.tm_min + 330) % 1440; /* UTC+5:30 */
  return ist_min / 15;                                       /* 0–95 */
}

/*
 * telemetry_due()
 * Returns true when a 15-minute telemetry publish should fire:
 *   • GPS time synced: fires once per IST 15-min boundary (:00/:15/:30/:45)
 *   • Time not synced: falls back to 15-min elapsed-time interval from boot
 */
static bool telemetry_due(void) {
  int slot = get_ist_15min_slot();
  if (slot < 0) {
    /* No time sync — elapsed-time fallback */
    uint64_t now = esp_timer_get_time();
    return (s_last_telemetry_us == 0 ||
            (now - s_last_telemetry_us) >= (TELEMETRY_INTERVAL_MS * 1000ULL));
  }
  return (slot != s_last_published_slot);
}

/* ========================================================================== */
/* OTA — AWS IoT Jobs firmware update                                         */
/* ========================================================================== */

/* Publish a job status update to $aws/things/{IMEI}/jobs/{jobId}/update */
static void ota_report_status(const char *job_id, const char *status,
                              const char *step_id, const char *fail_code) {
  if (!s_device_mqtt_client || !s_device_mqtt_connected || !job_id || !job_id[0])
    return;
  char topic[160];
  snprintf(topic, sizeof(topic), "$aws/things/%s/jobs/%s/update", s_imei,
           job_id);
  cJSON *root = cJSON_CreateObject();
  cJSON_AddStringToObject(root, "status", status);
  if (step_id || fail_code) {
    cJSON *det = cJSON_CreateObject();
    if (step_id)   cJSON_AddStringToObject(det, "stepId",      step_id);
    if (fail_code) cJSON_AddStringToObject(det, "failureCode", fail_code);
    cJSON_AddItemToObject(root, "statusDetails", det);
  }
  char *p = cJSON_PrintUnformatted(root);
  if (p) {
    esp_mqtt_client_publish(s_device_mqtt_client, topic, p, 0, 1, 0);
    free(p);
  }
  cJSON_Delete(root);
}

/* FreeRTOS task: download + flash firmware, then reboot.
 * Runs independently so the MQTT keepalive is not blocked. */
static void ota_flash_task(void *arg) {
  (void)arg;
  char job_id[64], url[512];
  /* Copy from globals under simple snapshot — main loop sets s_ota_pending=false
   * before spawning this task so no race with another trigger. */
  safe_copy(job_id, sizeof(job_id), s_ota_job_id);
  safe_copy(url,    sizeof(url),    s_ota_url);

  ESP_LOGI(TAG, "OTA: downloading from %s (job=%s)", url, job_id);
  ota_report_status(job_id, "IN_PROGRESS", "DOWNLOADING", NULL);

  esp_http_client_config_t http_cfg = {
      .url               = url,
      .crt_bundle_attach = esp_crt_bundle_attach,
      .timeout_ms        = 30000,
  };
  esp_https_ota_config_t ota_cfg = { .http_config = &http_cfg };

  ota_report_status(job_id, "IN_PROGRESS", "FLASHING", NULL);
  esp_err_t err = esp_https_ota(&ota_cfg);
  if (err == ESP_OK) {
    ESP_LOGI(TAG, "OTA: flash succeeded — rebooting");
    ota_report_status(job_id, "SUCCEEDED", NULL, NULL);
    vTaskDelay(pdMS_TO_TICKS(2000)); /* allow MQTT publish to drain */
    esp_restart();
  } else {
    ESP_LOGE(TAG, "OTA: flash failed (0x%x)", err);
    const char *code = (err == ESP_ERR_NO_MEM)        ? "INSUFFICIENT_SPACE"
                     : (err == ESP_ERR_INVALID_ARG)   ? "DOWNLOAD_FAILED"
                                                      : "FLASH_FAILED";
    ota_report_status(job_id, "FAILED", NULL, code);
  }
  vTaskDelete(NULL);
}

/* Handle an incoming job notification: request the full job document.
 * Called for both jobs/notify and jobs/get/accepted payloads. */
static void ota_request_job_document(const char *job_id) {
  if (!job_id || !job_id[0]) return;
  char topic[160];
  snprintf(topic, sizeof(topic), "$aws/things/%s/jobs/%s/get", s_imei, job_id);
  char pay[64];
  snprintf(pay, sizeof(pay), "{\"clientToken\":\"%s\"}", s_imei);
  if (s_device_mqtt_client && s_device_mqtt_connected)
    esp_mqtt_client_publish(s_device_mqtt_client, topic, pay, 0, 1, 0);
}

/* Parse a jobs/notify payload and kick off job document fetch */
static void ota_handle_notify(const char *json) {
  cJSON *root = cJSON_Parse(json);
  if (!root) return;
  /* jobs.QUEUED[0].jobId */
  cJSON *jobs  = cJSON_GetObjectItem(root, "jobs");
  cJSON *queued = jobs ? cJSON_GetObjectItem(jobs, "QUEUED") : NULL;
  if (!queued) queued = jobs ? cJSON_GetObjectItem(jobs, "IN_PROGRESS") : NULL;
  cJSON *first = (cJSON_IsArray(queued) && cJSON_GetArraySize(queued) > 0)
                     ? cJSON_GetArrayItem(queued, 0) : NULL;
  cJSON *jid   = first ? cJSON_GetObjectItem(first, "jobId") : NULL;
  if (cJSON_IsString(jid)) {
    ESP_LOGI(TAG, "OTA: job queued — %s", jid->valuestring);
    ota_request_job_document(jid->valuestring);
  }
  cJSON_Delete(root);
}

/* Parse a jobs/get/accepted payload (global pending jobs list) */
static void ota_handle_get_accepted(const char *json) {
  cJSON *root = cJSON_Parse(json);
  if (!root) return;
  /* Try queuedJobs first, then inProgressJobs */
  cJSON *arr = cJSON_GetObjectItem(root, "queuedJobs");
  if (!cJSON_IsArray(arr) || cJSON_GetArraySize(arr) == 0)
    arr = cJSON_GetObjectItem(root, "inProgressJobs");
  cJSON *first = (cJSON_IsArray(arr) && cJSON_GetArraySize(arr) > 0)
                     ? cJSON_GetArrayItem(arr, 0) : NULL;
  cJSON *jid   = first ? cJSON_GetObjectItem(first, "jobId") : NULL;
  if (cJSON_IsString(jid)) {
    ESP_LOGI(TAG, "OTA: pending job found — %s", jid->valuestring);
    ota_request_job_document(jid->valuestring);
  }
  cJSON_Delete(root);
}

/* Parse a jobs/{jobId}/get/accepted payload and set s_ota_pending */
static void ota_handle_job_document(const char *json) {
  cJSON *root = cJSON_Parse(json);
  if (!root) return;
  cJSON *exec    = cJSON_GetObjectItem(root, "execution");
  cJSON *jid     = exec ? cJSON_GetObjectItem(exec, "jobId")       : NULL;
  cJSON *jdoc    = exec ? cJSON_GetObjectItem(exec, "jobDocument") : NULL;
  cJSON *op      = jdoc ? cJSON_GetObjectItem(jdoc, "operation")   : NULL;
  cJSON *url     = jdoc ? cJSON_GetObjectItem(jdoc, "url")         : NULL;
  cJSON *version = jdoc ? cJSON_GetObjectItem(jdoc, "version")     : NULL;

  if (!cJSON_IsString(jid) || !cJSON_IsString(url)) {
    ESP_LOGW(TAG, "OTA: job document missing jobId or url");
    cJSON_Delete(root);
    return;
  }
  if (cJSON_IsString(op) && strcmp(op->valuestring, "firmware_update") != 0) {
    ESP_LOGI(TAG, "OTA: operation '%s' — not a firmware update, skip",
             op->valuestring);
    cJSON_Delete(root);
    return;
  }
  /* Version check: skip if already on this version */
  if (cJSON_IsString(version) &&
      strcmp(version->valuestring, CONFIG_FIRMWARE_VERSION) == 0) {
    ESP_LOGI(TAG, "OTA: already on version %s, reporting SUCCEEDED",
             version->valuestring);
    ota_report_status(jid->valuestring, "SUCCEEDED", NULL, NULL);
    cJSON_Delete(root);
    return;
  }

  safe_copy(s_ota_job_id, sizeof(s_ota_job_id), jid->valuestring);
  safe_copy(s_ota_url,    sizeof(s_ota_url),    url->valuestring);
  s_ota_pending = true;
  ESP_LOGI(TAG, "OTA: pending — job=%s url=%s ver=%s", s_ota_job_id, s_ota_url,
           cJSON_IsString(version) ? version->valuestring : "?");
  cJSON_Delete(root);
}

/* Returns true if 'topic' matches the pattern prefix+"/"+suffix
 * (simple single-level wildcard substitution for jobs/{jobId}/... matching) */
static bool topic_has_suffix(const char *topic, const char *suffix) {
  size_t tlen = strlen(topic), slen = strlen(suffix);
  return (tlen >= slen && strcmp(topic + tlen - slen, suffix) == 0);
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

  const uint8_t FN = MB_FC;          /* 0x04 — Read Input Registers */
  uint16_t addr = reg_3xxxx - 30001; /* base-1 → wire address       */

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
 * mb_read_1reg()
 * --------------
 * Reads one 16-bit integer register from the HPL meter (FC=0x04).
 * Response: 7 bytes [SlaveID, FC, ByteCount=2, DataHigh, DataLow, CRC_L, CRC_H]
 * Value = raw_uint16 × scale.
 * Returns -1.0f on communication failure.
 */
static float mb_read_1reg(uint16_t reg_3xxxx, float scale) {
  uint8_t data[2] = {0};
  if (!mb_read_raw_try(MB_SLAVE_ID, reg_3xxxx, 1, data, sizeof(data)))
    return -1.0f;
  uint16_t raw = ((uint16_t)data[0] << 8) | data[1];
  float v = (float)raw * scale;
  if (v < 0.0f || v > 1000000.0f)
    return -1.0f;
  return v;
}

/*
 * mb_read_2reg()
 * --------------
 * Reads two consecutive 16-bit registers as a Big-Endian 32-bit integer.
 * Response: 9 bytes [SlaveID, FC, ByteCount=4, D0H, D0L, D1H, D1L, CRC_L, CRC_H]
 * 32-bit assembly: (D0H<<24 | D0L<<16 | D1H<<8 | D1L) — standard Big-Endian.
 * Value = raw_uint32 × scale.
 * Returns -1.0f on communication failure.
 */
static float mb_read_2reg(uint16_t reg_3xxxx, float scale) {
  uint8_t data[4] = {0};
  if (!mb_read_raw_try(MB_SLAVE_ID, reg_3xxxx, 2, data, sizeof(data)))
    return -1.0f;
  uint32_t raw = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
                 ((uint32_t)data[2] << 8)  |  (uint32_t)data[3];
  float v = (float)raw * scale;
  if (v < 0.0f || v > 1000000000.0f)
    return -1.0f;
  return v;
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

  /* Single-phase: read R-phase voltage only for online/offline detection */
  float rv = mb_read_1reg(REG_VOLTAGE, 0.1f);
  bool read_ok = (rv >= 0.0f);

  if (read_ok) {
    s_cached_rv = clamp_non_negative(rv);
    if (!s_modbus_online)
      ESP_LOGI(TAG, "Modbus back online V=%.1f", s_cached_rv);
    s_modbus_online = true;
    s_modbus_offline_count = 0;
    s_cache_valid = true;
  } else {
    /* Failed read — debounce before declaring offline */
    s_modbus_offline_count++;
    if (s_modbus_offline_count > MODBUS_OFFLINE_COUNT_MAX)
      s_modbus_offline_count = MODBUS_OFFLINE_COUNT_MAX;
    ESP_LOGW(TAG, "Modbus read fail %d/%d", s_modbus_offline_count,
             MODBUS_OFFLINE_DEBOUNCE);
    if (s_modbus_offline_count >= MODBUS_OFFLINE_DEBOUNCE)
      s_modbus_online = false;
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

static void switch_to_battery(const char *reason, float rv) {
  gpio_set_level(POWER_RELAY_PIN, 1); /* LOW = Battery mode */
  s_is_battery_mode = true;
  s_cached_rv = 0.0f;
  nvs_save_battery_mode(true);
  ESP_LOGW(TAG, "BATTERY MODE [%s] V=%.1f", reason, rv);
  send_power_event_mqtt("POWER_FAILURE_SWITCHED_TO_BATTERY", "BATTERY");
}

static void switch_to_ac(float rv) {
  gpio_set_level(POWER_RELAY_PIN, 0); /* HIGH = AC mains */
  s_is_battery_mode = false;
  s_low_volt_buffer = 0;
  nvs_save_battery_mode(false);
  ESP_LOGI(TAG, "AC RESTORED V=%.1f", rv);
  send_power_event_mqtt("AC_POWER_RESTORED", "AC_ADAPTER");
}

static void update_power_failure_logic(float rv) {
  uint64_t now = esp_timer_get_time();
  if ((now - s_last_power_check_us) < POWER_CHECK_INTERVAL_US)
    return;
  s_last_power_check_us = now;

  /* ── SWITCH TO BATTERY ───────────────────────────────────────────────── */
  if (!s_is_battery_mode) {
    /* Signal A: meter alive but voltage below threshold */
    if (s_modbus_online) {
      if (rv < VOLTAGE_DEAD_THRESH) {
        if (++s_low_volt_buffer >= LOW_VOLT_DEBOUNCE)
          switch_to_battery("LOW_VOLTAGE", rv);
      } else {
        s_low_volt_buffer = 0;
      }
    }
    /* Signal B: meter completely offline */
    if (!s_modbus_online && s_modbus_offline_count >= MODBUS_DEAD_FOR_BATTERY)
      switch_to_battery("METER_OFFLINE", rv);
  }

  /* ── RESTORE AC ──────────────────────────────────────────────────────── */
  else {
    if (s_modbus_online && rv > VOLTAGE_DEAD_THRESH)
      switch_to_ac(rv);
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

/* V3-4 + V3-5: check_and_publish_faults — single-phase version.
 * Called ONLY when s_modbus_online (validated cache data).
 * Y/B phase faults are not applicable for 1P2W. */
static void check_and_publish_faults(float rv, float ri) {
  if (!s_modbus_online || !s_cache_valid)
    return;

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

  CHK(FIDX_ROV,   "ROV",   rv > FAULT_OV_THRESH);
  CHK(FIDX_RUV,   "RUV",   rv > 0.0f && rv < FAULT_UV_THRESH);
  CHK(FIDX_ROL,   "ROL",   ri > FAULT_OL_THRESH);
  CHK(FIDX_OL,    "OL",    ri > FAULT_OL_THRESH);
  CHK(FIDX_ACPFl, "ACPFl", s_is_battery_mode);
  CHK(FIDX_RPNl,  "RPNl",  s_relay_on && rv > 50.0f && ri < 0.1f);
  CHK(FIDX_SONF,  "SONF",  s_relay_on  && rv < 50.0f);
  CHK(FIDX_SOFF,  "SOFF",  !s_relay_on && rv > 50.0f && ri > 0.1f);

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

  /* --- Read HPL single-phase registers individually ---
   * FC=0x04, Slave=0x05.  1-reg reads: 16-bit uint × scale.
   * 2-reg reads: Big-Endian uint32 × scale.
   * Y and B phase values are always 0 (single-phase meter).
   */
  float rv   = 0.0f, ri  = 0.0f;
  float freq = 0.0f, rpf = 0.0f;
  float rkw  = 0.0f, rkva= 0.0f;
  float kwh  = 0.0f, kvah= 0.0f;

  {
    float v = mb_read_1reg(REG_VOLTAGE, 0.1f);
    if (v >= 0.0f) { rv = clamp_non_negative(v); s_cached_rv = rv; }
  }
  {
    float v = mb_read_1reg(REG_CURRENT, 0.01f);
    if (v >= 0.0f) { ri = clamp_non_negative(v); s_cached_ri = ri; }
  }
  {
    float v = mb_read_1reg(REG_KW, 0.001f);
    if (v >= 0.0f) rkw = clamp_non_negative(v);
  }
  {
    float v = mb_read_1reg(REG_PF, 0.01f);
    if (v >= 0.0f && v <= 1.0f) rpf = v;
  }
  {
    float v = mb_read_1reg(REG_FREQ, 0.1f);
    if (v >= 0.0f) freq = clamp_non_negative(v);
  }
  {
    float v = mb_read_2reg(REG_KWH, 0.1f);
    if (v >= 0.0f) kwh = clamp_non_negative(v);
  }
  {
    float v = mb_read_2reg(REG_KVAH, 0.1f);
    if (v >= 0.0f) kvah = clamp_non_negative(v);
  }
  {
    float v = mb_read_1reg(REG_KVA, 0.001f);
    if (v >= 0.0f) rkva = clamp_non_negative(v);
  }

  /* Single-phase: Y/B always 0 */
  const float yv = 0.0f, bv = 0.0f;
  const float yi = 0.0f, bi = 0.0f;
  const float ypf = 0.0f, bpf = 0.0f;
  const float ykw = 0.0f, bkw = 0.0f;
  const float ykva= 0.0f, bkva= 0.0f;

  float tkw  = rkw;
  float tkva = rkva;
  float avg_v = rv;   /* single-phase: avg = R phase */
  float avg_i = ri;

  /* Faults are evaluated in the main loop (V3-4) — not here. */

  /* --- Build payload --- */
  char topic[64], ts[32] = {0}, sr[8] = {0}, ss_s[8] = {0};
  snprintf(topic, sizeof(topic), "dt/%s", s_imei);
  iso_time_utc(ts, sizeof(ts));
  format_hhmm(s_sunrise_min, sr, sizeof(sr));
  format_hhmm(s_sunset_min, ss_s, sizeof(ss_s));

  /* Compute fault_code = count of currently active faults */
  int fault_code_val = 0;
  for (int _fi = 0; _fi < FIDX_MAX; _fi++) {
    if (s_fault[_fi].active) fault_code_val++;
  }

  /* Estimate lights ON from total current / per-lamp rated current */
  int no_lights_on_val = 0;
#if CONFIG_CCMS_LAMP_CURRENT_MA > 0
  {
    float lamp_a = CONFIG_CCMS_LAMP_CURRENT_MA / 1000.0f;
    no_lights_on_val = (int)roundf(avg_i / lamp_a);
    if (no_lights_on_val < 0) no_lights_on_val = 0;
  }
#endif

  char nsl_str[16], nwsl_str[16];
  snprintf(nsl_str,  sizeof(nsl_str),  "%d", (int)CONFIG_CCMS_NSL);
  snprintf(nwsl_str, sizeof(nwsl_str), "%d", (int)CONFIG_CCMS_NWSL);

  cJSON *root = cJSON_CreateObject();
  cJSON_AddStringToObject(root, "device_id", s_imei);
  cJSON_AddStringToObject(root, "time", ts);
  cJSON_AddBoolToObject(root, "on_off", s_relay_on);
  cJSON_AddNumberToObject(root, "fault_code", fault_code_val);
  cJSON_AddNumberToObject(root, "latt", s_gps.loc_valid ? s_gps.lat : 0.0);
  cJSON_AddNumberToObject(root, "long", s_gps.loc_valid ? s_gps.lon : 0.0);
  cJSON_AddStringToObject(root, "box_no", "");
  cJSON_AddStringToObject(root, "nsl", nsl_str);
  cJSON_AddStringToObject(root, "nwsl", nwsl_str);
  cJSON_AddStringToObject(root, "mode", "Auto(A)");
  cJSON_AddStringToObject(root, "sun_set_time", ss_s);
  cJSON_AddStringToObject(root, "sun_rise_time", sr);
  cJSON_AddNumberToObject(root, "no_lights_on", no_lights_on_val);

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
             "Telemetry published mid=%d | V=%.2f I=%.2f kWh=%.2f"
             " kW=%.2f PF=%.2f Hz=%.2f modbus=%s fault_code=%d",
             mid, rv, ri, kwh, rkw, rpf, freq,
             s_modbus_online ? "OK" : "NO", fault_code_val);
    free(payload);
  }
  cJSON_Delete(root);

  /* Update clock-aligned slot tracker so telemetry_due() won't re-fire
   * within the same 15-min window */
  int _slot = get_ist_15min_slot();
  if (_slot >= 0) s_last_published_slot = _slot;
  s_last_telemetry_us = esp_timer_get_time();
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
  snprintf(t, sizeof(t), "$aws/things/%s/jobs/+/get/rejected", s_imei);
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
    /* Initial publish is deferred to the main loop so it fires only after
     * modbus has stabilised (5 s warm-up + first successful read). */
    s_initial_publish_due = true;
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

    /* ------------------------------------------------------------------ */
    /* OTA / AWS IoT Jobs handler                                          */
    /* ------------------------------------------------------------------ */
    {
      char jobs_notify_t[128], jobs_get_acc_t[128];
      snprintf(jobs_notify_t,  sizeof(jobs_notify_t),
               "$aws/things/%s/jobs/notify", s_imei);
      snprintf(jobs_get_acc_t, sizeof(jobs_get_acc_t),
               "$aws/things/%s/jobs/get/accepted", s_imei);

      /* Static buffers for multi-chunk job payloads (reused per-message) */
      static char job_json[MAX_MQTT_JSON_LEN];
      int jlen = ev->data_len < (int)(sizeof(job_json) - 1)
                     ? ev->data_len : (int)(sizeof(job_json) - 1);

      if (!strcmp(topic, jobs_notify_t)) {
        /* New or updated job notification */
        memcpy(job_json, ev->data, jlen); job_json[jlen] = '\0';
        ota_handle_notify(job_json);

      } else if (!strcmp(topic, jobs_get_acc_t)) {
        /* Response to our on-connect jobs/get poll */
        memcpy(job_json, ev->data, jlen); job_json[jlen] = '\0';
        ota_handle_get_accepted(job_json);

      } else if (topic_has_suffix(topic, "/get/accepted")) {
        /* Per-job document: $aws/things/{IMEI}/jobs/{jobId}/get/accepted */
        memcpy(job_json, ev->data, jlen); job_json[jlen] = '\0';
        ota_handle_job_document(job_json);

      } else if (topic_has_suffix(topic, "/get/rejected") ||
                 topic_has_suffix(topic, "/update/rejected")) {
        memcpy(job_json, ev->data, jlen); job_json[jlen] = '\0';
        ESP_LOGW(TAG, "OTA: job request rejected — %.*s", jlen, job_json);
      }
    }
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

    /* === B. Send Modbus request and poll HARDWARE FIFO directly ===
     * FC=0x04, Slave=0x05, Reg=0x0007 (Voltage, 1 reg) */
    uint8_t diag_req[8] = {MB_SLAVE_ID, MB_FC, 0x00, 0x07, 0x00, 0x01, 0x00, 0x00};
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

    /* ------------------------------------------------------------------ */
    /* Modbus detection + power-failure + fault checks                     */
    /* ------------------------------------------------------------------ */
    if (now >= s_modbus_start_after_us) {
      modbus_detect_if_needed();
      update_power_failure_logic(s_cached_rv);
      /* V3-4: Fault logic runs in main loop, not MQTT task. */
      if ((now - s_last_fault_check_us) >= POWER_CHECK_INTERVAL_US) {
        s_last_fault_check_us = now;
        check_and_publish_faults(s_cached_rv, s_cached_ri);
      }
    }

    /* ------------------------------------------------------------------ */
    /* REQ 3 — Initial publish after modbus stabilises on boot.            */
    /* Fires once: when modbus comes online after the 5 s warm-up, or      */
    /* after a 2-min safety timeout so the server always gets an update.   */
    /* ------------------------------------------------------------------ */
    if (s_initial_publish_due && s_device_mqtt_connected &&
        now >= s_modbus_start_after_us &&
        (s_modbus_online ||
         now >= s_modbus_start_after_us + 120000000ULL /* 2 min */)) {
      ESP_LOGI(TAG, "Initial publish after boot stabilisation");
      publish_telemetry_now();
      s_initial_publish_due = false;
    }

    /* ------------------------------------------------------------------ */
    /* REQ 4 — GPS lock: publish coordinates immediately on first fix.     */
    /* ------------------------------------------------------------------ */
    if (s_gps_locked_once && !s_gps_was_locked) {
      s_gps_was_locked = true;
      if (s_device_mqtt_connected && !s_initial_publish_due) {
        ESP_LOGI(TAG, "GPS fix acquired — uploading coordinates");
        publish_telemetry_now();
      }
    }

    /* ------------------------------------------------------------------ */
    /* REQ 2 — Clock-aligned 15-min telemetry (IST :00/:15/:30/:45).       */
    /* Falls back to 15-min interval if GPS time has not yet synced.       */
    /* Skipped while initial publish is still pending (avoids duplicate).  */
    /* ------------------------------------------------------------------ */
    if (!s_initial_publish_due && s_device_mqtt_connected && telemetry_due()) {
      publish_telemetry_now();
    }

    /* ------------------------------------------------------------------ */
    /* Auto relay — sunset → ON, sunrise → OFF                            */
    /* ------------------------------------------------------------------ */
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

    /* ------------------------------------------------------------------ */
    /* OTA — spawn flash task when job document has been received.         */
    /* Runs in a separate task so MQTT keepalive is never blocked.         */
    /* ------------------------------------------------------------------ */
    if (s_ota_pending) {
      s_ota_pending = false; /* clear before spawn — prevents re-entry */
      ESP_LOGI(TAG, "OTA: spawning flash task for job %s", s_ota_job_id);
      xTaskCreate(ota_flash_task, "ota", 8192, NULL, 5, NULL);
    }

    vTaskDelay(pdMS_TO_TICKS(1000));
  }
}
