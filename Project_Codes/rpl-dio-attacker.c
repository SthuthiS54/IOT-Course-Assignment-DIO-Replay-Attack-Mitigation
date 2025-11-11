#include "contiki.h"
#include "net/routing/routing.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "sys/log.h"
#include "random.h"
#include "node-id.h"
#include "sys/clock.h"

#define LOG_MODULE "DIO-Attacker"
#define LOG_LEVEL LOG_LEVEL_INFO

/* Attack parameters */
#define ATTACK_INTERVAL (CLOCK_SECOND * 10) /* Replay every 10 seconds */
#define REPLAY_COUNT 5 /* Number of times to replay each captured DIO */

/* Captured DIO storage */
#define MAX_CAPTURED_DIOS 10

typedef struct {
  uint8_t dio_data[128];
  uint16_t dio_len;
  uip_ipaddr_t target_addr;
  uint32_t capture_time;
  uint8_t valid;
} captured_dio_t;

static captured_dio_t captured_dios[MAX_CAPTURED_DIOS];
static uint8_t capture_index = 0;

/* Attack statistics */
static uint32_t dios_captured = 0;
static uint32_t dios_replayed = 0;

/*---------------------------------------------------------------------------*/
/* Capture a DIO message for replay */
static void
capture_dio(const uint8_t *dio_data, uint16_t dio_len, 
            const uip_ipaddr_t *target)
{
  if(dio_len > 128) {
    LOG_WARN("DIO too large to capture\n");
    return;
  }

  memcpy(captured_dios[capture_index].dio_data, dio_data, dio_len);
  captured_dios[capture_index].dio_len = dio_len;
  uip_ipaddr_copy(&captured_dios[capture_index].target_addr, target);
  captured_dios[capture_index].capture_time = clock_seconds();
  captured_dios[capture_index].valid = 1;

  dios_captured++;
  
  LOG_INFO("Captured DIO #%lu (length: %u bytes)\n", 
           (unsigned long)dios_captured, dio_len);

  capture_index = (capture_index + 1) % MAX_CAPTURED_DIOS;
}

/*---------------------------------------------------------------------------*/
/* Replay captured DIO messages */
static void
replay_captured_dios(void)
{
  int i, j;
  
  for(i = 0; i < MAX_CAPTURED_DIOS; i++) {
    if(captured_dios[i].valid) {
      /* Replay each captured DIO multiple times */
      for(j = 0; j < REPLAY_COUNT; j++) {
        dios_replayed++;
        
        LOG_WARN("REPLAYING DIO #%d (attempt %d/%d) to ", 
                 i, j+1, REPLAY_COUNT);
        LOG_WARN_6ADDR(&captured_dios[i].target_addr);
        LOG_WARN_("\n");

        /* Simulate sending the replayed DIO */
        /* In real implementation, this would use uip_udp_packet_send() */
        
        /* Small delay between replays */
        for(volatile uint32_t _d = 0; _d < 20000; _d++) { }
      }
    }
  }
  
  LOG_INFO("Replay attack completed: %lu DIOs replayed\n", 
           (unsigned long)dios_replayed);
}

/*---------------------------------------------------------------------------*/
/* Simulate capturing a DIO from network traffic */
static void
simulate_dio_capture(void)
{
  uint8_t fake_dio[128];
  uip_ipaddr_t target;
  uint16_t dio_len = 64;

  /* Create fake DIO data */
  memset(fake_dio, 0xAA, dio_len);
  
  /* Set fake target address */
  uip_ip6addr(&target, 0xfe80, 0, 0, 0, 0x0212, 0x7400, 0x1234, 0x5678);

  /* Capture the DIO */
  capture_dio(fake_dio, dio_len, &target);
}

/*---------------------------------------------------------------------------*/
/* Print attack statistics */
static void
print_attack_statistics(void)
{
  LOG_INFO("=== DIO Replay Attack Statistics ===\n");
  LOG_INFO("DIOs captured: %lu\n", (unsigned long)dios_captured);
  LOG_INFO("DIOs replayed: %lu\n", (unsigned long)dios_replayed);
  LOG_INFO("Active captures in buffer: ");
  
  int active_count = 0;
  for(int i = 0; i < MAX_CAPTURED_DIOS; i++) {
    if(captured_dios[i].valid) active_count++;
  }
  LOG_INFO("%d/%d\n", active_count, MAX_CAPTURED_DIOS);
  LOG_INFO("====================================\n");
}

/*---------------------------------------------------------------------------*/
PROCESS(dio_attacker_process, "DIO Replay Attacker Process");
AUTOSTART_PROCESSES(&dio_attacker_process);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(dio_attacker_process, ev, data)
{
  static struct etimer attack_timer;
  static struct etimer capture_timer;
  static struct etimer stat_timer;

  PROCESS_BEGIN();

  LOG_WARN("DIO Replay Attacker initialized - WARNING: For research only!\n");
  
  /* Initialize random number generator */
  random_init(node_id + 1000);

  /* Set up timers */
  etimer_set(&capture_timer, CLOCK_SECOND * 15); /* Capture every 15s */
  etimer_set(&attack_timer, ATTACK_INTERVAL);
  etimer_set(&stat_timer, CLOCK_SECOND * 60);

  while(1) {
    PROCESS_WAIT_EVENT();

    if(etimer_expired(&capture_timer)) {
      /* Simulate capturing DIOs from network */
      simulate_dio_capture();
      etimer_reset(&capture_timer);
    }

    if(etimer_expired(&attack_timer)) {
      /* Launch replay attack */
      LOG_WARN("Launching replay attack...\n");
      replay_captured_dios();
      etimer_reset(&attack_timer);
    }

    if(etimer_expired(&stat_timer)) {
      print_attack_statistics();
      etimer_reset(&stat_timer);
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/