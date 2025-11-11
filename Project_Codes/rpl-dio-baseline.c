#include "contiki.h"
#include "net/routing/routing.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "sys/log.h"

#define LOG_MODULE "DIO-Baseline"
#define LOG_LEVEL LOG_LEVEL_INFO

/* Statistics for baseline comparison */
static uint32_t dio_received = 0;
static uint32_t dio_processed = 0;

/*---------------------------------------------------------------------------*/
/* Process incoming DIO without any protection */
static void
process_dio_baseline(const uip_ipaddr_t *sender, 
                     const uint8_t *dio_data, uint16_t dio_len)
{
  dio_received++;
  
  LOG_INFO("DIO received from ");
  LOG_INFO_6ADDR(sender);
  LOG_INFO_(" (length: %u bytes)\n", dio_len);

  /* No replay detection - accept all DIOs */
  dio_processed++;
  
  /* Process the DIO message (would call RPL processing here) */
  /* In real implementation, forward to rpl_dio_input() */
}

/*---------------------------------------------------------------------------*/
/* Print baseline statistics */
static void
print_baseline_statistics(void)
{
  LOG_INFO("=== Baseline (Unprotected) Statistics ===\n");
  LOG_INFO("Total DIOs received: %lu\n", (unsigned long)dio_received);
  LOG_INFO("DIOs processed: %lu\n", (unsigned long)dio_processed);
  LOG_INFO("Protection: NONE (baseline)\n");
  LOG_INFO("=========================================\n");
}

/*---------------------------------------------------------------------------*/
PROCESS(dio_baseline_process, "DIO Baseline (Unprotected) Process");
AUTOSTART_PROCESSES(&dio_baseline_process);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(dio_baseline_process, ev, data)
{
  static struct etimer stat_timer;

  PROCESS_BEGIN();

  LOG_INFO("DIO Baseline (Unprotected) initialized\n");
  LOG_WARN("WARNING: No replay attack protection active!\n");

  /* Set up statistics timer */
  etimer_set(&stat_timer, CLOCK_SECOND * 60);

  while(1) {
    PROCESS_WAIT_EVENT();

    if(etimer_expired(&stat_timer)) {
      print_baseline_statistics();
      etimer_reset(&stat_timer);
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/