#include "contiki.h"
#include "net/routing/routing.h"
#include "net/routing/rpl-lite/rpl.h"
#include "net/routing/rpl-lite/rpl-dag.h"
#include "net/ipv6/uip-ds6.h"
#include "net/ipv6/uip-ds6-nbr.h"
#include "net/packetbuf.h"
#include "sys/log.h"
#include "sys/energest.h"

#define LOG_MODULE "DIO-Evaluator"
#define LOG_LEVEL LOG_LEVEL_INFO

/* Enhanced evaluation metrics */
typedef struct {
  /* RPL Metrics */
  uint32_t rpl_neighbors;
  uint32_t parent_switches;
  uint32_t rank_changes;
  uint32_t dodag_version;
  uint16_t current_rank;
  uint16_t min_rank_seen;
  uint16_t max_rank_seen;
  
  /* Network Quality Metrics */
  uint32_t dio_received;
  uint32_t dis_sent;
  uint32_t dao_sent;
  uint32_t dao_ack_received;
  uint32_t packets_sent;
  uint32_t packets_received;
  uint32_t packets_dropped;
  
  /* Stability Metrics */
  uint32_t dodag_joins;
  uint32_t dodag_leaves;
  uint32_t total_uptime;
  uint32_t connected_time;
  uint32_t disconnected_time;
  
  /* Energy Metrics */
  uint32_t energy_cpu;
  uint32_t energy_lpm;
  uint32_t energy_tx;
  uint32_t energy_rx;
  
  /* Timing */
  uint32_t timestamp;
  uint32_t start_time;
} evaluation_metrics_t;

static evaluation_metrics_t metrics;
static evaluation_metrics_t prev_metrics;

/* Detailed tracking */
typedef struct {
  uip_ipaddr_t addr;
  uint16_t rank;
  uint32_t first_seen;
  uint32_t last_seen;
  uint32_t dio_count;
  uint8_t is_parent;
  uint8_t was_parent;
} neighbor_info_t;

#define MAX_TRACKED_NEIGHBORS 10
static neighbor_info_t tracked_neighbors[MAX_TRACKED_NEIGHBORS];

/* Track previous values */
static uint16_t last_rank = 0xFFFF;
static uip_ipaddr_t last_parent;
static uint8_t last_version = 0;
static uint8_t first_parent = 1;
static uint8_t was_in_dodag = 0;
static uint32_t last_join_time = 0;
static uint32_t last_leave_time = 0;

/* Performance tracking */
typedef struct {
  uint32_t min_value;
  uint32_t max_value;
  uint32_t avg_value;
  uint32_t sample_count;
} performance_stat_t;

static performance_stat_t rank_stability;
static performance_stat_t neighbor_stability;
static performance_stat_t energy_per_second;

/*---------------------------------------------------------------------------*/
static void
init_metrics(void)
{
  memset(&metrics, 0, sizeof(evaluation_metrics_t));
  memset(&prev_metrics, 0, sizeof(evaluation_metrics_t));
  memset(&last_parent, 0, sizeof(uip_ipaddr_t));
  memset(&tracked_neighbors, 0, sizeof(tracked_neighbors));
  memset(&rank_stability, 0, sizeof(performance_stat_t));
  memset(&neighbor_stability, 0, sizeof(performance_stat_t));
  memset(&energy_per_second, 0, sizeof(performance_stat_t));
  
  first_parent = 1;
  was_in_dodag = 0;
  metrics.min_rank_seen = 0xFFFF;
  metrics.max_rank_seen = 0;
  metrics.start_time = (uint32_t)clock_seconds();
  
  rank_stability.min_value = 0xFFFFFFFF;
  neighbor_stability.min_value = 0xFFFFFFFF;
  energy_per_second.min_value = 0xFFFFFFFF;
  
  LOG_INFO("╔════════════════════════════════════════════╗\n");
  LOG_INFO("║    Enhanced Evaluation System Started      ║\n");
  LOG_INFO("╚════════════════════════════════════════════╝\n");
}

/*---------------------------------------------------------------------------*/
static void
update_performance_stat(performance_stat_t *stat, uint32_t value)
{
  if(value < stat->min_value) stat->min_value = value;
  if(value > stat->max_value) stat->max_value = value;
  
  stat->avg_value = ((stat->avg_value * stat->sample_count) + value) / 
                    (stat->sample_count + 1);
  stat->sample_count++;
}

/*---------------------------------------------------------------------------*/
static neighbor_info_t *
find_or_create_neighbor(const uip_ipaddr_t *addr)
{
  int i;
  neighbor_info_t *oldest = &tracked_neighbors[0];
  uint32_t oldest_time = 0xFFFFFFFF;
  
  /* Find existing */
  for(i = 0; i < MAX_TRACKED_NEIGHBORS; i++) {
    if(tracked_neighbors[i].last_seen > 0 && 
       uip_ipaddr_cmp(&tracked_neighbors[i].addr, addr)) {
      return &tracked_neighbors[i];
    }
    if(tracked_neighbors[i].last_seen < oldest_time) {
      oldest_time = tracked_neighbors[i].last_seen;
      oldest = &tracked_neighbors[i];
    }
  }
  
  /* Create new */
  memset(oldest, 0, sizeof(neighbor_info_t));
  uip_ipaddr_copy(&oldest->addr, addr);
  oldest->first_seen = (uint32_t)clock_seconds();
  return oldest;
}

/*---------------------------------------------------------------------------*/
static void
update_energy_metrics(void)
{
  uint32_t prev_total = prev_metrics.energy_cpu + prev_metrics.energy_lpm + 
                        prev_metrics.energy_tx + prev_metrics.energy_rx;
  
  energest_flush();
  metrics.energy_cpu = (uint32_t)energest_type_time(ENERGEST_TYPE_CPU);
  metrics.energy_lpm = (uint32_t)energest_type_time(ENERGEST_TYPE_LPM);
  metrics.energy_tx = (uint32_t)energest_type_time(ENERGEST_TYPE_TRANSMIT);
  metrics.energy_rx = (uint32_t)energest_type_time(ENERGEST_TYPE_LISTEN);
  metrics.timestamp = (uint32_t)clock_seconds();
  
  /* Calculate energy per second */
  if(prev_metrics.timestamp > 0) {
    uint32_t time_delta = metrics.timestamp - prev_metrics.timestamp;
    uint32_t total_energy = metrics.energy_cpu + metrics.energy_lpm + 
                           metrics.energy_tx + metrics.energy_rx;
    if(time_delta > 0) {
      uint32_t energy_rate = (total_energy - prev_total) / time_delta;
      update_performance_stat(&energy_per_second, energy_rate);
    }
  }
}

/*---------------------------------------------------------------------------*/
static void
update_rpl_metrics(void)
{
  rpl_nbr_t *nbr;
  int neighbor_count = 0;
  uint32_t current_time = (uint32_t)clock_seconds();
  
  /* Update total uptime */
  metrics.total_uptime = current_time - metrics.start_time;
  
  /* Check if we're part of a DODAG */
  uint8_t in_dodag = (curr_instance.dag.state >= DAG_INITIALIZED);
  
  if(in_dodag) {
    metrics.connected_time++;
    
    /* Track DODAG join */
    if(!was_in_dodag) {
      metrics.dodag_joins++;
      last_join_time = current_time;
      LOG_INFO("✓ JOINED DODAG (join #%lu)\n", 
               (unsigned long)metrics.dodag_joins);
    }
    
    /* Get current rank */
    metrics.current_rank = curr_instance.dag.rank;
    metrics.dodag_version = curr_instance.dag.version;
    
    /* Track rank statistics */
    if(metrics.current_rank < metrics.min_rank_seen) {
      metrics.min_rank_seen = metrics.current_rank;
    }
    if(metrics.current_rank > metrics.max_rank_seen) {
      metrics.max_rank_seen = metrics.current_rank;
    }
    update_performance_stat(&rank_stability, metrics.current_rank);
    
    /* Detect rank changes */
    if(last_rank != 0xFFFF && last_rank != metrics.current_rank) {
      metrics.rank_changes++;
      int32_t rank_delta = (int32_t)metrics.current_rank - (int32_t)last_rank;
      LOG_INFO("Rank change: %u -> %u (%s%ld)\n", 
               last_rank, metrics.current_rank,
               rank_delta > 0 ? "+" : "", (long)rank_delta);
    }
    last_rank = metrics.current_rank;
    
    /* Detect version changes */
    if(last_version != 0 && last_version != metrics.dodag_version) {
      LOG_INFO("⚡ DODAG version change: %u -> %u\n", 
               last_version, metrics.dodag_version);
    }
    last_version = metrics.dodag_version;
    
    /* Clear previous parent flags */
    for(int i = 0; i < MAX_TRACKED_NEIGHBORS; i++) {
      tracked_neighbors[i].is_parent = 0;
    }
    
    /* Update neighbors */
    nbr = nbr_table_head(rpl_neighbors);
    while(nbr != NULL) {
      neighbor_count++;
      uip_ipaddr_t *addr = rpl_neighbor_get_ipaddr(nbr);
      
      if(addr != NULL) {
        neighbor_info_t *info = find_or_create_neighbor(addr);
        info->rank = nbr->rank;
        info->last_seen = current_time;
        info->dio_count++;
      }
      
      nbr = nbr_table_next(rpl_neighbors, nbr);
    }
    
    metrics.rpl_neighbors = neighbor_count;
    update_performance_stat(&neighbor_stability, neighbor_count);
    
    /* Detect parent changes */
    uip_ipaddr_t *parent = rpl_neighbor_get_ipaddr(curr_instance.dag.preferred_parent);
    if(parent != NULL) {
      neighbor_info_t *parent_info = find_or_create_neighbor(parent);
      parent_info->is_parent = 1;
      
      if(!first_parent && !uip_ipaddr_cmp(&last_parent, parent)) {
        metrics.parent_switches++;
        LOG_INFO("🔄 Parent switch to ");
        LOG_INFO_6ADDR(parent);
        LOG_INFO_(" (switch #%lu)\n", 
                 (unsigned long)metrics.parent_switches);
        
        /* Mark old parent */
        for(int i = 0; i < MAX_TRACKED_NEIGHBORS; i++) {
          if(uip_ipaddr_cmp(&tracked_neighbors[i].addr, &last_parent)) {
            tracked_neighbors[i].was_parent = 1;
          }
        }
      }
      uip_ipaddr_copy(&last_parent, parent);
      first_parent = 0;
    }
    
  } else {
    metrics.disconnected_time++;
    metrics.current_rank = 0xFFFF;
    metrics.rpl_neighbors = 0;
    
    /* Track DODAG leave */
    if(was_in_dodag) {
      metrics.dodag_leaves++;
      last_leave_time = current_time;
      uint32_t connected_duration = last_leave_time - last_join_time;
      LOG_WARN("✗ LEFT DODAG (leave #%lu, was connected %lus)\n", 
               (unsigned long)metrics.dodag_leaves,
               (unsigned long)connected_duration);
    }
  }
  
  was_in_dodag = in_dodag;
}

/*---------------------------------------------------------------------------*/
static float
calculate_stability_score(void)
{
  /* Stability score based on:
   * - Low parent switches (40%)
   * - Low rank changes (30%)
   * - High connection time (30%)
   */
  float parent_score = 0.0;
  float rank_score = 0.0;
  float connection_score = 0.0;
  
  if(metrics.total_uptime > 0) {
    /* Parent stability (fewer switches = better) */
    if(metrics.parent_switches == 0) {
      parent_score = 100.0;
    } else {
      parent_score = 100.0 / (1.0 + metrics.parent_switches * 0.5);
    }
    
    /* Rank stability (fewer changes = better) */
    if(metrics.rank_changes == 0) {
      rank_score = 100.0;
    } else {
      rank_score = 100.0 / (1.0 + metrics.rank_changes * 0.3);
    }
    
    /* Connection time (more = better) */
    connection_score = (metrics.connected_time * 100.0) / metrics.total_uptime;
  }
  
  return (parent_score * 0.4 + rank_score * 0.3 + connection_score * 0.3);
}

/*---------------------------------------------------------------------------*/
static void
print_detailed_report(void)
{
  update_energy_metrics();
  update_rpl_metrics();
  
  uint32_t total_energy = metrics.energy_cpu + metrics.energy_lpm + 
                          metrics.energy_tx + metrics.energy_rx;
  
  float stability_score = calculate_stability_score();
  
  LOG_INFO("\n");
  LOG_INFO("╔════════════════════════════════════════════════════════════╗\n");
  LOG_INFO("║           RPL NETWORK EVALUATION REPORT                    ║\n");
  LOG_INFO("╠════════════════════════════════════════════════════════════╣\n");
  LOG_INFO("║ Time: %lu s | Uptime: %lu s | Score: %.1f/100         ║\n",
           (unsigned long)metrics.timestamp,
           (unsigned long)metrics.total_uptime,
           stability_score);
  LOG_INFO("╚════════════════════════════════════════════════════════════╝\n");
  
  /* RPL Status */
  LOG_INFO("\n┌─── RPL NETWORK STATUS ───────────────────────────────────┐\n");
  if(curr_instance.dag.state >= DAG_INITIALIZED) {
    LOG_INFO("│ Status:          ✓ JOINED DODAG                          │\n");
    LOG_INFO("│ Current Rank:    %-6u                                   │\n", 
             metrics.current_rank);
    LOG_INFO("│ Rank Range:      %u - %u                                 │\n",
             metrics.min_rank_seen, metrics.max_rank_seen);
    LOG_INFO("│ DODAG Version:   %-3u                                    │\n", 
             metrics.dodag_version);
    LOG_INFO("│ Neighbors:       %-3lu                                    │\n", 
             (unsigned long)metrics.rpl_neighbors);
    
    uip_ipaddr_t *parent = rpl_neighbor_get_ipaddr(curr_instance.dag.preferred_parent);
    if(parent != NULL) {
      LOG_INFO("│ Preferred Parent: ");
      LOG_INFO_6ADDR(parent);
      LOG_INFO_("                │\n");
    }
  } else {
    LOG_INFO("│ Status:          ✗ NOT IN DODAG                          │\n");
  }
  LOG_INFO("└──────────────────────────────────────────────────────────┘\n");
  
  /* Network Dynamics */
  LOG_INFO("\n┌─── NETWORK DYNAMICS ─────────────────────────────────────┐\n");
  LOG_INFO("│ Parent Switches:    %-6lu                               │\n", 
           (unsigned long)metrics.parent_switches);
  LOG_INFO("│ Rank Changes:       %-6lu                               │\n", 
           (unsigned long)metrics.rank_changes);
  LOG_INFO("│ DODAG Joins:        %-6lu                               │\n", 
           (unsigned long)metrics.dodag_joins);
  LOG_INFO("│ DODAG Leaves:       %-6lu                               │\n", 
           (unsigned long)metrics.dodag_leaves);
  LOG_INFO("└──────────────────────────────────────────────────────────┘\n");
  
  /* Connection Statistics */
  LOG_INFO("\n┌─── CONNECTION STATISTICS ────────────────────────────────┐\n");
  if(metrics.total_uptime > 0) {
    float uptime_pct = (metrics.connected_time * 100.0) / metrics.total_uptime;
    float downtime_pct = (metrics.disconnected_time * 100.0) / metrics.total_uptime;
    
    LOG_INFO("│ Connected Time:     %lu s (%.1f%%)                      │\n",
             (unsigned long)metrics.connected_time, uptime_pct);
    LOG_INFO("│ Disconnected Time:  %lu s (%.1f%%)                      │\n",
             (unsigned long)metrics.disconnected_time, downtime_pct);
    
    if(metrics.dodag_joins > 0) {
      uint32_t avg_session = metrics.connected_time / metrics.dodag_joins;
      LOG_INFO("│ Avg Session:        %lu s                               │\n",
               (unsigned long)avg_session);
    }
  }
  LOG_INFO("└──────────────────────────────────────────────────────────┘\n");
  
  /* Energy Consumption */
  LOG_INFO("\n┌─── ENERGY CONSUMPTION (ticks) ───────────────────────────┐\n");
  LOG_INFO("│ CPU:       %10lu (%.1f%%)                             │\n", 
           (unsigned long)metrics.energy_cpu,
           total_energy > 0 ? (metrics.energy_cpu * 100.0) / total_energy : 0);
  LOG_INFO("│ LPM:       %10lu (%.1f%%)                             │\n", 
           (unsigned long)metrics.energy_lpm,
           total_energy > 0 ? (metrics.energy_lpm * 100.0) / total_energy : 0);
  LOG_INFO("│ TX:        %10lu (%.1f%%)                             │\n", 
           (unsigned long)metrics.energy_tx,
           total_energy > 0 ? (metrics.energy_tx * 100.0) / total_energy : 0);
  LOG_INFO("│ RX:        %10lu (%.1f%%)                             │\n", 
           (unsigned long)metrics.energy_rx,
           total_energy > 0 ? (metrics.energy_rx * 100.0) / total_energy : 0);
  LOG_INFO("│ ────────────────────────────────────────────────────────│\n");
  LOG_INFO("│ Total:     %10lu                                      │\n", 
           (unsigned long)total_energy);
  
  if(energy_per_second.sample_count > 0) {
    LOG_INFO("│ Rate:      %lu ticks/s (min: %lu, max: %lu)            │\n",
             (unsigned long)energy_per_second.avg_value,
             (unsigned long)energy_per_second.min_value,
             (unsigned long)energy_per_second.max_value);
  }
  LOG_INFO("└──────────────────────────────────────────────────────────┘\n");
  
  /* Performance Statistics */
  LOG_INFO("\n┌─── PERFORMANCE STATISTICS ───────────────────────────────┐\n");
  if(rank_stability.sample_count > 0) {
    LOG_INFO("│ Rank Stats:   avg=%u, min=%u, max=%u (%lu samples)     │\n",
             rank_stability.avg_value,
             rank_stability.min_value,
             rank_stability.max_value,
             (unsigned long)rank_stability.sample_count);
  }
  if(neighbor_stability.sample_count > 0) {
    LOG_INFO("│ Neighbor Stats: avg=%u, min=%u, max=%u (%lu samples)   │\n",
             neighbor_stability.avg_value,
             neighbor_stability.min_value,
             neighbor_stability.max_value,
             (unsigned long)neighbor_stability.sample_count);
  }
  LOG_INFO("└──────────────────────────────────────────────────────────┘\n");
  
  /* Delta Metrics */
  if(prev_metrics.timestamp > 0) {
    uint32_t time_delta = metrics.timestamp - prev_metrics.timestamp;
    uint32_t energy_delta = total_energy - 
      (prev_metrics.energy_cpu + prev_metrics.energy_lpm + 
       prev_metrics.energy_tx + prev_metrics.energy_rx);
    
    LOG_INFO("\n┌─── DELTA METRICS (last %lu seconds) ──────────────────────┐\n",
             (unsigned long)time_delta);
    LOG_INFO("│ Energy:         %lu ticks                               │\n", 
             (unsigned long)energy_delta);
    LOG_INFO("│ Parent Switches: %lu                                    │\n",
             (unsigned long)(metrics.parent_switches - prev_metrics.parent_switches));
    LOG_INFO("│ Rank Changes:   %lu                                     │\n",
             (unsigned long)(metrics.rank_changes - prev_metrics.rank_changes));
    LOG_INFO("│ DODAG Joins:    %lu                                     │\n",
             (unsigned long)(metrics.dodag_joins - prev_metrics.dodag_joins));
    LOG_INFO("└──────────────────────────────────────────────────────────┘\n");
  }
  
  /* CSV Output */
  LOG_INFO("\n[CSV] %lu,%u,%u,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%.1f\n",
           (unsigned long)metrics.timestamp,
           metrics.current_rank,
           metrics.dodag_version,
           (unsigned long)metrics.rpl_neighbors,
           (unsigned long)metrics.parent_switches,
           (unsigned long)metrics.rank_changes,
           (unsigned long)metrics.energy_cpu,
           (unsigned long)metrics.energy_lpm,
           (unsigned long)metrics.energy_tx,
           (unsigned long)metrics.energy_rx,
           (unsigned long)total_energy,
           (unsigned long)metrics.connected_time,
           stability_score);
  
  memcpy(&prev_metrics, &metrics, sizeof(evaluation_metrics_t));
}

/*---------------------------------------------------------------------------*/
static void
print_neighbor_details(void)
{
  int i, active_count = 0;
  uint32_t current_time = (uint32_t)clock_seconds();
  
  if(curr_instance.dag.state < DAG_INITIALIZED) {
    LOG_INFO("Not in DODAG - no neighbor information available\n");
    return;
  }
  
  LOG_INFO("\n┌─── NEIGHBOR DETAILS ─────────────────────────────────────┐\n");
  
  for(i = 0; i < MAX_TRACKED_NEIGHBORS; i++) {
    if(tracked_neighbors[i].last_seen > 0) {
      uint32_t age = current_time - tracked_neighbors[i].last_seen;
      uint32_t duration = current_time - tracked_neighbors[i].first_seen;
      
      if(age < 300) { /* Active within last 5 minutes */
        active_count++;
        
        LOG_INFO("│ %d. ", active_count);
        LOG_INFO_6ADDR(&tracked_neighbors[i].addr);
        LOG_INFO_("\n");
        LOG_INFO("│    Rank: %u | DIOs: %lu | Age: %lus | Duration: %lus\n",
                 tracked_neighbors[i].rank,
                 (unsigned long)tracked_neighbors[i].dio_count,
                 (unsigned long)age,
                 (unsigned long)duration);
        
        if(tracked_neighbors[i].is_parent) {
          LOG_INFO("│    [CURRENT PARENT]\n");
        } else if(tracked_neighbors[i].was_parent) {
          LOG_INFO("│    [FORMER PARENT]\n");
        }
        LOG_INFO("│\n");
      }
    }
  }
  
  if(active_count == 0) {
    LOG_INFO("│ No active neighbors                                      │\n");
  }
  
  LOG_INFO("└──────────────────────────────────────────────────────────┘\n");
}

/*---------------------------------------------------------------------------*/
static void
print_summary_stats(void)
{
  LOG_INFO("\n");
  LOG_INFO("╔════════════════════════════════════════════════════════════╗\n");
  LOG_INFO("║                  SUMMARY STATISTICS                        ║\n");
  LOG_INFO("╚════════════════════════════════════════════════════════════╝\n");
  LOG_INFO("CSV Header: time,rank,ver,nbr,parent_sw,rank_ch,cpu,lpm,tx,rx,total,conn_time,score\n");
  LOG_INFO("\n");
  LOG_INFO("Total Runtime:       %lu seconds\n", 
           (unsigned long)metrics.total_uptime);
  LOG_INFO("Stability Score:     %.1f / 100\n", calculate_stability_score());
  LOG_INFO("Network Efficiency:  %lu rank changes, %lu parent switches\n",
           (unsigned long)metrics.rank_changes,
           (unsigned long)metrics.parent_switches);
  LOG_INFO("Connection Quality:  %.1f%% uptime\n",
           metrics.total_uptime > 0 ? 
           (metrics.connected_time * 100.0) / metrics.total_uptime : 0);
  LOG_INFO("════════════════════════════════════════════════════════════\n");
}

/*---------------------------------------------------------------------------*/
PROCESS(dio_evaluator_process, "Enhanced RPL Network Evaluator");
AUTOSTART_PROCESSES(&dio_evaluator_process);

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(dio_evaluator_process, ev, data)
{
  static struct etimer report_timer;
  static struct etimer update_timer;
  static struct etimer neighbor_timer;
  
  PROCESS_BEGIN();
  
  init_metrics();
  energest_init();
  
  LOG_INFO("Detailed reports every 2 minutes\n");
  LOG_INFO("Quick updates every 30 seconds\n");
  LOG_INFO("Neighbor analysis every 5 minutes\n");
  
  etimer_set(&report_timer, CLOCK_SECOND * 120);   /* 2 min - detailed report */
  etimer_set(&update_timer, CLOCK_SECOND * 30);    /* 30 sec - quick update */
  etimer_set(&neighbor_timer, CLOCK_SECOND * 300); /* 5 min - neighbor details */
  
  while(1) {
    PROCESS_WAIT_EVENT();
    
    if(etimer_expired(&report_timer)) {
      print_detailed_report();
      etimer_reset(&report_timer);
    }
    
    if(etimer_expired(&update_timer)) {
      update_rpl_metrics();
      etimer_reset(&update_timer);
    }
    
    if(etimer_expired(&neighbor_timer)) {
      print_neighbor_details();
      print_summary_stats();
      etimer_reset(&neighbor_timer);
    }
  }
  
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/