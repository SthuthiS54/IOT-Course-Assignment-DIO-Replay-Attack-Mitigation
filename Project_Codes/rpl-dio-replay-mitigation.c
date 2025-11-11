#include "contiki.h"
#include "net/routing/routing.h"
#include "net/routing/rpl-lite/rpl.h"
#include "net/routing/rpl-lite/rpl-dag.h"
#include "net/routing/rpl-lite/rpl-icmp6.h"
#include "net/ipv6/uip.h"
#include "net/ipv6/uip-ds6.h"
#include "sys/log.h"
#include "random.h"

#define LOG_MODULE "DIO-Mitigation"
#define LOG_LEVEL LOG_LEVEL_INFO

/* Replay detection parameters */
#define DIO_CACHE_SIZE 30
#define DIO_TIMESTAMP_WINDOW 300
#define MONITORING_INTERVAL (CLOCK_SECOND * 2)

/* Blacklist parameters */
#define BLACKLIST_SIZE 10
#define BLACKLIST_THRESHOLD 5  /* Number of violations before blacklisting */
#define BLACKLIST_DURATION 600 /* Time in seconds to keep node blacklisted */
#define AUTO_BLACKLIST_ENABLED 1 /* Auto-blacklist on threshold */

/* Cache entry */
typedef struct {
  uip_ipaddr_t sender;
  uint32_t timestamp;
  uint16_t rank;
  uint8_t version;
  uint8_t dio_count;
  uint8_t valid;
} dio_cache_entry_t;

static dio_cache_entry_t dio_cache[DIO_CACHE_SIZE];
static uint8_t cache_index = 0;

/* Blacklist entry */
typedef struct {
  uip_ipaddr_t addr;
  uint32_t blacklist_time;
  uint32_t violation_count;
  uint8_t permanent;
  uint8_t active;
  char reason[32];
} blacklist_entry_t;

static blacklist_entry_t blacklist[BLACKLIST_SIZE];
static uint8_t blacklist_count = 0;

/* Statistics */
static uint32_t dio_received = 0;
static uint32_t dio_accepted = 0;
static uint32_t dio_replayed = 0;
static uint32_t dio_suspicious = 0;
static uint32_t dio_blocked_blacklist = 0;
static uint32_t nodes_blacklisted = 0;

/* Node tracking for behavioral analysis */
typedef struct {
  uip_ipaddr_t sender;
  uint32_t last_seen;
  uint16_t last_rank;
  uint8_t last_version;
  uint8_t dio_count_per_sec;
  uint32_t last_count_reset;
  uint32_t violation_count;
} node_stats_t;

#define MAX_NODES 10
static node_stats_t node_stats[MAX_NODES];

/*---------------------------------------------------------------------------*/
static void
init_blacklist(void)
{
  memset(blacklist, 0, sizeof(blacklist));
  blacklist_count = 0;
  LOG_INFO("Blacklist initialized (size: %d, threshold: %d)\n", 
           BLACKLIST_SIZE, BLACKLIST_THRESHOLD);
}

/*---------------------------------------------------------------------------*/
static void
init_cache(void)
{
  memset(dio_cache, 0, sizeof(dio_cache));
  memset(node_stats, 0, sizeof(node_stats));
  init_blacklist();
  random_init(linkaddr_node_addr.u8[0]);
  LOG_INFO("Mitigation cache initialized (size: %d)\n", DIO_CACHE_SIZE);
}

/*---------------------------------------------------------------------------*/
static uint32_t
get_timestamp(void)
{
  return (uint32_t)clock_seconds();
}

/*---------------------------------------------------------------------------*/
/* Check if a node is blacklisted */
static int
is_blacklisted(const uip_ipaddr_t *addr)
{
  int i;
  uint32_t current_time = get_timestamp();
  
  for(i = 0; i < BLACKLIST_SIZE; i++) {
    if(blacklist[i].active && uip_ipaddr_cmp(&blacklist[i].addr, addr)) {
      /* Check if temporary blacklist has expired */
      if(!blacklist[i].permanent) {
        if(current_time - blacklist[i].blacklist_time > BLACKLIST_DURATION) {
          blacklist[i].active = 0;
          LOG_INFO("Blacklist expired for ");
          LOG_INFO_6ADDR(addr);
          LOG_INFO_("\n");
          return 0;
        }
      }
      return 1;
    }
  }
  return 0;
}

/*---------------------------------------------------------------------------*/
/* Add a node to the blacklist */
static int
add_to_blacklist(const uip_ipaddr_t *addr, const char *reason, int permanent)
{
  int i;
  int empty_slot = -1;
  uint32_t oldest_time = 0xFFFFFFFF;
  int oldest_slot = 0;
  
  /* Check if already blacklisted */
  for(i = 0; i < BLACKLIST_SIZE; i++) {
    if(blacklist[i].active && uip_ipaddr_cmp(&blacklist[i].addr, addr)) {
      /* Update existing entry */
      blacklist[i].violation_count++;
      blacklist[i].blacklist_time = get_timestamp();
      if(permanent) {
        blacklist[i].permanent = 1;
      }
      LOG_WARN("Updated blacklist entry for ");
      LOG_WARN_6ADDR(addr);
      LOG_WARN_(" (violations: %lu)\n", 
                (unsigned long)blacklist[i].violation_count);
      return 1;
    }
    
    /* Track empty and oldest slots */
    if(!blacklist[i].active && empty_slot == -1) {
      empty_slot = i;
    }
    if(blacklist[i].blacklist_time < oldest_time) {
      oldest_time = blacklist[i].blacklist_time;
      oldest_slot = i;
    }
  }
  
  /* Use empty slot or replace oldest */
  i = (empty_slot != -1) ? empty_slot : oldest_slot;
  
  uip_ipaddr_copy(&blacklist[i].addr, addr);
  blacklist[i].blacklist_time = get_timestamp();
  blacklist[i].violation_count = 1;
  blacklist[i].permanent = permanent;
  blacklist[i].active = 1;
  strncpy(blacklist[i].reason, reason, sizeof(blacklist[i].reason) - 1);
  
  blacklist_count++;
  nodes_blacklisted++;
  
  LOG_WARN("⛔ BLACKLISTED: ");
  LOG_WARN_6ADDR(addr);
  LOG_WARN_(" | Reason: %s | %s\n", 
            reason, permanent ? "PERMANENT" : "TEMPORARY");
  
  return 1;
}

/*---------------------------------------------------------------------------*/
/* Remove a node from the blacklist (manual unblock) */
static int
remove_from_blacklist(const uip_ipaddr_t *addr)
{
  int i;
  
  for(i = 0; i < BLACKLIST_SIZE; i++) {
    if(blacklist[i].active && uip_ipaddr_cmp(&blacklist[i].addr, addr)) {
      blacklist[i].active = 0;
      LOG_INFO("Removed from blacklist: ");
      LOG_INFO_6ADDR(addr);
      LOG_INFO_("\n");
      return 1;
    }
  }
  return 0;
}

/*---------------------------------------------------------------------------*/
/* Print blacklist table */
static void
print_blacklist(void)
{
  int i;
  int active_count = 0;
  uint32_t current_time = get_timestamp();
  
  LOG_INFO("\n╔════════════════════════════════════════════╗\n");
  LOG_INFO("║           BLACKLIST TABLE                  ║\n");
  LOG_INFO("╚════════════════════════════════════════════╝\n");
  
  for(i = 0; i < BLACKLIST_SIZE; i++) {
    if(blacklist[i].active) {
      active_count++;
      uint32_t age = current_time - blacklist[i].blacklist_time;
      
      LOG_INFO("%d. ", active_count);
      LOG_INFO_6ADDR(&blacklist[i].addr);
      LOG_INFO_("\n");
      LOG_INFO("   Reason: %s\n", blacklist[i].reason);
      LOG_INFO("   Type: %s\n", 
               blacklist[i].permanent ? "PERMANENT" : "TEMPORARY");
      LOG_INFO("   Violations: %lu\n", 
               (unsigned long)blacklist[i].violation_count);
      LOG_INFO("   Age: %lus", (unsigned long)age);
      
      if(!blacklist[i].permanent) {
        uint32_t remaining = BLACKLIST_DURATION - age;
        LOG_INFO_(" (expires in %lus)", (unsigned long)remaining);
      }
      LOG_INFO_("\n\n");
    }
  }
  
  if(active_count == 0) {
    LOG_INFO("   (empty)\n");
  }
  
  LOG_INFO("Active entries: %d/%d\n", active_count, BLACKLIST_SIZE);
  LOG_INFO("════════════════════════════════════════════\n");
}

/*---------------------------------------------------------------------------*/
/* Find or create node stats entry */
static node_stats_t *
get_node_stats(const uip_ipaddr_t *addr)
{
  int i;
  node_stats_t *oldest = &node_stats[0];
  
  for(i = 0; i < MAX_NODES; i++) {
    if(uip_ipaddr_cmp(&node_stats[i].sender, addr)) {
      return &node_stats[i];
    }
    if(node_stats[i].last_seen < oldest->last_seen) {
      oldest = &node_stats[i];
    }
  }
  
  memset(oldest, 0, sizeof(node_stats_t));
  uip_ipaddr_copy(&oldest->sender, addr);
  return oldest;
}

/*---------------------------------------------------------------------------*/
/* Detect replay based on behavioral analysis */
static int
detect_replay_behavior(const uip_ipaddr_t *sender, uint16_t rank, 
                       uint8_t version)
{
  uint32_t current_time = get_timestamp();
  node_stats_t *stats = get_node_stats(sender);
  int is_replay = 0;
  
  dio_received++;
  
  /* Check blacklist first */
  if(is_blacklisted(sender)) {
    dio_blocked_blacklist++;
    LOG_WARN("🚫 BLOCKED (blacklisted): ");
    LOG_WARN_6ADDR(sender);
    LOG_WARN_("\n");
    return 2; /* Special code for blacklisted */
  }
  
  /* Reset counter every second */
  if(stats->last_count_reset != current_time) {
    stats->dio_count_per_sec = 0;
    stats->last_count_reset = current_time;
  }
  
  stats->dio_count_per_sec++;
  
  /* Detect high-frequency DIOs (replay attack signature) */
  if(stats->dio_count_per_sec > 3) {
    LOG_WARN("HIGH FREQUENCY DIOs from ");
    LOG_WARN_6ADDR(sender);
    LOG_WARN_(" (%u DIOs/sec) - REPLAY ATTACK!\n", stats->dio_count_per_sec);
    is_replay = 1;
    dio_suspicious++;
    stats->violation_count++;
    
    /* Auto-blacklist if threshold reached */
    if(AUTO_BLACKLIST_ENABLED && 
       stats->violation_count >= BLACKLIST_THRESHOLD) {
      add_to_blacklist(sender, "High frequency attack", 0);
    }
  }
  
  /* Detect duplicate rank/version (replay signature) */
  if(stats->last_seen > 0) {
    uint32_t time_diff = current_time - stats->last_seen;
    
    if(stats->last_rank == rank && 
       stats->last_version == version &&
       time_diff < 5) {
      LOG_WARN("DUPLICATE DIO from ");
      LOG_WARN_6ADDR(sender);
      LOG_WARN_(" (rank: %u, ver: %u, %lus ago) - REPLAY!\n", 
               rank, version, (unsigned long)time_diff);
      is_replay = 1;
      stats->violation_count++;
      
      /* Auto-blacklist if threshold reached */
      if(AUTO_BLACKLIST_ENABLED && 
         stats->violation_count >= BLACKLIST_THRESHOLD) {
        add_to_blacklist(sender, "Duplicate replay", 0);
      }
    }
  }
  
  /* Update stats */
  stats->last_seen = current_time;
  stats->last_rank = rank;
  stats->last_version = version;
  
  if(is_replay) {
    dio_replayed++;
  } else {
    dio_accepted++;
  }
  
  return is_replay;
}

/*---------------------------------------------------------------------------*/
/* Monitor RPL neighbor table */
static void
monitor_rpl_neighbors(void)
{
  rpl_nbr_t *nbr;
  static uint32_t last_check = 0;
  uint32_t current_time = get_timestamp();
  
  if(curr_instance.dag.state < DAG_INITIALIZED) {
    return;
  }
  
  /* Only check if time has progressed */
  if(current_time == last_check) {
    return;
  }
  last_check = current_time;
  
  /* Iterate through all neighbors */
  nbr = nbr_table_head(rpl_neighbors);
  while(nbr != NULL) {
    uip_ipaddr_t *addr = rpl_neighbor_get_ipaddr(nbr);
    uint16_t rank = nbr->rank;
    
    if(addr != NULL && rank < 0xFFFF) {
      detect_replay_behavior(addr, rank, curr_instance.dag.version);
    }
    
    nbr = nbr_table_next(rpl_neighbors, nbr);
  }
}

/*---------------------------------------------------------------------------*/
/* Print detailed statistics */
static void
print_statistics(void)
{
  int i;
  int active_nodes = 0;
  int blacklisted_nodes = 0;
  uint32_t total_replays = dio_replayed + dio_suspicious;
  
  for(i = 0; i < MAX_NODES; i++) {
    if(node_stats[i].last_seen > 0) {
      active_nodes++;
    }
  }
  
  for(i = 0; i < BLACKLIST_SIZE; i++) {
    if(blacklist[i].active) {
      blacklisted_nodes++;
    }
  }
  
  LOG_INFO("╔════════════════════════════════════════════╗\n");
  LOG_INFO("║   DIO REPLAY MITIGATION STATISTICS         ║\n");
  LOG_INFO("╚════════════════════════════════════════════╝\n");
  LOG_INFO("DIOs monitored:      %lu\n", (unsigned long)dio_received);
  LOG_INFO("DIOs accepted:       %lu (%.1f%%)\n", 
           (unsigned long)dio_accepted,
           dio_received > 0 ? (dio_accepted * 100.0) / dio_received : 0);
  LOG_INFO("Replays detected:    %lu (%.1f%%)\n", 
           (unsigned long)total_replays,
           dio_received > 0 ? (total_replays * 100.0) / dio_received : 0);
  LOG_INFO("  - High frequency:  %lu\n", (unsigned long)dio_suspicious);
  LOG_INFO("  - Duplicates:      %lu\n", (unsigned long)dio_replayed);
  LOG_INFO("DIOs blocked (BL):   %lu\n", (unsigned long)dio_blocked_blacklist);
  LOG_INFO("\n--- Blacklist Status ---\n");
  LOG_INFO("Active blacklist:    %d/%d\n", blacklisted_nodes, BLACKLIST_SIZE);
  LOG_INFO("Total blacklisted:   %lu\n", (unsigned long)nodes_blacklisted);
  LOG_INFO("Active nodes:        %d/%d\n", active_nodes, MAX_NODES);
  LOG_INFO("Cache usage:         %d/%d\n", cache_index, DIO_CACHE_SIZE);
  
  if(dio_received > 0 && total_replays > 0) {
    LOG_INFO("\n⚠️  REPLAY ATTACK IN PROGRESS! ⚠️\n");
    LOG_INFO("Attack intensity:    %.1f%% of traffic\n",
             (total_replays * 100.0) / dio_received);
  }
  
  LOG_INFO("\n--- Per-Node Analysis ---\n");
  for(i = 0; i < MAX_NODES; i++) {
    if(node_stats[i].last_seen > 0) {
      LOG_INFO("Node ");
      LOG_INFO_6ADDR(&node_stats[i].sender);
      
      if(is_blacklisted(&node_stats[i].sender)) {
        LOG_INFO_(" [BLACKLISTED]");
      }
      
      LOG_INFO_(": rank=%u ver=%u rate=%u/s violations=%lu age=%lus\n",
               node_stats[i].last_rank,
               node_stats[i].last_version,
               node_stats[i].dio_count_per_sec,
               (unsigned long)node_stats[i].violation_count,
               (unsigned long)(get_timestamp() - node_stats[i].last_seen));
    }
  }
  LOG_INFO("════════════════════════════════════════════\n");
}

/*---------------------------------------------------------------------------*/
PROCESS(dio_mitigation_process, "DIO Replay Mitigation Monitor");
AUTOSTART_PROCESSES(&dio_mitigation_process);

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(dio_mitigation_process, ev, data)
{
  static struct etimer monitoring_timer;
  static struct etimer stats_timer;
  static struct etimer blacklist_timer;
  
  PROCESS_BEGIN();
  
  LOG_INFO("╔════════════════════════════════════════════╗\n");
  LOG_INFO("║  DIO REPLAY MITIGATION SYSTEM STARTED      ║\n");
  LOG_INFO("╠════════════════════════════════════════════╣\n");
  LOG_INFO("║ Cache size:     %3d entries                ║\n", DIO_CACHE_SIZE);
  LOG_INFO("║ Blacklist size: %3d entries                ║\n", BLACKLIST_SIZE);
  LOG_INFO("║ BL threshold:   %3d violations             ║\n", BLACKLIST_THRESHOLD);
  LOG_INFO("║ BL duration:    %3d seconds                ║\n", BLACKLIST_DURATION);
  LOG_INFO("║ Auto-blacklist: %s                      ║\n", 
           AUTO_BLACKLIST_ENABLED ? "ENABLED " : "DISABLED");
  LOG_INFO("║ Time window:    %3d seconds                ║\n", DIO_TIMESTAMP_WINDOW);
  LOG_INFO("║ Monitor rate:   %3d seconds                ║\n", 
           (int)(MONITORING_INTERVAL / CLOCK_SECOND));
  LOG_INFO("╚════════════════════════════════════════════╝\n");
  
  init_cache();
  
  etimer_set(&monitoring_timer, MONITORING_INTERVAL);
  etimer_set(&stats_timer, CLOCK_SECOND * 30);
  etimer_set(&blacklist_timer, CLOCK_SECOND * 60);
  
  while(1) {
    PROCESS_WAIT_EVENT();
    
    if(etimer_expired(&monitoring_timer)) {
      monitor_rpl_neighbors();
      etimer_reset(&monitoring_timer);
    }
    
    if(etimer_expired(&stats_timer)) {
      print_statistics();
      etimer_reset(&stats_timer);
    }
    
    if(etimer_expired(&blacklist_timer)) {
      print_blacklist();
      etimer_reset(&blacklist_timer);
    }
  }
  
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/