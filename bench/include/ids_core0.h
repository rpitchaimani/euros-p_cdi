/* ids_core0.h -- core 0 IDS: ingestion, bounded queue, CPU-share-limited
 * processing, per-event and per-window logs.  See ids_core0.c. */
#ifndef IDS_CORE0_H
#define IDS_CORE0_H

void ids_init(void);
void ids_poll(void);

#endif
