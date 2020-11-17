#ifndef _HEARTBEAT_H
#define _HEARTBEAT_H

typedef enum {
  ACTIVITY_MONITOR_INTERFACE,
  ACTIVITY_MONITOR_GPS,
  ACTIVITY_SCAN_CHANNEL,
  ACTIVITY_DISPLAY_MENU,
  ACTIVITY_JOURNAL_DB,
  ACTIVITY_LAST
} Activity_t;

inline Activity_t
operator++(Activity_t& a, int) {
  const Activity_t prev = a;
  const int i = static_cast<int>(a);
  if (a != ACTIVITY_LAST) {
    a = static_cast<Activity_t>(i + 1);
  }
  return prev;
}

void *monitorHeartbeat(void *context);

void reportActivity(const Activity_t activity);

#endif // _HEARTBEAT_H
