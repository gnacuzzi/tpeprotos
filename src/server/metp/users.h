#ifndef USERS_H
#define USERS_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <inttypes.h>

#define MAX_USERNAME_LEN 64
#define MAX_PASSWORD_LEN 64
#define MAX_USERS 100

typedef enum {
    ROLE_USER,
    ROLE_ADMIN
} user_role;

typedef struct {
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];
    user_role role;
    bool is_active;
} user;

typedef struct {
    time_t timestamp;
    char username[MAX_USERNAME_LEN];
    char source_ip[64];
    char destination[256];
    uint64_t bytes;
} access_log;

bool init_users(void);
bool verify_user(const char *username, const char *password);
user_role get_user_role(const char *username);
bool add_user(const char *username, const char *password, user_role role);
bool remove_user(const char *username);
bool set_user_role(const char *username, user_role role);
bool can_user_execute_command(const char *username, const char *command);

void log_access(const char *username, const char *source_ip, const char *destination, uint64_t bytes);
const char *get_logs(void);
void clear_logs(void);


user_role user_role_from_string(const char *role_str);

#endif 
