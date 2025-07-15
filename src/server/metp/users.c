#include "users.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

static struct user users[MAX_USERS];
static int user_count = 0;
static access_log logs[1000]; 
static int log_count = 0;
static int log_index = 0;

static char * my_strdup(const char *s) {
    size_t len = strlen(s) + 1;
    char *p = malloc(len);
    if (p) memcpy(p, s, len);
    return p;
}

bool init_users(void) {
    user_count = 0;
    log_count = 0;
    log_index = 0;
    
    const char *superuser = getenv("PROXY_CTRL_SUPERUSER");
    if (superuser) {
        char *colon = strchr(superuser, ':');
        if (colon) {
            *colon = '\0';
            char *username = my_strdup(superuser);
            char *password = my_strdup(colon + 1);
            if (username && password) {
                add_user(username, password, ROLE_ADMIN);
                free(username);
                free(password);
            }
            *colon = ':'; 
        }
    }
    return true;
}

bool verify_user(const char *username, const char *password) {
    if (!username || !password) return false;
    
    for (int i = 0; i < user_count; i++) {
        if (users[i].is_active && 
            strcmp(users[i].username, username) == 0 &&
            strcmp(users[i].password, password) == 0) {
            return true;
        }
    }
    return false;
}

user_role get_user_role(const char *username) {
    if (!username) return ROLE_USER;
    
    for (int i = 0; i < user_count; i++) {
        if (users[i].is_active && strcmp(users[i].username, username) == 0) {
            return users[i].role;
        }
    }
    return ROLE_USER;
}

bool add_user(const char *username, const char *password, user_role role) {
    if (!username || !password) return false;

    for (int i = 0; i < user_count; i++) {
        if (users[i].is_active && strcmp(users[i].username, username) == 0) {
            return false; 
        }
    }

    for (int i = 0; i < user_count; i++) {
        if (!users[i].is_active) {
            users[i].username = my_strdup(username);
            users[i].password = my_strdup(password);
            users[i].role = role;
            users[i].is_active = true;
            return true;
        }
    }

    if (user_count >= MAX_USERS) return false;

    users[user_count].username = my_strdup(username);
    users[user_count].password = my_strdup(password);
    users[user_count].role = role;
    users[user_count].is_active = true;
    user_count++;
    return true;
}

bool remove_user(const char *username) {
    if (!username) return false;
    
    for (int i = 0; i < user_count; i++) {
        if (users[i].is_active && strcmp(users[i].username, username) == 0) {
            users[i].is_active = false;
            free(users[i].username);
            free(users[i].password);
            users[i].username = NULL;
            return true;
        }
    }
    return false;
}

bool set_user_role(const char *username, user_role role) {
    if (!username) return false;
    
    for (int i = 0; i < user_count; i++) {
        if (users[i].is_active && strcmp(users[i].username, username) == 0) {
            users[i].role = role;
            return true;
        }
    }
    return false;
}

bool can_user_execute_command(const char *username, const char *command) {
    if (!username || !command) return false;
    
    user_role role = get_user_role(username);
    
    if (role == ROLE_ADMIN) {
        return true; 
    }
    
    if (strcmp(command, "GET_METRICS") == 0) {
        return true;
    }
    
    return false;
}

int log_access(const char *username, const char *source_ip, const char *destination, uint64_t bytes) {
    if (!username || !source_ip || !destination) return -1;

    logs[log_index].timestamp = time(NULL);
    strncpy(logs[log_index].username, username, MAX_USERNAME_LEN - 1);
    strncpy(logs[log_index].source_ip, source_ip, 63);
    strncpy(logs[log_index].destination, destination, 255);
    logs[log_index].bytes = bytes;

    int index = log_index;
    log_index = (log_index + 1) % 1000;
    if (log_count < 1000) log_count++;

    return index;
}


const char *get_logs(void) {
    static char log_buffer[32768]; 
    int pos = 0;
    
    for (int i = 0; i < log_count; i++) {
        int idx = (log_index - log_count + i + 1000) % 1000;
        struct tm *tm_info = gmtime(&logs[idx].timestamp);
        
        int written = snprintf(log_buffer + pos, sizeof(log_buffer) - pos,
            "[%04d-%02d-%02dT%02d:%02d:%02dZ] %s %s %s %" PRIu64 "\n",
            tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
            tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec,
            logs[idx].username, logs[idx].source_ip, logs[idx].destination, logs[idx].bytes);
        
        if (written > 0 && pos + written < sizeof(log_buffer)) {
            pos += written;
        } else {
            break;
        }
    }
    
    return log_buffer;
}

void update_bytes_transferred(int log_id, uint64_t bytes) {
    if (log_id < 0) return;
    logs[log_id].bytes += bytes;
}


const char *get_users(void) {
    static char buf[4096];
    int pos = 0;
    buf[0] = '\0';

    for (int i = 0; i < user_count; i++) {
        if (!users[i].is_active) continue;
        const char *role_str = (users[i].role == ROLE_ADMIN) ? "admin" : "user";
        int written = snprintf(buf + pos, sizeof(buf) - pos,
                               "%s %s\n",
                               users[i].username,
                               role_str);
        if (written < 0 || written >= (int)(sizeof(buf) - pos))
            break;
        pos += written;
    }
    return buf;
}

void clear_logs(void) {
    log_count = 0;
    log_index = 0;
}


user_role user_role_from_string(const char *role_str) {
    if (strcmp(role_str, "admin") == 0) return ROLE_ADMIN;
    return ROLE_USER;
} 

int compare_users(const char * one, const char * two) {
    return strcmp(one, two) == 0;
}

struct user * authenticate_user(credentials * credentials) {
    for (int i = 0; i < user_count; i++) {
        if (compare_users(users[i].username,
                          (char *)credentials->usernme) &&
            compare_users(users[i].password,
                          (char *)credentials->passwd)) {
            return &users[i];
        }
    }
    static struct user empty_user = { .username = "", .password = "", .role = ROLE_USER, .is_active = false };
    return NULL;
}

void free_users() {
    for (int i = 0; i < user_count; i++) {
        free(users[i].username);
        free(users[i].password);
        users[i].username = NULL;
        users[i].password = NULL;
        users[i].is_active = false;
    }
    user_count = 0;
}
