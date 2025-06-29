#include "users.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

static user users[MAX_USERS];
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
    if (!username || !password || user_count >= MAX_USERS) return false;
    
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].username, username) == 0) {
            return false; 
        }
    }
    
    strncpy(users[user_count].username, username, MAX_USERNAME_LEN - 1);
    strncpy(users[user_count].password, password, MAX_PASSWORD_LEN - 1);
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

void log_access(const char *username, const char *source_ip, const char *destination, uint64_t bytes) {
    if (!username || !source_ip || !destination) return;
    
    logs[log_index].timestamp = time(NULL);
    strncpy(logs[log_index].username, username, MAX_USERNAME_LEN - 1);
    strncpy(logs[log_index].source_ip, source_ip, 63);
    strncpy(logs[log_index].destination, destination, 255);
    logs[log_index].bytes = bytes;
    
    log_index = (log_index + 1) % 1000;
    if (log_count < 1000) log_count++;
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

void clear_logs(void) {
    log_count = 0;
    log_index = 0;
}

bool parse_config_line(const char *line) {
    if (!line) return false;
    
    while (isspace(*line)) line++;
    if (*line == '\0') return true; 
    
    char *equals = strchr(line, '=');
    if (!equals) return false;
    
    *equals = '\0';
    char *key = my_strdup(line);
    char *value = my_strdup(equals + 1);
    *equals = '='; 
    
    if (!key || !value) {
        free(key);
        free(value);
        return false;
    }
    
    bool result = false;
    
    if (strcmp(key, "add_user") == 0) {
        char *colon = strchr(value, ':');
        if (colon) {
            *colon = '\0';
            char *username = my_strdup(value);
            char *password = my_strdup(colon + 1);
            if (username && password) {
                result = add_user(username, password, ROLE_USER);
                free(username);
                free(password);
            }
        }
    } else if (strcmp(key, "remove_user") == 0) {
        result = remove_user(value);
    } else if (strcmp(key, "set_role") == 0) {
        char *colon = strchr(value, ':');
        if (colon) {
            *colon = '\0';
            char *username = my_strdup(value);
            char *role_str = my_strdup(colon + 1);
            if (username && role_str) {
                user_role role = (strcmp(role_str, "admin") == 0) ? ROLE_ADMIN : ROLE_USER;
                result = set_user_role(username, role);
                free(username);
                free(role_str);
            }
        }
    }
    
    free(key);
    free(value);
    return result;
}

bool apply_configuration(const char *config_data) {
    if (!config_data) return false;
    
    char *data_copy = my_strdup(config_data);
    if (!data_copy) return false;
    
    char *line = strtok(data_copy, "\n");
    bool success = true;
    
    while (line) {
        if (strlen(line) > 0 && line[0] != '#') {
            if (!parse_config_line(line)) {
                success = false;
                break;
            }
        }
        line = strtok(NULL, "\n");
    }
    
    free(data_copy);
    return success;
} 
