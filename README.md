# TPE Protos - SOCKS5 Proxy con Protocolo METP
# Grupo 11

## Descripción

TPE Protos es un servidor proxy SOCKS5 de alto rendimiento con un protocolo de gestión y telemetría (METP) integrado. El proyecto implementa un proxy SOCKS5 completo con capacidades de monitoreo, gestión de usuarios y métricas en tiempo real.

## Arquitectura

### Componentes Principales

- **Servidor SOCKS5**: Proxy completo en puerto 1080
- **Protocolo METP**: Interfaz de gestión en puerto 8080
- **Sistema de Usuarios**: Autenticación y autorización con roles
- **Métricas**: Estadísticas en tiempo real de conexiones y transferencia
- **Logging**: Registro de acceso con timestamps

## Compilación y Estructura del Proyecto

### Requisitos

- `gcc` 
- `make`

### Compilar el proyecto

Desde la raíz del repositorio, ejecutar:

```bash
make all
```

Esto generará los ejecutables en la carpeta `bin/`:

- `bin/socks5d` — Servidor SOCKS5
- `bin/client` — Cliente METP

Para limpiar los archivos generados (objetos y ejecutables):

```bash
make clean
```

### Ubicación de los materiales

- **Códigos fuente:** `src/`
- **Archivos de construcción:** `Makefile`, `Makefile.inc` (en la raíz)
- **Ejecutables generados:** `bin/`
- **Tests:** `tests/`

## Uso

### 1. Configurar el Superusuario(Administrador)

```bash
export PROXY_CTRL_SUPERUSER=admin:password123
```

### 2. Ejecutar el Servidor

```bash
# Ejecutar con configuración por defecto
./bin/socks5d

# Mostrar ayuda
./bin/socks5d -h

# Mostrar versión
./bin/socks5d -v

# Configurar direcciones y puertos personalizados
./bin/socks5d -l 0.0.0.0 -p 1080 -L 127.0.0.1 -P 8080

# Agregar usuarios desde línea de comandos
./bin/socks5d -u admin:password123 -u user1:pass123 -u user2:pass456

# Ejemplo completo con todas las opciones
./bin/socks5d -l 0.0.0.0 -p 1080 -L 127.0.0.1 -P 8080 -u admin:password123 -u user1:pass123
```

### Opciones del Servidor

| Opción | Descripción | Valor por defecto |
|--------|-------------|-------------------|
| `-h` | Imprime la ayuda y termina | - |
| `-v` | Imprime información sobre la versión | - |
| `-l <addr>` | Dirección donde servirá el proxy SOCKS | 0.0.0.0 |
| `-L <addr>` | Dirección donde servirá el servicio de management | 127.0.0.1 |
| `-p <port>` | Puerto entrante conexiones SOCKS | 1080 |
| `-P <port>` | Puerto entrante conexiones configuración | 8080 |
| `-u <name>:<pass>` | Usuario y contraseña (hasta 10) | - |

### 3. Usar el Cliente METP

```bash
# Mostrar ayuda
./bin/client -h

# Mostrar versión
./bin/client -v

# Autenticarse con usuario:contraseña y obtener métricas
./bin/client -u admin:password123 -m

# Autenticarse y obtener logs (sólo rol Admin)
./bin/client -u admin:password123 -g

# Conectarse a un puerto distinto (ej.: 9090) y obtener métricas
./bin/client -u admin:password123 -p 9090 -m

# Agregar un nuevo usuario (modo Admin)
./bin/client -u admin:password123 -a bob password123

# Eliminar un usuario
./bin/client -u admin:password123 -d bob

# Cambiar rol de un usuario (por ejemplo a Admin)
./bin/client -u admin:password123 -r bob admin

# Cambiar tamaño máximo del buffer de I/O (ej.: 65536 bytes)
./bin/client -u admin:password123 -c 65536
```

## Protocolos

### METP (Metrics Protocol)

Protocolo de gestión basado en texto:

#### Handshake
```
Cliente -> Servidor: HELLO METP/1.0
Servidor -> Cliente: 200 Welcome to METP/1.0
```

#### Autenticación
```
Cliente -> Servidor: AUTH username password
Servidor -> Cliente: 200 OK (o 401 Unauthorized)
```

#### Comandos Disponibles

| Comando | Descripción | Permisos |
|---------|-------------|----------|
| `GET_METRICS` | Obtener estadísticas | User, Admin |
| `GET_LOGS` | Consultar logs de acceso | Admin |
| `USERS` | Consultar lista de ususarios | Admin |
| `ADD-USER` | Agregar usuario | Admin |
| `DELETE-USER` | Eliminar usuario | Admin |
| `SET-ROLE` | Cambiar rol de usuario | Admin |
| `CHANGE-BUFFER` | Cambiar tamaño de buffer | Admin |

#### Ejemplos de Respuesta

**GET_METRICS:**
```
200 OK
HISTORICAL_CONNECTIONS: 42
CURRENT_CONNECTIONS: 5
BYTES_TRANSFERRED: 1048576
.
```

**GET_LOGS:**
```
200 OK
[2025-01-15T14:30:25Z] admin 192.168.1.100 example.com:80 1024
[2025-01-15T14:31:10Z] user1 192.168.1.101 google.com:443 2048
.
```

## Sistema de Usuarios

### Roles

- **Admin**: Acceso completo a todos los comandos
- **User**: Solo puede ejecutar `GET_METRICS`

### Gestión de Usuarios

- **Agregar**: `ADD-USER username password`
- **Eliminar**: `DELETE-USER username`
- **Cambiar rol**: `SET-ROLE username role`

### Superusuario

El primer usuario admin se define mediante la variable de entorno:
```bash
export PROXY_CTRL_SUPERUSER=admin:password123
```

## Métricas

El servidor mantiene las siguientes métricas en tiempo real:

- **Conexiones históricas**: Total de conexiones desde el inicio
- **Conexiones actuales**: Conexiones activas en este momento
- **Bytes transferidos**: Total de datos transferidos
