# Práctica 2 - OpenSSL Scripting y Escalada de Privilegios

Este proyecto contiene scripts automatizados para completar la Práctica 2 de seguridad, que involucra:

1. **Conexión al servicio en puerto 54471**: Resolver desafíos criptográficos automáticamente
2. **Escalada de privilegios**: Verificar firmas digitales para obtener credenciales de root

## Estructura del Proyecto

```
practica2-openssl/
├── scripts/
│   ├── automate_service.sh      # Script principal para puerto 54471
│   └── privilege_escalation.sh  # Script para escalada de privilegios
├── temp/                        # Archivos temporales y logs
├── keys/                        # Claves criptográficas temporales
└── README.md                    # Esta documentación
```

## Prerrequisitos

Antes de ejecutar los scripts, asegúrate de tener instaladas las siguientes herramientas:

### En la máquina pivote (10.6.31.X):

```bash
# Instalar netcat
sudo apt install netcat-traditional

# Instalar OpenSSL
sudo apt install openssl

# Instalar expect (para automatización)
sudo apt install expect

# Instalar sshpass (para conexiones SSH automatizadas)
sudo apt install sshpass

# Verificar instalaciones
nc -h
openssl version
expect -v
sshpass -V
```

## Configuración de Red

- **Máquina objetivo**: 10.42.2.1
- **Puerto del servicio**: 54471
- **Puerto SSH**: 22
- **Red objetivo**: 10.42.0.0/16

## Uso de los Scripts

### 1. Script Principal: automate_service.sh

Este script automatiza todo el proceso de conexión al puerto 54471 y resolución de desafíos:

#### Comandos disponibles:

```bash
# Hacer executable el script
chmod +x scripts/automate_service.sh

# Automatización completa (recomendado)
./scripts/automate_service.sh auto

# Conexión manual al servicio
./scripts/automate_service.sh manual

# Conectar por SSH usando credenciales obtenidas
./scripts/automate_service.sh ssh

# Probar herramientas necesarias
./scripts/automate_service.sh test
```

#### Proceso automatizado:

El script resolverá automáticamente:

1. **Decodificación Base64**: Decodifica contraseñas en base64
2. **Hashing**: Calcula MD5, SHA256, SHA512, etc.
3. **Cifrado Simétrico**: Descifra usando AES, DES, etc.
4. **Cifrado Asimétrico**: Descifra usando RSA
5. **Cifrado Híbrido**: Combina RSA + AES

#### Archivos de salida:

- `ssh_credentials.txt`: Credenciales SSH si se completa en tiempo
- `user_flag.txt`: Flag de usuario si se agota el tiempo
- `temp/session.log`: Log detallado de la sesión

### 2. Script de Escalada: privilege_escalation.sh

Para la escalada de privilegios una vez dentro del sistema:

```bash
# Hacer executable el script
chmod +x scripts/privilege_escalation.sh

# Automatización de escalada (recomendado)
./scripts/privilege_escalation.sh auto

# Verificación manual de una firma específica
./scripts/privilege_escalation.sh manual archivo.txt firma.sig clave.pub sha512

# Probar todas las combinaciones
./scripts/privilege_escalation.sh test

# Verificar archivo específico con clave específica
./scripts/privilege_escalation.sh verify 1 2 sha512
```

## Flujo de Trabajo Recomendado

### Fase 1: Obtener Credenciales SSH

1. **Preparación**:
   ```bash
   cd "C:/Users/samuel/Documents/uni 25-26/seguridad/practica2-openssl"
   chmod +x scripts/*.sh
   ```

2. **Prueba de conectividad**:
   ```bash
   ./scripts/automate_service.sh test
   ```

3. **Automatización completa**:
   ```bash
   ./scripts/automate_service.sh auto
   ```

4. **Verificar resultados**:
   ```bash
   cat ssh_credentials.txt    # Si se completó en tiempo
   cat user_flag.txt         # Si se agotó el tiempo
   ```

### Fase 2: Acceso SSH

```bash
# Conectar automáticamente usando credenciales obtenidas
./scripts/automate_service.sh ssh

# O manualmente:
# ssh usuario@10.42.2.1
# (usar credenciales de ssh_credentials.txt)
```

### Fase 3: Escalada de Privilegios

Una vez dentro del sistema SSH:

1. **Ejecutar programa de escalada**:
   ```bash
   # Transferir script al sistema remoto si es necesario
   # Ejecutar programa de escalada del sistema
   ./privilege_escalation_program  # (nombre del programa real)
   ```

2. **Automatizar verificación** (en tu máquina local):
   ```bash
   ./scripts/privilege_escalation.sh auto
   ```

## Tipos de Desafíos Criptográficos

### 1. Decodificación Base64
```bash
# Ejemplo manual:
echo "SGVsbG8gV29ybGQ=" | openssl enc -base64 -d
# Resultado: Hello World
```

### 2. Hashing
```bash
# MD5
echo -n "password" | openssl dgst -md5

# SHA256
echo -n "password" | openssl dgst -sha256

# SHA512
echo -n "password" | openssl dgst -sha512
```

### 3. Cifrado Simétrico
```bash
# Descifrar AES-192-ECB
echo "base64_encrypted" | openssl enc -base64 -d | \
  openssl enc -aes-192-ecb -d -K "clave_hex" -iv 00000000000000000000000000000000
```

### 4. Cifrado Asimétrico
```bash
# Descifrar con clave privada RSA
echo "base64_encrypted" | openssl enc -base64 -d | \
  openssl rsautl -decrypt -inkey private_key.pem
```

### 5. Cifrado Híbrido
```bash
# 1. Descifrar clave simétrica con RSA
echo "encrypted_key_base64" | openssl enc -base64 -d | \
  openssl rsautl -decrypt -inkey private_key.pem | xxd -p | tr -d '\n'

# 2. Descifrar datos con clave simétrica
echo "encrypted_data_base64" | openssl enc -base64 -d | \
  openssl enc -aes-256-ecb -d -K "decrypted_key_hex"
```

### 6. Verificación de Firmas Digitales
```bash
# Verificar firma
openssl dgst -sha512 -verify public_key.pub -signature signature.sig file.txt
```

## Troubleshooting

### Problemas Comunes:

1. **Error de conexión**:
   ```bash
   # Verificar conectividad
   nc -z 10.42.2.1 54471
   nc -z 10.42.2.1 22
   ```

2. **Timeout en automatización**:
   - El script está diseñado para trabajar en menos de 30 segundos
   - Si falla, intenta el modo manual primero para entender el flujo

3. **Error de OpenSSL**:
   ```bash
   # Verificar instalación
   openssl version
   which openssl
   ```

4. **Problemas de permisos**:
   ```bash
   chmod +x scripts/*.sh
   chmod 600 keys/*.pem  # Para claves privadas
   ```

### Logs y Depuración:

- `temp/session.log`: Log de la sesión del puerto 54471
- `temp/escalation.log`: Log de escalada de privilegios
- `temp/verification_results.txt`: Resultados de verificación de firmas

## Comandos de Utilidad

### Convertir entre formatos:
```bash
# Hexadecimal a binario
echo "48656c6c6f" | xxd -r -p

# Binario a hexadecimal
echo "Hello" | xxd -p

# Base64 encode/decode
echo "Hello" | openssl enc -base64
echo "SGVsbG8K" | openssl enc -base64 -d
```

### Generar claves para pruebas:
```bash
# Generar clave privada RSA
openssl genrsa -out test_private.pem 2048

# Extraer clave pública
openssl rsa -in test_private.pem -pubout -out test_public.pem

# Firmar archivo
openssl dgst -sha512 -sign test_private.pem -out test.sig test.txt

# Verificar firma
openssl dgst -sha512 -verify test_public.pem -signature test.sig test.txt
```

## Resultados Esperados

Al completar exitosamente la práctica, deberías obtener:

1. **Flag de usuario**: En `user_flag.txt` o como output del programa
2. **Flag de root**: En `root_flag.txt` después de escalada exitosa
3. **Credenciales SSH**: Usuario y contraseña para acceso SSH
4. **Credenciales Root**: Usuario y contraseña de root

## Notas de Seguridad

- Los scripts manejan credenciales temporalmente en archivos
- Todos los archivos temporales se limpian automáticamente
- Las claves se almacenan solo durante la ejecución
- Logs pueden contener información sensible - revisar antes de compartir

## Autor

Samuel - Práctica 2 de Seguridad  
Universidad - Curso 2025-26  
Fecha: 21 de Septiembre, 2025