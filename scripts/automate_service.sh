#!/bin/bash

# Práctica 2 - Automatización del servicio en puerto 54471
# Script para resolver automáticamente todos los desafíos criptográficos
# Autor: Samuel
# Fecha: 2025-09-22

# Configuración
TARGET_HOST="10.42.2.1"
TARGET_PORT="54471"
TIMEOUT=30

# Directorios
SCRIPT_DIR="$(dirname "$0")"
TEMP_DIR="${SCRIPT_DIR}/../temp"
KEYS_DIR="${SCRIPT_DIR}/../keys"

# Crear directorios temporales si no existen
mkdir -p "$TEMP_DIR" "$KEYS_DIR"

# Función para logging
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$TEMP_DIR/session.log"
}

# Función para limpiar archivos temporales
cleanup() {
    log "Limpiando archivos temporales..."
    rm -f "$TEMP_DIR"/*.tmp "$KEYS_DIR"/*.pem "$KEYS_DIR"/*.pub "$KEYS_DIR"/*.priv
}

# Función para decodificar base64
decode_base64() {
    echo "$1" | openssl enc -base64 -d
}

# Función para calcular hash MD5
calculate_md5() {
    echo -n "$1" | openssl dgst -md5 | cut -d' ' -f2
}

# Función para calcular otros hashes
calculate_hash() {
    local hash_type="$1"
    local input="$2"
    echo -n "$input" | openssl dgst -"$hash_type" | cut -d' ' -f2
}

# Función para descifrado simétrico
decrypt_symmetric() {
    local algorithm="$1"
    local key="$2"
    local encrypted_base64="$3"
    
    echo "$encrypted_base64" | openssl enc -base64 -d | openssl enc -"$algorithm" -d -K "$key" -iv 00000000000000000000000000000000 2>/dev/null
}

# Función para descifrado asimétrico
decrypt_asymmetric() {
    local private_key_content="$1"
    local encrypted_base64="$2"
    
    # Guardar clave privada temporal
    echo "$private_key_content" > "$KEYS_DIR/temp_private.pem"
    
    # Desencriptar
    echo "$encrypted_base64" | openssl enc -base64 -d | openssl rsautl -decrypt -inkey "$KEYS_DIR/temp_private.pem" 2>/dev/null
}

# Función para descifrado híbrido
decrypt_hybrid() {
    local private_key_content="$1"
    local encrypted_key_base64="$2"
    local encrypted_data_base64="$3"
    local symmetric_algorithm="$4"
    
    # Guardar clave privada temporal
    echo "$private_key_content" > "$KEYS_DIR/temp_private.pem"
    
    # Desencriptar la clave simétrica
    local decrypted_key=$(echo "$encrypted_key_base64" | openssl enc -base64 -d | openssl rsautl -decrypt -inkey "$KEYS_DIR/temp_private.pem" 2>/dev/null | xxd -p | tr -d '\n')
    
    # Desencriptar los datos con la clave simétrica
    echo "$encrypted_data_base64" | openssl enc -base64 -d | openssl enc -"$symmetric_algorithm" -d -K "$decrypted_key" -iv 00000000000000000000000000000000 2>/dev/null
}

# Función principal de automatización
automate_service() {
    log "Iniciando conexión a $TARGET_HOST:$TARGET_PORT"
    
    # Usar expect para automatizar la interacción
    expect << 'EOF'
set timeout 30
set target_host [lindex $argv 0]
set target_port [lindex $argv 1]

proc log_message {msg} {
    puts "[timestamp -format {%Y-%m-%d %H:%M:%S}] $msg"
}

proc decode_base64 {encoded} {
    set temp_file "/tmp/base64_temp"
    set fd [open $temp_file "w"]
    puts $fd $encoded
    close $fd
    
    set result [exec openssl enc -base64 -d -in $temp_file]
    file delete $temp_file
    return $result
}

proc calculate_md5 {input} {
    return [exec echo -n $input | openssl dgst -md5 | cut -d' ' -f2]
}

proc calculate_hash {hash_type input} {
    return [exec echo -n $input | openssl dgst -$hash_type | cut -d' ' -f2]
}

# Conectar al servicio
spawn nc $target_host $target_port
set spawn_id $spawn_id

# Variables para almacenar estados
set current_password ""
set stage 1

while {1} {
    expect {
        timeout {
            log_message "Timeout - reiniciando conexión"
            break
        }
        
        # Etapa 1: Decodificación Base64
        -re "## Encoding ##.*# Base 64 #\r?\n(.+)\r?\n# give me the password #" {
            set encoded $expect_out(1,string)
            log_message "Base64 encontrado: $encoded"
            set current_password [decode_base64 $encoded]
            log_message "Password decodificado: $current_password"
            send "$current_password\r"
            exp_continue
        }
        
        # Etapa 2: Hash MD5
        -re "## Hashing ##.*# hash md5 of the last inserted password #.*# give me the password #" {
            set md5_hash [calculate_md5 $current_password]
            log_message "MD5 calculado: $md5_hash"
            send "$md5_hash\r"
            set current_password $md5_hash
            exp_continue
        }
        
        # Otros tipos de hash
        -re "# hash (\w+) of the last inserted password #.*# give me the password #" {
            set hash_type $expect_out(1,string)
            set hash_result [calculate_hash $hash_type $current_password]
            log_message "$hash_type calculado: $hash_result"
            send "$hash_result\r"
            set current_password $hash_result
            exp_continue
        }
        
        # Cifrado simétrico
        -re "## Symmetric ciphers ##.*# (.+) cipher algorithm #.*# key (.+) #.*# Base64 of the ciphered password #\r?\n(.+)\r?\n# give me the password #" {
            set algorithm $expect_out(1,string)
            set key $expect_out(2,string)
            set encrypted $expect_out(3,string)
            
            log_message "Cifrado simétrico detectado: $algorithm"
            log_message "Clave: $key"
            
            # Crear archivo temporal para descifrado
            set temp_file "/tmp/encrypted_temp"
            set fd [open $temp_file "w"]
            puts $fd $encrypted
            close $fd
            
            set decrypted [exec bash -c "echo '$encrypted' | openssl enc -base64 -d | openssl enc -$algorithm -d -K $key -iv 00000000000000000000000000000000 2>/dev/null || echo 'ERROR'"]
            
            if {$decrypted ne "ERROR"} {
                log_message "Descifrado exitoso: $decrypted"
                send "$decrypted\r"
                set current_password $decrypted
            } else {
                log_message "Error en descifrado simétrico"
            }
            
            file delete $temp_file
            exp_continue
        }
        
        # Cifrado asimétrico - capturar claves y datos
        -re "## Asymmetric ciphers ##.*# key1.pub #\r?\n(-----BEGIN PUBLIC KEY-----.*-----END PUBLIC KEY-----)\r?\n# key1.priv #\r?\n(-----BEGIN PRIVATE KEY-----.*-----END PRIVATE KEY-----)\r?\n# Base64 of the ciphered password #\r?\n(.+)\r?\n# give me the password #" {
            set public_key $expect_out(1,string)
            set private_key $expect_out(2,string)
            set encrypted $expect_out(3,string)
            
            log_message "Cifrado asimétrico detectado"
            
            # Guardar clave privada
            set key_file "/tmp/private_key.pem"
            set fd [open $key_file "w"]
            puts $fd $private_key
            close $fd
            
            set decrypted [exec bash -c "echo '$encrypted' | openssl enc -base64 -d | openssl rsautl -decrypt -inkey $key_file 2>/dev/null || echo 'ERROR'"]
            
            if {$decrypted ne "ERROR"} {
                log_message "Descifrado asimétrico exitoso: $decrypted"
                send "$decrypted\r"
                set current_password $decrypted
            } else {
                log_message "Error en descifrado asimétrico"
            }
            
            file delete $key_file
            exp_continue
        }
        
        # Cifrado híbrido
        -re "## Asymmetric ciphers used for cipher symmetric cipher keys ##.*# key1.pub #\r?\n(-----BEGIN PUBLIC KEY-----.*-----END PUBLIC KEY-----)\r?\n# key1.priv #\r?\n(-----BEGIN PRIVATE KEY-----.*-----END PRIVATE KEY-----)\r?\n# (.+) symetric cipher algorithm #.*# Base64 of the key for symmetric algorithm after asymmetric cipher #\r?\n(.+)\r?\n# Base64 of the ciphered password after symmetric cipher#\r?\n(.+)\r?\n# give me the password #" {
            set public_key $expect_out(1,string)
            set private_key $expect_out(2,string)
            set sym_algorithm $expect_out(3,string)
            set encrypted_key $expect_out(4,string)
            set encrypted_data $expect_out(5,string)
            
            log_message "Cifrado híbrido detectado: $sym_algorithm"
            
            # Guardar clave privada
            set key_file "/tmp/private_key.pem"
            set fd [open $key_file "w"]
            puts $fd $private_key
            close $fd
            
            # Descifrar clave simétrica
            set decrypted_key [exec bash -c "echo '$encrypted_key' | openssl enc -base64 -d | openssl rsautl -decrypt -inkey $key_file 2>/dev/null | xxd -p | tr -d '\\n' || echo 'ERROR'"]
            
            if {$decrypted_key ne "ERROR"} {
                # Descifrar datos con clave simétrica
                set decrypted [exec bash -c "echo '$encrypted_data' | openssl enc -base64 -d | openssl enc -$sym_algorithm -d -K $decrypted_key -iv 00000000000000000000000000000000 2>/dev/null || echo 'ERROR'"]
                
                if {$decrypted ne "ERROR"} {
                    log_message "Descifrado híbrido exitoso: $decrypted"
                    send "$decrypted\r"
                    set current_password $decrypted
                } else {
                    log_message "Error en descifrado de datos híbrido"
                }
            } else {
                log_message "Error en descifrado de clave híbrida"
            }
            
            file delete $key_file
            exp_continue
        }
        
        # Capturar credenciales SSH
        -re "SSH Username: (.+)\r?\nSSH Password: (.+)\r?" {
            set username $expect_out(1,string)
            set password $expect_out(2,string)
            log_message "¡CREDENCIALES OBTENIDAS!"
            log_message "Usuario SSH: $username"
            log_message "Contraseña SSH: $password"
            
            # Guardar credenciales
            set cred_file "ssh_credentials.txt"
            set fd [open $cred_file "w"]
            puts $fd "SSH Username: $username"
            puts $fd "SSH Password: $password"
            close $fd
            
            break
        }
        
        # Capturar flag de usuario si se agota el tiempo
        -re "User flag: (.+)\r?" {
            set user_flag $expect_out(1,string)
            log_message "Flag de usuario obtenida: $user_flag"
            
            set flag_file "user_flag.txt"
            set fd [open $flag_file "w"]
            puts $fd "User flag: $user_flag"
            close $fd
            
            break
        }
        
        eof {
            log_message "Conexión cerrada"
            break
        }
    }
}

close
EOF

    # Limpiar archivos temporales
    cleanup
}

# Función para conectar por SSH usando las credenciales obtenidas
ssh_connect() {
    if [ -f "ssh_credentials.txt" ]; then
        local username=$(grep "SSH Username:" ssh_credentials.txt | cut -d' ' -f3)
        local password=$(grep "SSH Password:" ssh_credentials.txt | cut -d' ' -f3)
        
        log "Conectando por SSH con usuario: $username"
        sshpass -p "$password" ssh "$username@$TARGET_HOST"
    else
        log "No se encontraron credenciales SSH"
        return 1
    fi
}

# Menú principal
case "$1" in
    "auto")
        log "Iniciando automatización completa..."
        automate_service
        ;;
    "ssh")
        log "Conectando por SSH..."
        ssh_connect
        ;;
    "manual")
        log "Conectando manualmente al servicio..."
        nc "$TARGET_HOST" "$TARGET_PORT"
        ;;
    "test")
        log "Probando herramientas..."
        echo "Probando netcat..."
        nc -z "$TARGET_HOST" 22 && echo "Puerto SSH accesible" || echo "Puerto SSH no accesible"
        echo "Probando OpenSSL..."
        echo "hola" | openssl enc -base64
        ;;
    *)
        echo "Uso: $0 {auto|ssh|manual|test}"
        echo "  auto   - Automatizar todo el proceso de desafíos"
        echo "  ssh    - Conectar por SSH usando credenciales obtenidas"
        echo "  manual - Conexión manual al puerto 54471"
        echo "  test   - Probar herramientas necesarias"
        exit 1
        ;;
esac