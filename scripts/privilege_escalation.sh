#!/bin/bash

# Práctica 2 - Escalada de privilegios mediante verificación de firmas digitales
# Script para automatizar la verificación de firmas y obtener credenciales de root
# Autor: Samuel
# Fecha: 2025-09-22

# Directorios
SCRIPT_DIR="$(dirname "$0")"
TEMP_DIR="${SCRIPT_DIR}/../temp"
KEYS_DIR="${SCRIPT_DIR}/../keys"

# Crear directorios si no existen
mkdir -p "$TEMP_DIR" "$KEYS_DIR"

# Función para logging
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$TEMP_DIR/escalation.log"
}

# Función para limpiar archivos temporales
cleanup() {
    log "Limpiando archivos temporales de escalada..."
    rm -f "$TEMP_DIR"/file*.tmp "$TEMP_DIR"/signature*.tmp "$KEYS_DIR"/key*.pem
}

# Función para decodificar base64 y guardar archivo
decode_and_save() {
    local encoded_content="$1"
    local output_file="$2"
    echo "$encoded_content" | openssl enc -base64 -d > "$output_file"
}

# Función para verificar firma digital
verify_signature() {
    local file_path="$1"
    local signature_path="$2"
    local public_key_path="$3"
    local hash_algorithm="$4"
    
    # Verificar la firma
    openssl dgst -"$hash_algorithm" -verify "$public_key_path" -signature "$signature_path" "$file_path" 2>/dev/null
    return $?
}

# Función principal de escalada automatizada
automate_privilege_escalation() {
    log "Iniciando automatización de escalada de privilegios..."
    
    # Usar expect para automatizar la interacción con el programa de escalada
    expect << 'EOF'
set timeout 60

proc log_message {msg} {
    puts "[timestamp -format {%Y-%m-%d %H:%M:%S}] $msg"
}

proc decode_base64_to_file {encoded filename} {
    set fd [open $filename "w"]
    puts $fd $encoded
    close $fd
    exec openssl enc -base64 -d -in $filename -out ${filename}.decoded
    file delete $filename
    file rename ${filename}.decoded $filename
}

proc verify_signature {file_path sig_path key_path hash_alg} {
    set result [catch {exec openssl dgst -$hash_alg -verify $key_path -signature $sig_path $file_path} output]
    if {$result == 0} {
        return 1
    } else {
        return 0
    }
}

# Variables para almacenar datos
set files {}
set signatures {}
set public_keys {}
set private_keys {}
set hash_algorithm ""

# Ejecutar el programa de escalada (asumiendo que está disponible)
spawn ./privilege_escalation_program
set spawn_id $spawn_id

# Estado de parsing
set parsing_state "init"
set current_key_num 0
set current_file_num 0
set current_sig_num 0

while {1} {
    expect {
        timeout {
            log_message "Timeout en programa de escalada"
            break
        }
        
        # Capturar claves públicas
        -re "# key(\\d+).pub #\\r?\\n(-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----)\\r?\\n" {
            set key_num $expect_out(1,string)
            set pub_key $expect_out(2,string)
            log_message "Clave pública $key_num capturada"
            
            # Guardar clave pública
            set key_file "temp/key${key_num}.pub"
            set fd [open $key_file "w"]
            puts $fd $pub_key
            close $fd
            
            lappend public_keys $key_file
            exp_continue
        }
        
        # Capturar claves privadas
        -re "# key(\\d+).priv #\\r?\\n(-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----)\\r?\\n" {
            set key_num $expect_out(1,string)
            set priv_key $expect_out(2,string)
            log_message "Clave privada $key_num capturada"
            
            # Guardar clave privada
            set key_file "temp/key${key_num}.priv"
            set fd [open $key_file "w"]
            puts $fd $priv_key
            close $fd
            
            lappend private_keys $key_file
            exp_continue
        }
        
        # Capturar archivos
        -re "# file(\\d+) #\\r?\\n(.+?)\\r?\\n(?=# |$)" {
            set file_num $expect_out(1,string)
            set file_content $expect_out(2,string)
            log_message "Archivo $file_num capturado"
            
            # Decodificar y guardar archivo
            set file_path "temp/file${file_num}.txt"
            decode_base64_to_file $file_content $file_path
            lappend files $file_path
            exp_continue
        }
        
        # Capturar algoritmo hash
        -re "# hash #\\r?\\n(\\w+)\\r?\\n" {
            set hash_algorithm $expect_out(1,string)
            log_message "Algoritmo hash: $hash_algorithm"
            exp_continue
        }
        
        # Capturar firmas
        -re "# signature file (\\d+) #\\r?\\n(.+?)\\r?\\n(?=# |$)" {
            set sig_num $expect_out(1,string)
            set sig_content $expect_out(2,string)
            log_message "Firma $sig_num capturada"
            
            # Decodificar y guardar firma
            set sig_path "temp/signature${sig_num}.sig"
            decode_base64_to_file $sig_content $sig_path
            lappend signatures $sig_path
            exp_continue
        }
        
        # Responder a preguntas sobre qué clave firmó cada archivo
        -re "# Key for signature (\\d+) #" {
            set sig_num $expect_out(1,string)
            log_message "Verificando firma $sig_num"
            
            # Intentar verificar con cada clave pública
            set correct_key 0
            for {set i 1} {$i <= 3} {incr i} {
                set key_file "temp/key${i}.pub"
                set file_path "temp/file${sig_num}.txt"
                set sig_path "temp/signature${sig_num}.sig"
                
                if {[verify_signature $file_path $sig_path $key_file $hash_algorithm]} {
                    set correct_key $i
                    log_message "Archivo $sig_num firmado con clave $i"
                    break
                }
            }
            
            if {$correct_key > 0} {
                send "$correct_key\r"
            } else {
                log_message "No se pudo verificar la firma $sig_num"
                send "1\r"
            }
            exp_continue
        }
        
        # Capturar credenciales de root
        -re "Root Username: (.+)\\r?\\nRoot Password: (.+)\\r?" {
            set root_username $expect_out(1,string)
            set root_password $expect_out(2,string)
            log_message "¡CREDENCIALES DE ROOT OBTENIDAS!"
            log_message "Usuario root: $root_username"
            log_message "Contraseña root: $root_password"
            
            # Guardar credenciales
            set cred_file "root_credentials.txt"
            set fd [open $cred_file "w"]
            puts $fd "Root Username: $root_username"
            puts $fd "Root Password: $root_password"
            close $fd
            
            break
        }
        
        # Capturar flag de root
        -re "Root flag: (.+)\\r?" {
            set root_flag $expect_out(1,string)
            log_message "Flag de root obtenida: $root_flag"
            
            set flag_file "root_flag.txt"
            set fd [open $flag_file "w"]
            puts $fd "Root flag: $root_flag"
            close $fd
            
            break
        }
        
        eof {
            log_message "Programa de escalada terminado"
            break
        }
    }
}

close
EOF

    cleanup
}

# Función para verificar firmas manualmente
manual_verification() {
    log "Modo de verificación manual..."
    
    if [ $# -lt 4 ]; then
        echo "Uso: manual_verification <archivo> <firma> <clave_publica> <algoritmo_hash>"
        return 1
    fi
    
    local file_path="$1"
    local signature_path="$2"
    local public_key_path="$3"
    local hash_algorithm="$4"
    
    log "Verificando: $file_path con clave $public_key_path"
    
    if verify_signature "$file_path" "$signature_path" "$public_key_path" "$hash_algorithm"; then
        log "✓ Verificación exitosa"
        echo "VALIDA"
        return 0
    else
        log "✗ Verificación fallida"
        echo "INVALIDA"
        return 1
    fi
}

# Función auxiliar para probar todas las combinaciones
test_all_signatures() {
    log "Probando todas las combinaciones de firmas y claves..."
    
    local base_dir="${TEMP_DIR}"
    local results_file="${base_dir}/verification_results.txt"
    
    echo "Resultados de verificación de firmas:" > "$results_file"
    echo "=====================================" >> "$results_file"
    
    for file_num in {1..5}; do
        echo "" >> "$results_file"
        echo "Archivo $file_num:" >> "$results_file"
        
        for key_num in {1..3}; do
            local file_path="${base_dir}/file${file_num}.txt"
            local sig_path="${base_dir}/signature${file_num}.sig"
            local key_path="${base_dir}/key${key_num}.pub"
            
            if [ -f "$file_path" ] && [ -f "$sig_path" ] && [ -f "$key_path" ]; then
                if verify_signature "$file_path" "$sig_path" "$key_path" "sha512"; then
                    echo "  Clave $key_num: VÁLIDA ✓" >> "$results_file"
                    log "Archivo $file_num verificado con clave $key_num"
                else
                    echo "  Clave $key_num: INVÁLIDA ✗" >> "$results_file"
                fi
            fi
        done
    done
    
    log "Resultados guardados en $results_file"
    cat "$results_file"
}

# Menú principal
case "$1" in
    "auto")
        log "Iniciando escalada automática..."
        automate_privilege_escalation
        ;;
    "manual")
        shift
        manual_verification "$@"
        ;;
    "test")
        log "Probando verificación de firmas..."
        test_all_signatures
        ;;
    "verify")
        if [ $# -eq 5 ]; then
            # Verificar archivo específico con clave específica
            local file_num="$2"
            local key_num="$3"
            local hash_alg="${4:-sha512}"
            
            local file_path="${TEMP_DIR}/file${file_num}.txt"
            local sig_path="${TEMP_DIR}/signature${file_num}.sig"
            local key_path="${TEMP_DIR}/key${key_num}.pub"
            
            manual_verification "$file_path" "$sig_path" "$key_path" "$hash_alg"
        else
            echo "Uso: $0 verify <num_archivo> <num_clave> [algoritmo_hash]"
        fi
        ;;
    *)
        echo "Uso: $0 {auto|manual|test|verify}"
        echo "  auto                              - Automatizar escalada de privilegios"
        echo "  manual <archivo> <firma> <clave> <hash> - Verificación manual"
        echo "  test                              - Probar todas las combinaciones"
        echo "  verify <num_archivo> <num_clave> [hash]  - Verificar archivo específico"
        exit 1
        ;;
esac