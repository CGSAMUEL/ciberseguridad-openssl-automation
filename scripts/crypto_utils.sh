#!/bin/bash

# Práctica 2 - Utilidades criptográficas
# Script de utilidades para operaciones criptográficas rápidas
# Autor: Samuel
# Fecha: 2025-09-22

# Función para mostrar ayuda
show_help() {
    echo "Utilidades Criptográficas - Práctica 2"
    echo "======================================"
    echo ""
    echo "Uso: $0 <comando> [argumentos]"
    echo ""
    echo "Comandos disponibles:"
    echo ""
    echo "  base64_decode <texto>          - Decodificar texto base64"
    echo "  base64_encode <texto>          - Codificar texto en base64"
    echo "  hash <algoritmo> <texto>       - Calcular hash (md5, sha1, sha256, sha512)"
    echo "  symmetric_decrypt <alg> <key> <encrypted> - Descifrado simétrico"
    echo "  generate_keys                  - Generar par de claves RSA para pruebas"
    echo "  verify_sig <file> <sig> <key> <hash> - Verificar firma digital"
    echo "  hex_to_ascii <hex>             - Convertir hexadecimal a ASCII"
    echo "  ascii_to_hex <texto>           - Convertir ASCII a hexadecimal"
    echo "  test_openssl                   - Probar instalación de OpenSSL"
    echo ""
    echo "Ejemplos:"
    echo "  $0 base64_decode 'SGVsbG8gV29ybGQ='"
    echo "  $0 hash md5 'password'"
    echo "  $0 symmetric_decrypt aes-192-ecb 'clave_hex' 'encrypted_base64'"
    echo ""
}

# Función para decodificar base64
base64_decode() {
    if [ -z "$1" ]; then
        echo "Error: Se requiere texto en base64"
        echo "Uso: $0 base64_decode <texto_base64>"
        return 1
    fi
    
    echo "Decodificando base64: $1"
    echo "Resultado:"
    echo "$1" | openssl enc -base64 -d
    echo ""
}

# Función para codificar base64
base64_encode() {
    if [ -z "$1" ]; then
        echo "Error: Se requiere texto para codificar"
        echo "Uso: $0 base64_encode <texto>"
        return 1
    fi
    
    echo "Codificando en base64: $1"
    echo "Resultado:"
    echo "$1" | openssl enc -base64
}

# Función para calcular hashes
calculate_hash() {
    if [ -z "$1" ] || [ -z "$2" ]; then
        echo "Error: Se requieren algoritmo y texto"
        echo "Uso: $0 hash <algoritmo> <texto>"
        echo "Algoritmos disponibles: md5, sha1, sha224, sha256, sha384, sha512"
        return 1
    fi
    
    local algorithm="$1"
    local text="$2"
    
    echo "Calculando hash $algorithm de: $text"
    echo "Resultado:"
    echo -n "$text" | openssl dgst -"$algorithm" | cut -d' ' -f2
}

# Función para descifrado simétrico
symmetric_decrypt() {
    if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
        echo "Error: Se requieren algoritmo, clave y texto cifrado"
        echo "Uso: $0 symmetric_decrypt <algoritmo> <clave_hex> <texto_base64>"
        echo "Algoritmos comunes: aes-128-ecb, aes-192-ecb, aes-256-ecb, aes-128-cbc, etc."
        return 1
    fi
    
    local algorithm="$1"
    local key="$2"
    local encrypted_base64="$3"
    
    echo "Descifrando con $algorithm"
    echo "Clave: $key"
    echo "Texto cifrado: $encrypted_base64"
    echo "Resultado:"
    
    echo "$encrypted_base64" | openssl enc -base64 -d | \
        openssl enc -"$algorithm" -d -K "$key" -iv 00000000000000000000000000000000 2>/dev/null || \
        echo "Error: No se pudo descifrar. Verifica algoritmo, clave y datos."
}

# Función para generar claves RSA de prueba
generate_keys() {
    local key_dir="../keys"
    mkdir -p "$key_dir"
    
    echo "Generando par de claves RSA de 2048 bits..."
    
    # Generar clave privada
    openssl genrsa -out "$key_dir/test_private.pem" 2048
    
    # Extraer clave pública
    openssl rsa -in "$key_dir/test_private.pem" -pubout -out "$key_dir/test_public.pem"
    
    echo "Claves generadas:"
    echo "- Clave privada: $key_dir/test_private.pem"
    echo "- Clave pública: $key_dir/test_public.pem"
    
    echo ""
    echo "Contenido de la clave pública:"
    cat "$key_dir/test_public.pem"
}

# Función para verificar firma digital
verify_signature() {
    if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ] || [ -z "$4" ]; then
        echo "Error: Se requieren archivo, firma, clave pública y algoritmo hash"
        echo "Uso: $0 verify_sig <archivo> <firma> <clave_publica> <algoritmo_hash>"
        return 1
    fi
    
    local file_path="$1"
    local signature_path="$2"
    local public_key_path="$3"
    local hash_algorithm="$4"
    
    echo "Verificando firma digital:"
    echo "- Archivo: $file_path"
    echo "- Firma: $signature_path"
    echo "- Clave pública: $public_key_path"
    echo "- Algoritmo: $hash_algorithm"
    echo ""
    
    if openssl dgst -"$hash_algorithm" -verify "$public_key_path" -signature "$signature_path" "$file_path" 2>/dev/null; then
        echo "✓ FIRMA VÁLIDA"
        return 0
    else
        echo "✗ FIRMA INVÁLIDA"
        return 1
    fi
}

# Función para convertir hex a ASCII
hex_to_ascii() {
    if [ -z "$1" ]; then
        echo "Error: Se requiere texto hexadecimal"
        echo "Uso: $0 hex_to_ascii <texto_hex>"
        return 1
    fi
    
    echo "Convirtiendo hexadecimal a ASCII: $1"
    echo "Resultado:"
    echo "$1" | xxd -r -p
    echo ""
}

# Función para convertir ASCII a hex
ascii_to_hex() {
    if [ -z "$1" ]; then
        echo "Error: Se requiere texto ASCII"
        echo "Uso: $0 ascii_to_hex <texto>"
        return 1
    fi
    
    echo "Convirtiendo ASCII a hexadecimal: $1"
    echo "Resultado:"
    echo -n "$1" | xxd -p | tr -d '\n'
    echo ""
}

# Función para probar OpenSSL
test_openssl() {
    echo "Probando instalación de OpenSSL..."
    echo "================================="
    echo ""
    
    echo "Versión de OpenSSL:"
    openssl version
    echo ""
    
    echo "Prueba de base64:"
    test_text="Hola Mundo"
    encoded=$(echo "$test_text" | openssl enc -base64)
    decoded=$(echo "$encoded" | openssl enc -base64 -d)
    echo "Original: $test_text"
    echo "Codificado: $encoded"
    echo "Decodificado: $decoded"
    
    if [ "$test_text" = "$decoded" ]; then
        echo "✓ Base64 funciona correctamente"
    else
        echo "✗ Error en base64"
    fi
    echo ""
    
    echo "Prueba de hash MD5:"
    hash_result=$(echo -n "$test_text" | openssl dgst -md5 | cut -d' ' -f2)
    echo "Hash MD5 de '$test_text': $hash_result"
    echo ""
    
    echo "Algoritmos de cifrado disponibles:"
    openssl enc -list | head -10
    echo "..."
    echo ""
    
    echo "Algoritmos de hash disponibles:"
    openssl dgst -list | head -10
    echo "..."
}

# Función para mostrar ejemplos interactivos
interactive_examples() {
    echo "Ejemplos Interactivos"
    echo "===================="
    echo ""
    
    while true; do
        echo "Selecciona un ejemplo:"
        echo "1. Decodificar base64"
        echo "2. Calcular hash MD5"
        echo "3. Descifrado AES-192-ECB"
        echo "4. Convertir hex a ASCII"
        echo "5. Salir"
        echo ""
        read -p "Opción (1-5): " option
        
        case $option in
            1)
                read -p "Introduce texto en base64: " b64_text
                base64_decode "$b64_text"
                ;;
            2)
                read -p "Introduce texto para hash: " hash_text
                calculate_hash "md5" "$hash_text"
                ;;
            3)
                read -p "Introduce clave hexadecimal: " sym_key
                read -p "Introduce texto cifrado (base64): " sym_encrypted
                symmetric_decrypt "aes-192-ecb" "$sym_key" "$sym_encrypted"
                ;;
            4)
                read -p "Introduce texto hexadecimal: " hex_text
                hex_to_ascii "$hex_text"
                ;;
            5)
                echo "¡Adiós!"
                break
                ;;
            *)
                echo "Opción inválida"
                ;;
        esac
        echo ""
    done
}

# Procesamiento de argumentos
case "$1" in
    "base64_decode")
        base64_decode "$2"
        ;;
    "base64_encode")
        base64_encode "$2"
        ;;
    "hash")
        calculate_hash "$2" "$3"
        ;;
    "symmetric_decrypt")
        symmetric_decrypt "$2" "$3" "$4"
        ;;
    "generate_keys")
        generate_keys
        ;;
    "verify_sig")
        verify_signature "$2" "$3" "$4" "$5"
        ;;
    "hex_to_ascii")
        hex_to_ascii "$2"
        ;;
    "ascii_to_hex")
        ascii_to_hex "$2"
        ;;
    "test_openssl")
        test_openssl
        ;;
    "interactive")
        interactive_examples
        ;;
    "help"|"-h"|"--help"|"")
        show_help
        ;;
    *)
        echo "Error: Comando no reconocido: $1"
        echo ""
        show_help
        exit 1
        ;;
esac