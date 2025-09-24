import socket
import subprocess
import traceback
import time

# Función para decodificar una cadena en base64
def decodificar_base64(linea):
    comando = f'echo "{linea}" | base64 -d'
    resultado = subprocess.run(comando, capture_output=True, text=True, shell=True)
    return resultado.stdout.strip()

# Función para calcular el hash de una línea usando el algoritmo especificado
def calcular_hash(algoritmo, linea):
    comando = f'echo -n "{linea}" | openssl dgst -{algoritmo}'
    resultado = subprocess.run(comando, capture_output=True, text=True, shell=True)
    return resultado.stdout.split(' ')[1].strip()

# Función para descifrar usando cifrado simétrico
def descifrar_simetrico(algoritmo, linea, clave):
    comando = f'echo "{linea}" | base64 -d | openssl enc -d -{algoritmo} -k {clave}'
    resultado = subprocess.run(comando, capture_output=True, text=True, shell=True)
    return resultado.stdout.strip()

# Función para descifrar usando cifrado asimétrico
def descifrar_asimetrico(linea, archivo_clave_privada):
    comando = f'echo "{linea.strip()}" | base64 -d | openssl pkeyutl -decrypt -inkey {archivo_clave_privada}'
    resultado = subprocess.run(comando, capture_output=True, text=True, shell=True)
    return resultado.stdout.strip()

# Diccionario de algoritmos de hash soportados
algoritmos_hash = {
    'blake2b512': 'blake2b512',
    'blake2s256': 'blake2s256',
    'md2': 'md2',
    'md4': 'md4',
    'md5': 'md5',
    'rmd160': 'rmd160',
    'sha1': 'sha1',
    'sha224': 'sha224',
    'sha256': 'sha256',
    'sha3-224': 'sha3-224',
    'sha3-256': 'sha3-256',
    'sha3-384': 'sha3-384',
    'sha3-512': 'sha3-512',
    'sha384': 'sha384',
    'sha512': 'sha512',
    'sha512-224': 'sha512-224',
    'sha512-256': 'sha512-256',
    'shake128': 'shake128',
    'shake256': 'shake256',
    'sm3': 'sm3',
    'ripemd160': 'ripemd160'
}

# Diccionario de algoritmos de cifrado simétrico soportados
algoritmos_simetricos = {
    'aes-128-cbc': 'aes-128-cbc',
    'aes-128-ecb': 'aes-128-ecb',
    'aes-192-cbc': 'aes-192-cbc',
    'aes-192-ecb': 'aes-192-ecb',
    'aes-256-cbc': 'aes-256-cbc',
    'aes-256-ecb': 'aes-256-ecb',
    'aria-128-cbc': 'aria-128-cbc',
    'aria-128-cfb': 'aria-128-cfb',
    'aria-128-cfb1': 'aria-128-cfb1',
    'aria-128-cfb8': 'aria-128-cfb8',
    'aria-128-ctr': 'aria-128-ctr',
    'aria-128-ecb': 'aria-128-ecb',
    'aria-128-ofb': 'aria-128-ofb',
    'aria-192-cbc': 'aria-192-cbc',
    'aria-192-cfb': 'aria-192-cfb',
    'aria-192-cfb1': 'aria-192-cfb1',
    'aria-192-cfb8': 'aria-192-cfb8',
    'aria-192-ctr': 'aria-192-ctr',
    'aria-192-ecb': 'aria-192-ecb',
    'aria-192-ofb': 'aria-192-ofb',
    'aria-256-cbc': 'aria-256-cbc',
    'aria-256-cfb': 'aria-256-cfb',
    'aria-256-cfb1': 'aria-256-cfb1',
    'aria-256-cfb8': 'aria-256-cfb8',
    'aria-256-ctr': 'aria-256-ctr',
    'aria-256-ecb': 'aria-256-ecb',
    'aria-256-ofb': 'aria-256-ofb',
    'base64': 'base64',
    'bf': 'bf',
    'bf-cbc': 'bf-cbc',
    'bf-cfb': 'bf-cfb',
    'bf-ecb': 'bf-ecb',
    'bf-ofb': 'bf-ofb',
    'camellia-128-cbc': 'camellia-128-cbc',
    'camellia-128-ecb': 'camellia-128-ecb',
    'camellia-192-cbc': 'camellia-192-cbc',
    'camellia-192-ecb': 'camellia-192-ecb',
    'camellia-256-cbc': 'camellia-256-cbc',
    'camellia-256-ecb': 'camellia-256-ecb',
    'cast': 'cast',
    'cast-cbc': 'cast-cbc',
    'cast5-cbc': 'cast5-cbc',
    'cast5-cfb': 'cast5-cfb',
    'cast5-ecb': 'cast5-ecb',
    'cast5-ofb': 'cast5-ofb',
    'des': 'des',
    'des-cbc': 'des-cbc',
    'des-cfb': 'des-cfb',
    'des-ecb': 'des-ecb',
    'des-ede': 'des-ede',
    'des-ede-cbc': 'des-ede-cbc',
    'des-ede-cfb': 'des-ede-cfb',
    'des-ede-ofb': 'des-ede-ofb',
    'des-ede3': 'des-ede3',
    'des-ede3-cbc': 'des-ede3-cbc',
    'des-ede3-cfb': 'des-ede3-cfb',
    'des-ede3-ofb': 'des-ede3-ofb',
    'des-ofb': 'des-ofb',
    'des3': 'des3',
    'desx': 'desx',
    'idea': 'idea',
    'idea-cbc': 'idea-cbc',
    'idea-cfb': 'idea-cfb',
    'idea-ecb': 'idea-ecb',
    'idea-ofb': 'idea-ofb',
    'rc2': 'rc2',
    'rc2-40-cbc': 'rc2-40-cbc',
    'rc2-64-cbc': 'rc2-64-cbc',
    'rc2-cbc': 'rc2-cbc',
    'rc2-cfb': 'rc2-cfb',
    'rc2-ecb': 'rc2-ecb',
    'rc2-ofb': 'rc2-ofb',
    'rc4': 'rc4',
    'rc4-40': 'rc4-40',
    'rc5': 'rc5',
    'rc5-cbc': 'rc5-cbc',
    'rc5-cfb': 'rc5-cfb',
    'rc5-ecb': 'rc5-ecb',
    'rc5-ofb': 'rc5-ofb',
    'seed': 'seed',
    'seed-cbc': 'seed-cbc',
    'seed-cfb': 'seed-cfb',
    'seed-ecb': 'seed-ecb',
    'seed-ofb': 'seed-ofb',
    'zlib': 'zlib'
}

# Configuración de la conexión
ip = '10.42.2.1'
puerto = 54471

cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

password = ''
ultimo_password = ''

try:
    # Conexión al servidor
    cliente.connect((ip, puerto))
    print(f'Conectado a {ip}:{puerto}')

    archivo_socket = cliente.makefile('rw')
    print("Makefile creado")

    for _ in range(10):
        linea = archivo_socket.readline()
        print(linea)

        # Decodificación base64
        if '## Encoding ##' in linea:
            print(archivo_socket.readline())
            linea = archivo_socket.readline()
            print(linea)
            print(archivo_socket.readline())
            password = decodificar_base64(linea)
            ultimo_password = password
            archivo_socket.write(password + "\n")
            print(password)
        # Hashing
        elif '## Hashing ##' in linea:
            for _ in range(3):
                linea = archivo_socket.readline()
                print(linea)
                algoritmo = [algoritmos_hash[k] for k in algoritmos_hash if k in linea][0]
                password = calcular_hash(algoritmo, ultimo_password)
                ultimo_password = password
                archivo_socket.write(password + "\n")
                archivo_socket.flush()
                print(password)
        # Cifrado simétrico
        elif '## Symmetric ciphers ##' in linea:
            for _ in range(3):
                linea = archivo_socket.readline()
                print(linea)
                algoritmo = [algoritmos_simetricos[k] for k in algoritmos_simetricos if k in linea][0]
                linea = archivo_socket.readline()
                print(linea)
                clave = linea.split(' ')[2]
                print(archivo_socket.readline())
                linea = archivo_socket.readline()
                print(linea)
                password = descifrar_simetrico(algoritmo, linea, clave)
                ultimo_password = password
                archivo_socket.write(password + "\n")
                archivo_socket.flush()
                print(password)
                print(archivo_socket.readline())
        # Cifrado asimétrico
        elif '## Asymmetric ciphers ##' in linea:
            for _ in range(2):
                print(archivo_socket.readline())
                clave_pub = open('key1.pub', 'w')
                clave_pub.truncate(0)
                while True:
                    linea = archivo_socket.readline()
                    print(linea)
                    clave_pub.write(linea)
                    if 'END PUBLIC KEY' in linea:
                        break
                print(archivo_socket.readline())
                clave_priv = open('key1.priv', 'w')
                clave_priv.truncate(0)
                while True:
                    linea = archivo_socket.readline()
                    print(linea)
                    clave_priv.write(linea)
                    if 'END PRIVATE KEY' in linea:
                        break
                clave_priv.flush()
                print(archivo_socket.readline())
                linea = archivo_socket.readline()
                print(linea)
                password = descifrar_asimetrico(linea, 'key1.priv')
                ultimo_password = password
                archivo_socket.write(password + "\n")
                archivo_socket.flush()
                print(password)
        # Cifrado asimétrico para clave simétrica
        elif '## Asymmetric ciphers used for cipher symmetric cipher keys ##' in linea:
            print(archivo_socket.readline())
            clave_pub = open('key1.pub', 'w')
            clave_pub.truncate(0)
            while True:
                linea = archivo_socket.readline()
                print(linea)
                clave_pub.write(linea)
                if 'END PUBLIC KEY' in linea:
                    break
            print(archivo_socket.readline())
            clave_priv = open('key1.priv', 'w')
            clave_priv.truncate(0)
            while True:
                linea = archivo_socket.readline()
                print(linea)
                clave_priv.write(linea)
                if 'END PRIVATE KEY' in linea:
                    break
            clave_priv.flush()
            linea = archivo_socket.readline()
            algoritmo = [algoritmos_simetricos[k] for k in algoritmos_simetricos if k in linea][0]
            print(archivo_socket.readline())
            linea = archivo_socket.readline()
            clave_simetrica = descifrar_asimetrico(linea, 'key1.priv')
            print(archivo_socket.readline())
            linea = archivo_socket.readline()
            password = descifrar_simetrico(algoritmo, linea, clave_simetrica)
            ultimo_password = password
            archivo_socket.write(password + "\n")
            archivo_socket.flush()
            print(password)
        else:
            print(linea)
        archivo_socket.flush()
except Exception as e:
    print(e)
    traceback.print_exc()
finally:
    cliente.close()
