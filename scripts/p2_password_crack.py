import socket
import subprocess
import traceback
import time

def decodificarBase64(line):
    #command = ['echo', "{}".format(line), '|', 'base64', '-d']
    command = 'echo "{}" | base64 -d'.format(line)
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    return result.stdout.strip()


def hash(hashingAlgorithm, line):
    command = 'echo -n "{}" | openssl dgst -{}'.format(line, hashingAlgorithm)
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    return result.stdout.split(' ')[1].strip()


def descifrarSimetrico(cypherAlgorithm, line, key):
    command = 'echo "{}" | base64 -d | openssl enc -d -{} -k {}'.format(line, cypherAlgorithm, key)
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    return result.stdout.strip()


def descifrarAsimetrico(line, privateKeyFileName):
    command = 'echo "{}" | base64 -d | openssl pkeyutl -decrypt -inkey {}'.format(line.strip(), privateKeyFileName)
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    return result.stdout.strip()

hashingAlgorithms = {
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

symmetricCypherAlgorithms = {
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

ip = '10.42.2.1'
port = 54471

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

password = ''
lastPassword = ''

try:
    client.connect((ip, port))
    print('Conectado a {ip}:{port}')

    socketFile = client.makefile('rw')
    print("Makefile hecho")

    for i in range(10):
        line = socketFile.readline()
        print(line)

        if('## Encoding ##' in line):
            print(socketFile.readline())
            line = socketFile.readline()
            print(line)
            print(socketFile.readline())
            password = decodificarBase64(line)
            lastPassword = password
            socketFile.write(password+"\n")
            print(password)
        elif('## Hashing ##' in line):
            for i in range(3):
                line = socketFile.readline()
                print(line)
                hashAlgorithm = [hashingAlgorithms[k] for k in hashingAlgorithms.keys() if k in line][0]
                password = hash(hashAlgorithm, lastPassword)
                lastPassword = password
                socketFile.write(password+"\n")
                socketFile.flush()
                print(password)
        elif('## Symmetric ciphers ##' in line):
            for i in range(3):
                line = socketFile.readline()
                print(line)
                cypherAlgorithm = [symmetricCypherAlgorithms[k] for k in symmetricCypherAlgorithms.keys() if k in line][0]
                line = socketFile.readline()
                print(line)
                key = line.split(' ')[2]
                print(socketFile.readline())
                line = socketFile.readline()
                print(line)
                password = descifrarSimetrico(cypherAlgorithm, line, key)
                lastPassword = password
                socketFile.write(password+"\n")
                socketFile.flush()
                print(password)
                print(socketFile.readline())
        elif('## Asymmetric ciphers ##' in line):
            for i in range(2):
                print(socketFile.readline())
                asymmetricKey1Pub = open('key1.pub', 'w')
                asymmetricKey1Pub.truncate(0)
                while(True):
                    line = socketFile.readline()
                    print(line)
                    asymmetricKey1Pub.write(line)
                    if('END PUBLIC KEY' in line):
                        break
                
                print(socketFile.readline())
                asymmetricKey1Priv = open('key1.priv', 'w')
                asymmetricKey1Priv.truncate(0)
                while(True):
                    line = socketFile.readline()
                    print(line)
                    asymmetricKey1Priv.write(line)
                    if('END PRIVATE KEY' in line):
                        break
                asymmetricKey1Priv.flush()
                print(socketFile.readline())
                line = socketFile.readline()
                print(line)
                password = descifrarAsimetrico(line, 'key1.priv')
                lastPassword = password
                socketFile.write(password+"\n")
                socketFile.flush()
                print(password)
        elif('## Asymmetric ciphers used for cipher symmetric cipher keys ##' in line):
            print(socketFile.readline())
            asymmetricKey1Pub = open('key1.pub', 'w')
            asymmetricKey1Pub.truncate(0)
            while(True):
                line = socketFile.readline()
                print(line)
                asymmetricKey1Pub.write(line)
                if('END PUBLIC KEY' in line):
                    break
            
            print(socketFile.readline())
            asymmetricKey1Priv = open('key1.priv', 'w')
            asymmetricKey1Priv.truncate(0)
            while(True):
                line = socketFile.readline()
                print(line)
                asymmetricKey1Priv.write(line)
                if('END PRIVATE KEY' in line):
                    break
            asymmetricKey1Priv.flush()
            line = socketFile.readline()
            cypherAlgorithm = [symmetricCypherAlgorithms[k] for k in symmetricCypherAlgorithms.keys() if k in line][0]
            print(socketFile.readline())
            line = socketFile.readline() 
            symmetricKey = descifrarAsimetrico(line, 'key1.priv')
            print(socketFile.readline())
            line = socketFile.readline() 
            password = descifrarSimetrico(cypherAlgorithm, line, symmetricKey)
            lastPassword = password
            socketFile.write(password+"\n")
            socketFile.flush()
            print(password)
        else:
            print(line)
        socketFile.flush()
except Exception as e:
    print(e)
    traceback.print_exc()
finally:
    client.close()