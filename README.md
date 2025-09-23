Este repositorio contiene la práctica 2 de ciberseguridad con OpenSSL.

**IMPORTANTE:**
Solo el archivo `scripts/p2_password_crack.py` es funcional y correcto. Todos los demás scripts han sido eliminados.

## Uso

Ejecuta el script principal:

```bash
python scripts/p2_password_crack.py
```

Este script automatiza la conexión al servicio remoto de la práctica, resolviendo los siguientes desafíos:

- Decodificación Base64
- Hashing con varios algoritmos (md5, sha256, sha512, etc.)
- Descifrado simétrico (AES, DES, etc.)
- Descifrado asimétrico (RSA)
- Cifrado híbrido (RSA + cifrado simétrico)

El script se conecta al servidor, lee los retos, ejecuta los comandos necesarios usando OpenSSL y responde automáticamente, permitiendo obtener las credenciales y banderas requeridas para la práctica.

## Autor

Samuel
