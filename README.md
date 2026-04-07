# cryptoSC — Cifrado AES-256-GCM para archivos de texto plano

Herramienta CLI para cifrar y descifrar archivos de texto plano usando la librería **PyCryptodome** y el algoritmo **AES en modo GCM**.

---

## Estructura del proyecto

```
cryptoSC/
├── cryptoSC.py       # Programa principal
├── requirements.txt     # Dependencias
├── mensaje_prueba.txt   # Archivo de texto de prueba
├── README.md            # Este archivo
└── capturas/            # Evidencia de ejecución (screenshots)
```

---

## Instalación

```bash
# 1. Clonar el repositorio
git clone https://github.com/sebastianmct/CryptoSC-BlockChain.git
cd cryptoSC

# 3. Instalar dependencias
pip install -r requirements.txt
```

---

## Uso — Línea de comandos

CLI

### 1. Generar una llave criptográfica

```bash
python cryptoSC.py generar-llave --salida llave.key
```

### 2. Cifrar un archivo

```bash
python cryptoSC.py cifrar --texto mensaje_prueba.txt --llave llave.key --salida mensaje.enc
```

### 3. Descifrar un archivo

```bash
python cryptoSC.py descifrar --cifrado mensaje.enc --llave llave.key --salida recuperado.txt
```

---

## Modo AES seleccionado: **GCM (Galois/Counter Mode)**

### Justificación

Se eligió AES-GCM sobre otros modos (CBC, CTR, ECB) por las siguientes razones:

| Característica | ECB | CBC | GCM |
|---|---|---|---|
| Confidencialidad | Débil | Sí | Sí |
| Integridad / Autenticación | No | No | Sí (tag) |
| Paralelizable | Sí | No | Sí |
| Necesita padding | Sí | Sí | **No** |
| Detecta alteraciones | No | No | **Sí** |

**GCM es un modo AEAD (Authenticated Encryption with Associated Data):** en un solo paso cifra el contenido *y* genera un tag de autenticación de 16 bytes. Si alguien altera el archivo cifrado o usa una llave incorrecta, el descifrado falla antes de devolver cualquier dato.

### Tamaño de llave utilizado

**AES-256 → llave de 32 bytes (256 bits)**

Se eligió AES-256 (el máximo disponible) para mayor resistencia ante ataques de fuerza bruta, siguiendo las recomendaciones actuales del NIST para datos que requieren protección a largo plazo.

---

## Formato del archivo `.enc`

El archivo cifrado no guarda solo el ciphertext, sino tres partes concatenadas:

```
[ nonce: 16 bytes ] + [ tag: 16 bytes ] + [ ciphertext: N bytes ]
```

- **nonce**: valor aleatorio único para cada cifrado (no secreto, pero imprescindible para descifrar).
- **tag**: huella de autenticación. Si el archivo es alterado, este tag no coincidirá y el descifrado fallará.
- **ciphertext**: los datos cifrados, del mismo tamaño que el texto original.

---

## Flujo del sistema

![Diagrama de flujo AES](http://www.plantuml.com/plantuml/proxy?cache=no&src=https://raw.githubusercontent.com/sebastianmct/CryptoSC-BlockChain/main/diagrama.puml)

## Bibliografía

- Arboledas Brihuega, D. (2017). *Criptografía sin secretos con Python*. RA-MA Editorial.
- PyCryptodome Documentation: https://pycryptodome.readthedocs.io/en/latest/
