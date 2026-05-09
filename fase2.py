"""
Operacion "Claves de Guerra" - Fase 2: Cifrado Híbrido y Análisis Visual.

Decisiones de diseño:
    - Cifrado Simétrico: AES-128 en modo CBC para asegurar confidencialidad y ocultar patrones.
    - Cifrado Asimétrico: RSA-OAEP con SHA-256 para cifrar la clave de sesión AES[cite: 2].
    - Análisis BMP: Se preserva la cabecera (54 bytes) para permitir la visualización del efecto de patrones en ECB[cite: 2].
"""

import os
from pathlib import Path
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from fase1 import cargar_llaves, normalizar_rol

# Configuración de archivos
ARCHIVO_ENTRADA = "silo_circuito.bmp"
DIR_SALIDA = Path("comunicaciones")
DIR_SALIDA.mkdir(exist_ok=True)

def cifrar_archivo_hibrido(ruta_archivo: str, rol_receptor: str):
    """
    Nombre función: cifrar_archivo_hibrido
    Parámetros: ruta_archivo (str), rol_receptor (str)
    Descripción: Implementa cifrado híbrido. Cifra el archivo con AES-128-CBC y 
    la llave AES con la llave pública RSA (KEY1) del receptor[cite: 2].
    """
    # 1. Preparar llaves y datos
    llaves_receptor = cargar_llaves(rol_receptor)
    pub_key_rsa = llaves_receptor["key1_pub"]
    
    with open(ruta_archivo, "rb") as f:
        datos_originales = f.read()

    # 2. Cifrado Simétrico (AES-128-CBC)
    session_key = get_random_bytes(16) # 128 bits[cite: 2]
    cipher_aes = AES.new(session_key, AES.MODE_CBC)
    datos_cifrados = cipher_aes.encrypt(pad(datos_originales, AES.block_size))

    # 3. Cifrado Asimétrico de la llave (RSA-OAEP)[cite: 2]
    cipher_rsa = PKCS1_OAEP.new(pub_key_rsa)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # 4. Guardar archivo compuesto (Llave Cifrada + IV + Datos Cifrados)
    nombre_salida = DIR_SALIDA / f"manifiesto_para_{normalizar_rol(rol_receptor)}.bin"
    with open(nombre_salida, "wb") as f:
        f.write(enc_session_key) # 256 bytes (RSA-2048)
        f.write(cipher_aes.iv)   # 16 bytes
        f.write(datos_cifrados)
    
    return nombre_salida

def analizar_visual_bmp(ruta_bmp: str):
    """
    Nombre función: analizar_visual_bmp
    Parámetros: ruta_bmp (str)
    Descripción: Genera dos versiones cifradas de una imagen preservando la cabecera 
    para comparar la fuga de información entre modos ECB y CBC[cite: 2].
    """
    with open(ruta_bmp, "rb") as f:
        header = f.read(54) # Cabecera estándar BMP
        data = f.read()

    key = get_random_bytes(16)
    
    # Modo ECB (Fuga de patrones)[cite: 2]
    cipher_ecb = AES.new(key, AES.MODE_ECB)
    data_ecb = cipher_ecb.encrypt(pad(data, AES.block_size))
    with open(DIR_SALIDA / "silo_cifrado_ECB.bmp", "wb") as f:
        f.write(header + data_ecb[:len(data)])

    # Modo CBC (Seguro)[cite: 2]
    cipher_cbc = AES.new(key, AES.MODE_CBC)
    data_cbc = cipher_cbc.encrypt(pad(data, AES.block_size))
    with open(DIR_SALIDA / "silo_cifrado_CBC.bmp", "wb") as f:
        f.write(header + data_cbc[:len(data)])

if __name__ == "__main__":
    print("=" * 72)
    print("FASE 2 — GUERRA DE SOMBRAS: CIFRADO HÍBRIDO")
    print("=" * 72)

    # Ejemplo: Santiago cifra el plano para Lucas
    rol_santiago = "202373089-0"
    rol_lucas = "202273058-7"

    if os.path.exists(ARCHIVO_ENTRADA):
        print(f"[+] Generando análisis visual ECB vs CBC...")
        analizar_visual_bmp(ARCHIVO_ENTRADA)
        print(f"    -> Archivos generados en {DIR_SALIDA}/")

        print(f"\n[+] Ejecutando protocolo de cifrado híbrido...")
        archivo_bin = cifrar_archivo_hibrido(ARCHIVO_ENTRADA, rol_lucas)
        print(f"    -> Manifiesto OMEGA generado: {archivo_bin}")
    else:
        print(f"[!] Error: No se encuentra el archivo {ARCHIVO_ENTRADA}")

    print("\n" + "=" * 72)