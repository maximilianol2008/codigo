"""
Operacion "Claves de Guerra" - Fase 1: Identidad Criptografica.

Decisiones de diseño:
    - KDF principal: PBKDF2-HMAC-SHA256 con 200.000 iteraciones
    - SALT determinístico por miembro: deriva del ROL (que es único por estudiante) para que el mismo miembro pueda regenerar sus llaves en
      cualquier terminal (requisito del enunciado), pero dos miembros con nombres similares obtengan SALTs distintos (efecto avalancha inverso).
    - Generación RSA deterministica: se construye un PRNG en modo contador basado en SHA-256 sobre el seed derivado, y se inyecta como "randfunc"
      al generador RSA de PyCryptodome.
    - Normalización de ROL: variantes cosméticas en como el usuario tipea su ROL (mayusculas/minusculas de la K, espacios, puntos de millares)
      se reducen a una forma canónica antes del uso criptográfico.

Instalar pip install pycryptodome
"""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Callable

from Crypto.PublicKey import RSA


#-----------------------
# Constantes operativas del Consejo
DOMAIN_SEPARATOR = b"GOLGOTHA-CONSEJO-2026::v1"
SALT_DOMAIN = DOMAIN_SEPARATOR + b"::SALT"
SEED_DOMAIN = DOMAIN_SEPARATOR + b"::SEED"
RNG_DOMAIN  = DOMAIN_SEPARATOR + b"::RNG"

PBKDF2_ITERATIONS = 200_000          
SEED_LEN = 64                         # 512 bits de material derivado
SALT_LEN = 16                         # 128 bits de salt
RSA_BITS = 2048                       # tamaño de las llaves RSA de 2048 bits

DIRECTORIO_LLAVES = Path("claves")    # carpeta de salida con llaves PEM

#Etiquetas estandar de cada par; las fases 2–4 importan estas constantes
ETIQUETA_CIFRADO = b"KEY1::CIFRADO"
ETIQUETA_FIRMA   = b"KEY2::FIRMA"

#Regex de ROL USM: exactamente 9 dígitos, guion, digito 0-9 o 'K'.
_REGEX_ROL = re.compile(r"\d{9}-[0-9K]")


#------------------------
# Funciones del modulo
def normalizar_rol(rol: str) -> str:
    """
    Nombre función: normalizar_rol
    Parámetros:
        rol (str): ROL del miembro tal como lo tipeó el usuario
    Descripción: Devuelve una forma canónica del ROL para que el mismo miembro siempre derive las mismas llaves,
          sin importar variaciones en como lo escribe. Aplica:
          - strip() de espacios al inicio y final.
          - elimina puntos
          - upper() del digito verificador (la 'K' es el caso tipico: en el ROL el verificador lo tomaremos como que se escribe en mayuscula).
          - valida formato basico: exactamente 9 digitos, guion y digito 0-9 o K.
        Sin esta normalizacion, "202273058-K" y "202273058-k" producirian
        identidades criptograficas distintas, rompiendo la garantia de "regenerar en cualquier terminal" del enunciado.
    """
    if rol is None:
        raise ValueError("El ROL no puede ser None")
    candidato = rol.strip().replace(".", "").upper()
    if not _REGEX_ROL.fullmatch(candidato):
        raise ValueError(
            f"ROL '{rol}' no tiene formato valido. "
            f"Esperado: 9 digitos, guion, digito o 'K' (ej: '202273058-7')."
        )
    return candidato


def derivar_salt(rol: str) -> bytes:
    """
    Nombre función: derivar_salt
    Parámetros:
        rol (str): ROL unico del miembro del Consejo (ej: "202273058-7").
    Descripción: Deriva un SALT de 16 bytes a partir del ROL, usando SHA-256. 
        Primero normaliza el ROL para que formatos distintos del mismo ROL produzcan el mismo SALT. 
        Como cada miembro tiene un ROL unico, cada SALT sera distinto, evitando que nombres similares
        generen llaves parecidas.
    """
    rol_norm = normalizar_rol(rol)
    return hashlib.sha256(SALT_DOMAIN + b"::" + rol_norm.encode("utf-8")).digest()[:SALT_LEN]
# Cada ROL produce un SALT distinto


def derivar_seed_pbkdf2(nombre: str, rol: str, salt: bytes, iteraciones: int = PBKDF2_ITERATIONS) -> bytes:
    """
    Nombre función: derivar_seed_pbkdf2
    Parámetros:
        nombre (str): nombre completo del miembro.
        rol (str): ROL del miembro.
        salt (bytes): SALT generado por "derivar_salt"
        iteraciones (int): cantidad de iteraciones del KDF (default 200_000).
    Descripción: Aplica PBKDF2-HMAC-SHA256 usando nombre y ROL como contraseña, con el SALT entregado
        para producir 64 bytes de material clave.
        Las 200.000 iteraciones hacen que un atacante tarde mucho en probar cada intento, dificultando ataques de
        fuerza bruta o diccionario.
    """
    rol_norm = normalizar_rol(rol)
    password = SEED_DOMAIN + b"::" + (nombre.strip() + "::" + rol_norm).encode("utf-8") # construye el password que va a entrar al KDF
    return hashlib.pbkdf2_hmac(         # PBKDF2 aplica sha256 en un bucle de 200.000 iteraciones(constante declarada en el inicio)
        hash_name="sha256",
        password=password,
        salt=salt,
        iterations=iteraciones,         # El resultado son 64 bytes que no revelan nada sobre el nombre o el rol original
        dklen=SEED_LEN,
    )


def crear_prng_deterministico(seed: bytes) -> Callable[[int], bytes]: #Se pide que las llaves sean regenerables 
    """
    Nombre función: crear_prng_deterministico
    Parámetros:
        seed (bytes): material clave que actua como semilla del PRNG.
    Descripción: Crea un generador de bytes pseudoaleatorios que siempre
        produce la misma secuencia para la misma semilla. Funciona
        hasheando la semilla junto a un contador que sube en cada bloque,
        lo que permite entregarle a RSA una fuente de aleatoriedad
        reproducible para regenerar las mismas llaves en cualquier terminal.
    """
    estado = {"contador": 0, "buffer": b""} #diccionario con "contador" que lleva la cuenta de bloques sha-256 generados
                                                #buffer, almacen temporal de bytes ya generados pero no entregados
    def randfunc(n: int) -> bytes:
        """
        Nombre función: randfunc
        Parámetros:
            n (int): cantidad de bytes pseudoaleatorios solicitados.
        Descripción: Entrega exactamente n bytes del buffer interno.
            Si el buffer no tiene suficientes, genera nuevos bloques de
            32 bytes hasheando la semilla con el contador actual hasta tener suficiente. 
            Los bytes sobrantes se guardan para el siguiente llamado sin desperdiciarlos.
        """    
        while len(estado["buffer"]) < n:    
            bloque = hashlib.sha256(RNG_DOMAIN + b"::" + seed + estado["contador"].to_bytes(8, "big")).digest() #generar un bloque de 32 bytes
            estado["buffer"] += bloque  #agrega los 32 bytes al buffer y avanza el contador
            estado["contador"] += 1
        salida, estado["buffer"] = estado["buffer"][:n], estado["buffer"][n:]   #corta el buffer, entrega los n bytes primeros, y guarda el resto para el proximo llamado
        return salida

    return randfunc


def generar_par_rsa(seed: bytes, etiqueta: bytes, bits: int = RSA_BITS) -> RSA.RsaKey:  #generacion par de llaves
    """
    Nombre función: generar_par_rsa
    Parámetros:
        seed (bytes): semilla maestra derivada del KDF.
        etiqueta (bytes): etiqueta para diferenciar pares (ej: b"KEY1::CIFRADO").
        bits (int): tamaño en bits del modulo RSA (default 2048).
    Descripción: Genera un par de llaves RSA a partir de la semilla maestra y una etiqueta.
        La etiqueta permite crear multiples pares desde el mismo seed sin que colisionen, 
        ya que cada par usa su propio seed derivado como SHA-256(seed || etiqueta). 
        Al pasarle el PRNG deterministico a RSA, las llaves siempre son las mismas para los
        mismos inputs.
    """
    seed_par = hashlib.sha256(seed + b"::" + etiqueta).digest()  #con la etiqueta, cada par es criptograficamente independiente 
    return RSA.generate(bits, randfunc=crear_prng_deterministico(seed_par)) #como el prng que se hizo antes es deterministico, 
                                                                            #RSA siempre generara la misma llave para el mismo seed_par

def guardar_llave(llave: RSA.RsaKey, ruta_priv: Path, ruta_pub: Path) -> None: #Toma un par de llaves RSA y las guarda en disco en dos archivos separados:
                                                                                #uno para la llave privada y otro para la publica, ambos en formato PEM.
    """                                                                         
    Nombre función: guardar_llave
    Parámetros:
        llave (RSA.RsaKey): par de llaves RSA a serializar.
        ruta_priv (Path): destino del archivo PEM con la llave privada.
        ruta_pub (Path): destino del archivo PEM con la llave publica.
    Descripción: Guarda el par de llaves RSA en dos archivos PEM separados uno para la llave privada y otro para la publica. 
        La llave privada se guarda con permisos 0600 para que solo el dueño pueda leerla.
    """
    ruta_priv.parent.mkdir(parents=True, exist_ok=True) #crea la carpeta si no existe
    ruta_priv.write_bytes(llave.export_key(format="PEM", pkcs=8))   #guarda la llave privada, export key es para serializar la llave al formato PEM
    ruta_pub.write_bytes(llave.public_key().export_key(format="PEM"))   #extrae la parte publica del par y serializa en formato SPKI
    try:        #permisos de archivo
        os.chmod(ruta_priv, 0o600)
    except (OSError, NotImplementedError):
        pass  


def construir_identidad(nombre: str, rol: str, directorio: Path = DIRECTORIO_LLAVES) -> dict:
    """
    Nombre función: construir_identidad
    Parámetros:
        nombre (str): nombre completo del miembro.
        rol (str): ROL del miembro.
        directorio (Path): carpeta donde guardar las llaves.
    Descripción: Ejecuta el pipeline completo de la Fase I para un miembro.
        Normaliza el ROL, genera el SALT, deriva la semilla maestra con PBKDF2 
        y genera dos pares RSA-2048 (uno para cifrar y otro para firmar) que guarda en disco. 
        Retorna un diccionario con todos los metadatos y objetos generados.
    """
    rol = normalizar_rol(rol)  #forma canonica usada de aqui en adelante
    salt = derivar_salt(rol)
    seed = derivar_seed_pbkdf2(nombre, rol, salt)   #para producir la semilla maestra seed. de este valor se derivan las llaves RSA

    par1 = generar_par_rsa(seed, etiqueta=ETIQUETA_CIFRADO)     #misma seed pero con etiquetas diferentes para generar 2 pares independientes
    par2 = generar_par_rsa(seed, etiqueta=ETIQUETA_FIRMA)

    base = directorio / _sanitizar_nombre(rol)      #convierte el rol en un nombre de carpeta seguro
    ruta_priv1 = base / "key1_cifrado_priv.pem"
    ruta_pub1  = base / "key1_cifrado_pub.pem"
    ruta_priv2 = base / "key2_firma_priv.pem"
    ruta_pub2  = base / "key2_firma_pub.pem"

    guardar_llave(par1, ruta_priv1, ruta_pub1)  
    guardar_llave(par2, ruta_priv2, ruta_pub2)

    return {
        "miembro": {"nombre": nombre, "rol": rol},
        "kdf": f"PBKDF2-HMAC-SHA256 (iter={PBKDF2_ITERATIONS})",
        "salt_hex": salt.hex(),
        "seed_huella_sha256": hashlib.sha256(seed).hexdigest(), #se guarda el hash de la seed
        "key1": {
            "objeto": par1,
            "fingerprint": _fingerprint(par1),
            "priv_pem": str(ruta_priv1),
            "pub_pem":  str(ruta_pub1),
        },
        "key2": {
            "objeto": par2,
            "fingerprint": _fingerprint(par2),
            "priv_pem": str(ruta_priv2),
            "pub_pem":  str(ruta_pub2),
        },
    }


def cargar_llaves(rol: str, directorio: Path = DIRECTORIO_LLAVES) -> dict:
    """
    Nombre función: cargar_llaves
    Parámetros:
        rol (str): ROL del miembro cuyas llaves se quieren cargar.
        directorio (Path): carpeta base donde residen los PEM.
    Descripción: Carga desde disco los cuatro archivos PEM de un miembro
        (llave privada y publica de cifrado, llave privada y publica de firma) a partir de su ROL.
        Es la funcion que usan las fases siguientes para acceder a las llaves sin tener que regenerarlas.
    """
    rol = normalizar_rol(rol)
    base = directorio / _sanitizar_nombre(rol)
    if not base.is_dir():
        raise FileNotFoundError(
            f"No existen llaves para ROL '{rol}' en {base}. "
            f"Ejecute primero construir_identidad(...)."
        )
    return {
        "key1_priv": RSA.import_key((base / "key1_cifrado_priv.pem").read_bytes()),
        "key1_pub":  RSA.import_key((base / "key1_cifrado_pub.pem").read_bytes()),
        "key2_priv": RSA.import_key((base / "key2_firma_priv.pem").read_bytes()),
        "key2_pub":  RSA.import_key((base / "key2_firma_pub.pem").read_bytes()),
    }


def _fingerprint(llave: RSA.RsaKey) -> str:
    """
    Nombre función: _fingerprint
    Parámetros:
        llave (RSA.RsaKey): llave a identificar.
    Descripción: Genera una huella corta de 16 caracteres hex a partir de la llave pública. 
    Sirve para identificar llaves en logs sin exponer su contenido completo.
    """
    pub_der = llave.public_key().export_key(format="DER")
    return hashlib.sha256(pub_der).hexdigest()[:16]


def _sanitizar_nombre(s: str) -> str:
    """
    Nombre función: _sanitizar_nombre
    Parámetros:
        s (str): cadena potencialmente con caracteres no validos.
    Descripción: Convierte una cadena en un nombre de carpeta seguro
        reemplazando cualquier caracter no alfanumerico por un guion
        bajo, para que funcione en cualquier sistema operativo.
    """
    return "".join(c if c.isalnum() else "_" for c in s)


###
#Punto de entrada operativo: genera las identidades del Consejo
###
if __name__ == "__main__":
    consejo = [
        ("Santiago Cifuentes",   "202373089-0"),
        ("Lucas Roilar",    "202273058-7"),
        ("Maximiliano Sanchez",   "202273132-k"),
        ("Felipe Rebellaut",   "202023024-2"),
    ]

    print("=" * 72)
    print("FASE 1 — CONSTRUCCIÓN DE IDENTIDAD CRIPTOGRÁFICA DEL CONSEJO")
    print("=" * 72)

    for nombre, rol in consejo:
        ident = construir_identidad(nombre, rol)
        print(f"\n[+] Miembro: {nombre} (ROL {rol})")
        print(f"    KDF      : {ident['kdf']}")
        print(f"    SALT     : {ident['salt_hex']}")
        print(f"    Seed h.  : {ident['seed_huella_sha256'][:32]}…")
        print(f"    KEY1 fp  : {ident['key1']['fingerprint']}  -> {ident['key1']['priv_pem']}")
        print(f"    KEY2 fp  : {ident['key2']['fingerprint']}  -> {ident['key2']['priv_pem']}")

    print("\n" + "=" * 72)
    print(f"Llaves persistidas bajo: {DIRECTORIO_LLAVES.resolve()}")
    print("=" * 72)