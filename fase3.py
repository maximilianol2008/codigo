import base64

from typing import Optional

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad

from fase1 import cargar_llaves, construir_identidad


SEP = "=" * 72


# Helpers

def _cargar_miembro(nombre: str, rol: str) -> dict:
    """
    Carga las llaves del miembro.
    Si no existen, las genera.
    """

    try:
        llaves = cargar_llaves(rol)

        print(f"[OK] Llaves cargadas para {nombre}")

        return llaves

    except FileNotFoundError:

        print(f"[INFO] Generando llaves para {nombre}")

        identidad = construir_identidad(nombre, rol)

        return {
            "key1_priv": identidad["key1"]["objeto"],
            "key1_pub": identidad["key1"]["objeto"].public_key(),

            "key2_priv": identidad["key2"]["objeto"],
            "key2_pub": identidad["key2"]["objeto"].public_key(),
        }


# Firma digital

def firmar_mensaje(
    mensaje: str,
    key_priv: RSA.RsaKey
) -> bytes:
    """
    Firma el mensaje usando RSA.
    """

    h = SHA256.new(mensaje.encode("utf-8"))

    return pkcs1_15.new(key_priv).sign(h)


def verificar_firma(
    mensaje: str,
    firma: bytes,
    key_pub: RSA.RsaKey
) -> bool:
    """
    Verifica la firma del mensaje.
    """

    h = SHA256.new(mensaje.encode("utf-8"))

    try:
        pkcs1_15.new(key_pub).verify(h, firma)

        return True

    except ValueError:

        return False


# Cifrado híbrido

def cifrar_mensaje(
    mensaje: str,
    key_pub_receptor: RSA.RsaKey
):
    """
    Cifra el mensaje usando AES + RSA.
    """

    # Session key AES
    session_key = get_random_bytes(16)

    # Cifrado AES
    cipher_aes = AES.new(session_key, AES.MODE_CBC)

    cuerpo = cipher_aes.encrypt(
        pad(
            mensaje.encode("utf-8"),
            AES.block_size
        )
    )

    # Protegemos la session key con RSA
    cipher_rsa = PKCS1_OAEP.new(key_pub_receptor)

    enc_session = cipher_rsa.encrypt(session_key)

    return (
        enc_session,
        cipher_aes.iv,
        cuerpo
    )


def descifrar_mensaje(
    enc_session,
    iv,
    cuerpo,
    key_priv_receptor
):
    """
    Descifra el mensaje.
    """

    # Recuperamos la session key
    cipher_rsa = PKCS1_OAEP.new(key_priv_receptor)

    session_key = cipher_rsa.decrypt(enc_session)

    # Descifrado AES
    cipher_aes = AES.new(
        session_key,
        AES.MODE_CBC,
        iv=iv
    )

    mensaje = unpad(
        cipher_aes.decrypt(cuerpo),
        AES.block_size
    )

    return mensaje.decode("utf-8")


# Envío

def enviar_mensaje(
    mensaje: str,
    nombre_emisor: str,
    llaves_emisor: dict,
    llaves_receptor: dict,
) -> dict:
    """
    Firma y cifra el mensaje.
    """

    print("\n[1] Firmando mensaje con RSA...")

    firma = firmar_mensaje(
        mensaje,
        llaves_emisor["key2_priv"]
    )

    print("[2] Generando session key AES...")

    print("[3] Cifrando mensaje con AES...")

    enc_session, iv, cuerpo = cifrar_mensaje(
        mensaje,
        llaves_receptor["key1_pub"]
    )

    print("[4] Protegiendo session key con RSA-OAEP...")

    print("[5] Armando paquete final...")

    return {

        "emisor": nombre_emisor,

        "enc_session":
            base64.b64encode(enc_session).decode(),

        "iv":
            base64.b64encode(iv).decode(),

        "cuerpo":
            base64.b64encode(cuerpo).decode(),

        "firma":
            base64.b64encode(firma).decode(),

        "pub_firma":
            llaves_emisor["key2_pub"]
            .export_key()
            .decode(),
    }

# Recepción

def recibir_mensaje(
    paquete: dict,
    llaves_receptor: dict,
) -> tuple[Optional[str], bool, str]:
    """
    Descifra y verifica el mensaje.
    """

    try:

        print("[6] Descifrando session key con RSA...")

        print("[7] Descifrando mensaje con AES...")

        mensaje = descifrar_mensaje(

            base64.b64decode(paquete["enc_session"]),

            base64.b64decode(paquete["iv"]),

            base64.b64decode(paquete["cuerpo"]),

            llaves_receptor["key1_priv"]
        )

    except Exception:

        return (
            None,
            False,
            "SABOTAJE DETECTADO"
        )

    print("[8] Verificando firma digital...")

    firma = base64.b64decode(
        paquete["firma"]
    )

    pub_emisor = RSA.import_key(
        paquete["pub_firma"]
    )

    firma_valida = verificar_firma(
        mensaje,
        firma,
        pub_emisor
    )

    if firma_valida:

        return (
            mensaje,
            True,
            "Firma valida"
        )

    else:

        return (
            mensaje,
            False,
            "SABOTAJE DETECTADO"
        )

# Simulación

def simular_intercambio(
    nombre_emisor: str,
    llaves_emisor: dict,
    nombre_receptor: str,
    llaves_receptor: dict,
    mensaje: str,
    sabotaje: bool = False,
):
    """
    Simula un intercambio completo.
    """

    paquete = enviar_mensaje(
        mensaje,
        nombre_emisor,
        llaves_emisor,
        llaves_receptor
    )

    # Alteramos el mensaje
    if sabotaje:

        cuerpo = base64.b64decode(
            paquete["cuerpo"]
        )

        cuerpo_alterado = (
            cuerpo[:-1] +
            bytes([cuerpo[-1] ^ 0xFF])
        )

        paquete["cuerpo"] = (
            base64.b64encode(cuerpo_alterado)
            .decode()
        )

    mensaje_recibido, valida, estado = recibir_mensaje(
        paquete,
        llaves_receptor
    )

    print("\n" + SEP)

    print(f"ENVIO: {nombre_emisor} → {nombre_receptor}")

    print(f"Mensaje original: {mensaje}")

    if mensaje_recibido:
        print(f"Mensaje recibido: {mensaje_recibido}")

    print(f"Estado: {estado}")

    print(SEP)


# Main

if __name__ == "__main__":

    print("FASE 3 - LA MISIVA DEL TRAIDOR")

    consejo_datos = [
        ("Santiago Cifuentes", "202373089-0"),
        ("Lucas Roilar", "202273058-7"),
        ("Maximiliano Sanchez", "202273132-k"),
    ]

    consejo = {}

    # Cargamos las llaves
    for nombre, rol in consejo_datos:

        consejo[nombre] = _cargar_miembro(
            nombre,
            rol
        )

    alfa = "Santiago Cifuentes"
    beta = "Lucas Roilar"
    gamma = "Maximiliano Sanchez"

    # Intercambio normal
    simular_intercambio(
        nombre_emisor=alfa,
        llaves_emisor=consejo[alfa],

        nombre_receptor=beta,
        llaves_receptor=consejo[beta],

        mensaje="Activar protocolo Delta"
    )

    # Otro intercambio válido
    simular_intercambio(
        nombre_emisor=gamma,
        llaves_emisor=consejo[gamma],

        nombre_receptor=alfa,
        llaves_receptor=consejo[alfa],

        mensaje="Ruta segura confirmada"
    )

    # Intercambio con sabotaje
    simular_intercambio(
        nombre_emisor=beta,
        llaves_emisor=consejo[beta],

        nombre_receptor=gamma,
        llaves_receptor=consejo[gamma],

        mensaje="Confirmado",

        sabotaje=True
    )