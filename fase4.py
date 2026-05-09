

import os
import random

# primo mayor a cualquier clave de 256 bits
PRIME = 2**257 - 93

# Secreto (clave de 256 bits)
SECRET = 0xA3F1C2D7E8B94F6A1D2E3C4B5A6978F0E1D2C3B4A5968778899AABBCCDDEEFF


# =============================================================================
# Nombre función: _eval_polynomial
# Parámetros:
#   - coefficients (list[int]): coeficientes [S, a1, a2] donde índice = potencia
#   - x (int): punto donde se evalúa el polinomio
#   - p (int): primo del cuerpo finito
# Descripción: Evalúa el polinomio en el punto x usando el método de Horner,
#              operando en aritmética modular sobre Z_p.
# =============================================================================
def _eval_polynomial(coefficients, x, p):
    result = 0
    for coeff in reversed(coefficients):
        result = (result * x + coeff) % p
    return result


# =============================================================================
# Función: generate_shares
# Parámetros:
#   - secret (int): el secreto S a fragmentar
#   - n (int): número total de shares a generar
#   - k (int): umbral mínimo de shares para reconstruir
#   - p (int): primo del cuerpo finito
# Descripción: Construye un polinomio aleatorio de grado k-1 con P(0) = secret,
#              lo evalúa en x = 1..n y retorna los n shares como tuplas (x, y).
# =============================================================================
def generate_shares(secret, n, k, p):
    coefficients = [secret] + [random.randint(1, p - 1) for _ in range(k - 1)]
    shares = [(x, _eval_polynomial(coefficients, x, p)) for x in range(1, n + 1)]
    return shares


# =============================================================================
# Nombre función: lagrange_interpolation
# Parámetros:
#   - shares (list[tuple]): subconjunto de shares [(x1,y1), (x2,y2), ...]
#   - p (int): primo del cuerpo finito
# Descripción: Reconstruye P(0) = S usando interpolación de Lagrange en Z_p.
#              Las divisiones se realizan como multiplicaciones por el inverso
#              modular, calculado con el pequeño teorema de Fermat.
# =============================================================================
def lagrange_interpolation(shares, p):
    secret = 0
    k = len(shares)

    for i in range(k):
        xi, yi = shares[i]
        numerator = 1
        denominator = 1

        for j in range(k):
            if i == j:
                continue
            xj, _ = shares[j]
            numerator = (numerator * (-xj)) % p
            denominator = (denominator * (xi - xj)) % p
        lagrange_coeff = (numerator * pow(denominator, p - 2, p)) % p
        secret = (secret + yi * lagrange_coeff) % p

    return secret


# =============================================================================
# Nombre función: recover_secret
# Parámetros:
#   - shares (list[tuple]): subconjunto de shares a utilizar
#   - p (int): primo del cuerpo finito
#   - original_secret (int): secreto original para verificar reconstrucción
# Descripción: Intenta reconstruir el secreto a partir de los shares entregados.
#              Imprime el resultado e indica si la reconstrucción fue exitosa
#              o si se detectó un sabotaje (reconstrucción incorrecta).
# =============================================================================
def recover_secret(shares, p, original_secret):
    recovered = lagrange_interpolation(shares, p)
    indices = [s[0] for s in shares]

    print(f"  Shares utilizados: {indices}")
    print(f"  Secreto recuperado: {hex(recovered)}")

    if recovered == original_secret:
        print("  Estado: RECONSTRUCCIÓN EXITOSA")
    else:
        print("  Estado: El secreto no pudo ser recuperado")


# =============================================================================
# Nombre función: save_shares
# Parámetros:
#   - shares (list[tuple]): lista completa de shares generados
#   - filename (str): nombre del archivo de salida
# Descripción: Guarda los shares generados en un archivo .txt, con cada share
#              en formato legible (índice y valor en hexadecimal).
# =============================================================================
def save_shares(shares, filename="shares.txt"):
    with open(filename, "w") as f:
        f.write("=== SHARES GENERADOS — OPERACIÓN CLAVES DE GUERRA ===\n\n")
        for x, y in shares:
            f.write(f"Share {x}: {hex(y)}\n")
    print(f"  Shares guardados en '{filename}'")



def main():
    print("=" * 60)
    print("   FASE IV")
    print("=" * 60)

    N = 4   # Número total de miembros del consejo
    K = 3   # Umbral mínimo para reconstruir

    print(f"\n[CONFIG] Esquema ({K} de {N}) sobre primo p = 2^257 - 93")
    print(f"\n[SECRETO] {hex(SECRET)}")

    print("\n[1] GENERANDO SHARES...")
    shares = generate_shares(SECRET, N, K, PRIME)
    for x, y in shares:
        print(f"  Miembro {x}: {hex(y)}")

    save_shares(shares)

    print("\n[2] PRUEBAS DE RECONSTRUCCIÓN")
    print("\n--- CASO ÉXITO: 3 shares (mínimo requerido) ---")
    recover_secret(shares[:3], PRIME, SECRET)

    print("\n--- CASO ÉXITO: 4 shares (todos los miembros) ---")
    recover_secret(shares, PRIME, SECRET)

    print("\n--- CASO ÉXITO: 3 shares alternos (1, 3, 4) ---")
    recover_secret([shares[0], shares[2], shares[3]], PRIME, SECRET)

    # Casos de fallo
  
    print("\n--- CASO FALLO: 2 shares (bajo el umbral) ---")
    recover_secret(shares[:2], PRIME, SECRET)

    print("\n--- CASO FALLO: 1 share (bajo el umbral) ---")
    recover_secret(shares[:1], PRIME, SECRET)

    print("\n" + "=" * 60)
    print("   FIN DE LA SIMULACIÓN")
    print("=" * 60)


if __name__ == "__main__":
    main()
