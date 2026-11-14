"""Firma Ed25519 (RFC 8032) en Python puro, solo librería estándar.

La usa el agente para verificar que un plan de parcheo lo firmó la clave del aprobador que se
fijó al instalarlo (docs/plan-parcheo.md, sección 3). `radar/seguridad/ed25519.py` es copia
exacta de este archivo (una prueba lo compara): el servidor la usa para no guardar planes con
firmas inválidas, pero quien decide es el agente.

No es de tiempo constante: sirve para verificar firmas públicas y para las pruebas. Las claves
privadas reales se usan en el navegador (WebCrypto), no aquí.
"""

from __future__ import annotations

import hashlib

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_RAIZ_MENOS_UNO = pow(2, (_P - 1) // 4, _P)

LARGO_CLAVE = 32
LARGO_FIRMA = 64


def _inverso(x: int) -> int:
    return pow(x, _P - 2, _P)


def _recuperar_x(y: int, signo: int) -> int | None:
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inverso(_D * y * y + 1) % _P
    if x2 == 0:
        return None if signo else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _RAIZ_MENOS_UNO % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != signo:
        x = _P - x
    return x


# Puntos en coordenadas extendidas (X, Y, Z, T), con x = X/Z, y = Y/Z, x*y = T/Z.
_GY = 4 * _inverso(5) % _P
_GX = _recuperar_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)
_NEUTRO = (0, 1, 1, 0)


def _sumar(a: tuple, b: tuple) -> tuple:
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    pa = (y1 - x1) * (y2 - x2) % _P
    pb = (y1 + x1) * (y2 + x2) % _P
    pc = 2 * t1 * t2 * _D % _P
    pd = 2 * z1 * z2 % _P
    e, f, g, h = pb - pa, pd - pc, pd + pc, pb + pa
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _multiplicar(escalar: int, punto: tuple) -> tuple:
    resultado = _NEUTRO
    while escalar > 0:
        if escalar & 1:
            resultado = _sumar(resultado, punto)
        punto = _sumar(punto, punto)
        escalar >>= 1
    return resultado


def _iguales(a: tuple, b: tuple) -> bool:
    x1, y1, z1, _ = a
    x2, y2, z2, _ = b
    return (x1 * z2 - x2 * z1) % _P == 0 and (y1 * z2 - y2 * z1) % _P == 0


def _comprimir(punto: tuple) -> bytes:
    x, y, z, _ = punto
    zi = _inverso(z)
    x, y = x * zi % _P, y * zi % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _descomprimir(datos: bytes) -> tuple | None:
    if len(datos) != 32:
        return None
    y = int.from_bytes(datos, "little")
    signo = y >> 255
    y &= (1 << 255) - 1
    x = _recuperar_x(y, signo)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _h(*partes: bytes) -> int:
    return int.from_bytes(hashlib.sha512(b"".join(partes)).digest(), "little")


def _escalar_secreto(secreto: bytes) -> tuple[int, bytes]:
    digesto = hashlib.sha512(secreto).digest()
    a = int.from_bytes(digesto[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, digesto[32:]


def clave_publica(secreto: bytes) -> bytes:
    """Clave pública de una semilla de 32 bytes (solo para pruebas y herramientas)."""
    if len(secreto) != LARGO_CLAVE:
        raise ValueError("La semilla Ed25519 mide 32 bytes")
    a, _ = _escalar_secreto(secreto)
    return _comprimir(_multiplicar(a, _G))


def firmar(secreto: bytes, mensaje: bytes) -> bytes:
    """Firma `mensaje` con la semilla de 32 bytes (pruebas y herramientas de línea de órdenes)."""
    if len(secreto) != LARGO_CLAVE:
        raise ValueError("La semilla Ed25519 mide 32 bytes")
    a, prefijo = _escalar_secreto(secreto)
    publica = _comprimir(_multiplicar(a, _G))
    r = _h(prefijo, mensaje) % _L
    punto_r = _comprimir(_multiplicar(r, _G))
    k = _h(punto_r, publica, mensaje) % _L
    s = (r + k * a) % _L
    return punto_r + int.to_bytes(s, 32, "little")


def verificar(publica: bytes, mensaje: bytes, firma: bytes) -> bool:
    """True solo si `firma` es una firma Ed25519 válida de `mensaje` con `publica`.

    Nunca lanza: cualquier entrada mal formada es una firma inválida.
    """
    if not isinstance(publica, bytes | bytearray) or not isinstance(firma, bytes | bytearray):
        return False
    if len(publica) != LARGO_CLAVE or len(firma) != LARGO_FIRMA:
        return False
    punto_a = _descomprimir(bytes(publica))
    punto_r = _descomprimir(bytes(firma[:32]))
    if punto_a is None or punto_r is None:
        return False
    s = int.from_bytes(firma[32:], "little")
    if s >= _L:
        return False
    k = _h(bytes(firma[:32]), bytes(publica), mensaje) % _L
    return _iguales(_multiplicar(s, _G), _sumar(punto_r, _multiplicar(k, punto_a)))


def huella(publica: bytes) -> str:
    """Huella corta de una clave pública para mostrarla a las personas (SHA-256, 16 hex)."""
    return hashlib.sha256(publica).hexdigest()[:16]
