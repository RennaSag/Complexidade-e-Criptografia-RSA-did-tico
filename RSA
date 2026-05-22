"""
RSA Didático — Implementação educacional com análise de complexidade
=======================================================================
Disciplina: Teoria da Computação / Complexidade e Criptografia

Complexidade:
  Geração de chaves : O(k^4)  [k = bits do módulo]
  Cifração          : O(k^3)  [exponenciação modular]
  Decifração        : O(k^3)
  Fatoração tentativa: O(2^(k/2)) = O(sqrt(n))
  Fatoração GNFS    : O(exp(c * k^(1/3) * (log k)^(2/3)))
  Fatoração Shor    : O(k^3)  [computador quântico]

Referências:
  Rivest, Shamir, Adleman. CACM 21(2), 1978.
  Cormen et al. Introduction to Algorithms, 4ª ed., MIT Press, 2022.
"""

import math, time, random
from typing import Tuple, Optional


# Aritmética modular

def mdc(a: int, b: int) -> int:
    """Algoritmo de Euclides. Complexidade: O(log min(a,b))."""
    while b:
        a, b = b, a % b
    return a


def mdc_estendido(a: int, b: int) -> Tuple[int, int, int]:
    """
    Euclides Estendido.
    Retorna (g, x, y) tal que a*x + b*y = g = mdc(a,b).
    Complexidade: O(log min(a,b)).
    """
    if b == 0:
        return a, 1, 0
    g, x1, y1 = mdc_estendido(b, a % b)
    return g, y1, x1 - (a // b) * y1


def inverso_modular(a: int, m: int) -> Optional[int]:
    """
    Inverso multiplicativo de a módulo m.
    Existe sse mdc(a,m) = 1.
    Complexidade: O(log m).
    """
    g, x, _ = mdc_estendido(a, m)
    if g != 1:
        return None
    return x % m


def exp_modular(base: int, exp: int, mod: int) -> int:
    """
    Exponenciação modular por quadrados sucessivos.
    Calcula base^exp mod mod em O(log exp) multiplicações modulares.
    Cada multiplicação de k-bit: O(k^2) => total O(k^3).
    """
    resultado = 1
    base %= mod
    while exp > 0:
        if exp & 1:
            resultado = (resultado * base) % mod
        exp >>= 1
        base = (base * base) % mod
    return resultado


# Testes de primalidade

def miller_rabin(n: int, k: int = 20) -> bool:
    """
    Teste de primalidade probabilístico Miller-Rabin.
    Probabilidade de erro: < 4^(-k).
    Para k=20 e n < 2^1024: erro desprezível (~10^-12).
    Complexidade: O(k * log^2 n).
    """
    if n < 2: return False
    if n in (2, 3): return True
    if n % 2 == 0: return False

    # Decompor n-1 = 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = exp_modular(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


def gerar_primo(bits: int) -> int:
    """
    Gera um primo aleatório de exatamente `bits` bits.
    Pelo Teorema dos Números Primos: densidade de primos perto de 2^bits
    é Θ(1/bits), logo O(bits) tentativas em média.
    """
    while True:
        n = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if miller_rabin(n):
            return n


# RSA 

class ChavePublicaRSA:
    def __init__(self, e: int, n: int):
        self.e = e
        self.n = n
        self.bits = n.bit_length()

    def __repr__(self):
        return f"ChavePublicaRSA(e={self.e}, bits={self.bits})"


class ChavePrivadaRSA:
    def __init__(self, d: int, n: int, p: int = 0, q: int = 0):
        self.d = d
        self.n = n
        self.p = p
        self.q = q

    def __repr__(self):
        return f"ChavePrivadaRSA(d=<oculto>, n_bits={self.n.bit_length()})"


def gerar_chaves_rsa(bits: int = 512) -> Tuple[ChavePublicaRSA, ChavePrivadaRSA]:
    """
    Geração de par de chaves RSA de `bits` bits.

    Passos:
      1. p, q ← GerarPrimo(bits/2)  distintos
      2. n ← p*q
      3. φ(n) ← (p-1)*(q-1)
      4. e ← 65537 (primo de Fermat F4, padrão industrial)
      5. d ← e^{-1} mod φ(n)

    Segurança: baseia-se na dificuldade de fatorar n.
    """
    meio = bits // 2
    p = gerar_primo(meio)
    q = gerar_primo(meio)
    while q == p:
        q = gerar_primo(meio)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    if mdc(e, phi) != 1:
        e = 3
        while mdc(e, phi) != 1:
            e += 2

    d = inverso_modular(e, phi)
    return ChavePublicaRSA(e, n), ChavePrivadaRSA(d, n, p, q)


def cifrar_rsa(m: int, pub: ChavePublicaRSA) -> int:
    """c = m^e mod n.  Requer 0 < m < n.  O(k^3)."""
    if not (0 < m < pub.n):
        raise ValueError(f"Mensagem fora do intervalo (0, {pub.n})")
    return exp_modular(m, pub.e, pub.n)


def decifrar_rsa(c: int, priv: ChavePrivadaRSA) -> int:
    """m = c^d mod n.  O(k^3)."""
    return exp_modular(c, priv.d, priv.n)


# Ataque por fatoração

def fatorar_tentativa(n: int, verbose: bool = True) -> Tuple[Optional[int], int, float]:
    """
    Fatoração por divisão tentativa.
    Complexidade: O(sqrt(n)) = O(2^(k/2))  onde k = bits de n.
    Evidencia por que RSA com módulo pequeno é inseguro.
    """
    t0 = time.perf_counter()
    tentativas = 0

    if n % 2 == 0:
        return 2, 1, time.perf_counter() - t0

    i = 3
    limite = int(math.isqrt(n)) + 1
    while i <= limite:
        tentativas += 1
        if n % i == 0:
            if verbose:
                print(f"  n={n} = {i} × {n//i}  ({tentativas} divisões, "
                      f"{(time.perf_counter()-t0)*1000:.3f} ms)")
            return i, tentativas, time.perf_counter() - t0
        i += 2

    if verbose:
        print(f"  n={n} é primo  ({tentativas} testes, {(time.perf_counter()-t0)*1000:.3f} ms)")
    return None, tentativas, time.perf_counter() - t0


# Demonstrações

def demo_rsa_didatico():
    """RSA com primos pequenos para máxima clareza."""
    print("\n" + "═"*60)
    print("RSA DIDÁTICO — PASSO A PASSO")
    print("═"*60)

    p, q = 61, 53
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 17
    d = inverso_modular(e, phi)
    m = 65  # 'A' ASCII

    print(f"\n[GERAÇÃO DE CHAVES]")
    print(f"  p={p}, q={q}  (secretos)")
    print(f"  n = {p}×{q} = {n}  (público)")
    print(f"  φ(n) = {phi}  (secreto)")
    print(f"  e={e}  mdc({e},{phi})={mdc(e,phi)}  (público)")
    print(f"  d={d}  e·d mod φ = {(e*d)%phi}  (secreto)")

    c = cifrar_rsa(m, ChavePublicaRSA(e, n))
    m2 = decifrar_rsa(c, ChavePrivadaRSA(d, n))

    print(f"\n[CIFRAÇÃO]   m={m} → c={m}^{e} mod {n} = {c}")
    print(f"[DECIFRAÇÃO] c={c} → m={c}^{d} mod {n} = {m2}  {'✓' if m2==m else '✗'}")

    print(f"\n[ATAQUE POR FATORAÇÃO]")
    fatorar_tentativa(n)
    print(f"  → n pequeno: trivialmente quebrável")
    print(f"  → n de 2048 bits: ~2^1024 ≈ 10^308 operações (infactível)")


def analise_complexidade_fatoracao():
    """Experimento empírico: divisões tentadas vs tamanho de n."""
    print("\n" + "═"*60)
    print("ANÁLISE EMPÍRICA — COMPLEXIDADE DE FATORAÇÃO")
    print("═"*60)
    print(f"  {'Bits':>6}  {'n':>20}  {'Divisões':>12}  {'Tempo (ms)':>12}")
    print("  " + "─"*56)

    casos = [
        (8,   143),
        (10,  1073),
        (14,  9797),
        (18,  265189),
        (26,  99401791),
    ]
    for bits, n in casos:
        _, div, t = fatorar_tentativa(n, verbose=False)
        print(f"  {bits:6d}  {n:20d}  {div:12,d}  {t*1000:12.3f}")

    print(f"\n  Crescimento O(2^(bits/2)) confirma exponencialidade.")
    print(f"  RSA-2048: ~2^1024 ≈ 10^308 divisões (universo tem ~10^80 átomos).")


def demo_rsa_seguro():
    """RSA de 512 bits: demonstra eficiência da operação legítima."""
    print("\n" + "═"*60)
    print("RSA DE 512 BITS — OPERAÇÃO LEGÍTIMA vs ATAQUE")
    print("═"*60)

    t0 = time.perf_counter()
    pub, priv = gerar_chaves_rsa(512)
    t_gen = time.perf_counter() - t0

    print(f"\n  Geração de chaves: {t_gen*1000:.1f} ms")

    m = random.randint(2, pub.n - 1)

    t0 = time.perf_counter()
    c = cifrar_rsa(m, pub)
    t_cif = time.perf_counter() - t0

    t0 = time.perf_counter()
    m2 = decifrar_rsa(c, priv)
    t_dec = time.perf_counter() - t0

    print(f"  Cifração:  {t_cif*1000:.3f} ms")
    print(f"  Decifração: {t_dec*1000:.3f} ms")
    print(f"  Verificação: {'✓ correto' if m2 == m else '✗ erro'}")

    bits_n = pub.bits
    print(f"\n  Resistência ao ataque:")
    print(f"    Divisão tentativa: ~2^{bits_n//2} ≈ 10^{int(bits_n//2*0.301):.0f} ops (infactível)")
    print(f"    GNFS: exp(c·{bits_n}^(1/3)·(log {bits_n})^(2/3)) ops (ainda infactível)")
    print(f"    Shor (quântico): O({bits_n}^3) = O({bits_n**3:,}) ops (quebraria RSA!)")


if __name__ == "__main__":
    print("RSA DIDÁTICO — Complexidade e Criptografia")
    print("Implementação educacional com análise de complexidade")
    demo_rsa_didatico()
    analise_complexidade_fatoracao()
    demo_rsa_seguro()