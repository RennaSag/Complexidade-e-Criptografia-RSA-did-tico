"""
LWE Simplificado — Implementação educacional com análise de complexidade

Learning With Errors (LWE) - Regev, 2005.

Complexidade:
  Geração de instância LWE  : O(m * n)   [m amostras, n dimensão]
  Cifração de um bit        : O(m + n)   [combinação linear esparsa]
  Decifração                : O(n)       [produto interno + limiar]
  Criptanálise (BKZ)        : 2^Ω(n)    [melhor algoritmo clássico e quântico]
  Eliminação gaussiana (sem ruído): O(n^3) [inviável com ruído]

Parâmetros didáticos (NÃO use em produção):
  q  = módulo pequeno (primo, ~17-97)
  n  = dimensão do segredo (2-8)
  σ  = desvio padrão do ruído Gaussiano discreto (~1-3)
  m  = número de amostras = n + segurança extra

Parâmetros reais (Kyber-512 / ML-KEM, NIST FIPS 203):
  q  = 3329
  n  = 256
  σ  ≈ 1.0  (distribuição binomial centrada, não Gaussiana)

ATENÇÃO — erro conhecido da IA corrigido:
  A redução de Regev (2005) do pior caso SVP/GapSVP para o caso médio
  LWE utiliza um ORÁCULO QUÂNTICO (quantum oracle). A redução NÃO é
  puramente clássica, ao contrário do que IAs costumam afirmar.
  Fonte: Regev, O. "On Lattices, Learning with Errors..." JACM 2009.

Referências:
  Regev, O. On Lattices, Learning with Errors, Random Linear Codes,
    and Cryptography. JACM 56(6), 2009.
  NIST FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism
    Standard. 2024.
  Peikert, C. A Decade of Lattice Cryptography. FnTCS 10(4), 2016.
"""

import math
import random
import time
from typing import List, Tuple, Optional



def mod_positivo(x: int, q: int) -> int:
    """Reduz x mod q para o intervalo [0, q). Complexidade: O(1)."""
    return x % q


def produto_interno_mod(a: List[int], b: List[int], q: int) -> int:
    """
    Produto interno <a, b> mod q.
    Complexidade: O(n) onde n = len(a).
    """
    assert len(a) == len(b), "Vetores de dimensões diferentes."
    return mod_positivo(sum(ai * bi for ai, bi in zip(a, b)), q)


def multiplicacao_matriz_vetor(A: List[List[int]], v: List[int], q: int) -> List[int]:
    """
    Produto A·v mod q.
    A: matriz m×n, v: vetor n×1.
    Resultado: vetor m×1.
    Complexidade: O(m * n).
    """
    return [produto_interno_mod(linha, v, q) for linha in A]



def amostrar_gaussiano_discreto(sigma: float) -> int:
    """
    Amostra da distribuição Gaussiana discreta com desvio σ.
    Método: soma de 12 variáveis U[−0.5, 0.5] (aproximação pelo TCL).
    Retorna inteiro pequeno em torno de 0.

    Complexidade: O(1) (número fixo de amostras).

    Nota: implementações reais (Kyber) usam a distribuição binomial
    centrada B(η) por eficiência e segurança contra ataques de canal
    lateral. Aqui usamos Gaussiana para clareza didática.
    """
    if sigma == 0.0:
        return 0
    # Teorema Central do Limite: soma de 12 U[-0.5, 0.5] ≈ N(0, 1)
    u = sum(random.random() - 0.5 for _ in range(12))
    return round(u * sigma)


def amostrar_vetor_erro(m: int, sigma: float, q: int) -> List[int]:
    """
    Gera vetor de erros e de tamanho m.
    Cada componente: amostra Gaussiana discreta reduzida mod q.
    Complexidade: O(m).
    """
    return [mod_positivo(amostrar_gaussiano_discreto(sigma), q) for _ in range(m)]



def gerar_instancia_lwe(
    n: int,
    q: int,
    sigma: float,
    m: Optional[int] = None
) -> Tuple[List[List[int]], List[int], List[int], List[int]]:
    """
    Gera uma instância LWE pública (A, b) com segredo s e ruído e.

    O problema LWE (decisional): distinguir (A, b = As + e mod q)
    de (A, b uniforme). Com ruído σ > 0, isso é computacionalmente
    difícil (conjectura LWE).

    Parâmetros:
        n     : dimensão do segredo s
        q     : módulo (primo recomendado)
        sigma : desvio padrão do ruído
        m     : número de amostras (default = n + 4)

    Retorna:
        A : matriz pública  m × n,  elementos em Z_q
        b : vetor público   m × 1,  b = As + e mod q
        s : segredo         n × 1   (não público — apenas para verificação)
        e : vetor de erros  m × 1   (não público)

    Complexidade: O(m * n) para construir A e calcular As.
    """
    if m is None:
        m = n + 4

    # Matriz pública A: elementos uniformes em Z_q
    A = [[random.randint(0, q - 1) for _ in range(n)] for _ in range(m)]

    # Segredo s: uniforme em Z_q (versão padrão LWE)
    s = [random.randint(0, q - 1) for _ in range(n)]

    # Vetor de erros
    e = amostrar_vetor_erro(m, sigma, q)

    # b = As + e (mod q)
    As = multiplicacao_matriz_vetor(A, s, q)
    b = [mod_positivo(As[i] + e[i], q) for i in range(m)]

    return A, b, s, e



def gerar_chave_lwe(
    n: int,
    q: int,
    sigma: float
) -> Tuple[Tuple[List[List[int]], List[int]], List[int]]:
    """
    Gera par (chave_publica, chave_privada) para cifração LWE.

    chave_publica = (A, b)  onde b = As + e mod q
    chave_privada = s

    Complexidade: O(n^2) para m = O(n) amostras.
    """
    m = n * 2  # amostras suficientes para cifração
    A, b, s, _ = gerar_instancia_lwe(n, q, sigma, m)
    return (A, b), s



def cifrar_bit_lwe(
    bit: int,
    chave_publica: Tuple[List[List[int]], List[int]],
    q: int
) -> Tuple[List[int], int]:
    """
    Cifra um bit ∈ {0, 1} usando o esquema de Regev.

    Ideia: escolher subconjunto aleatório r ⊆ {amostras}.
    Criptograma: (u, v) onde
        u = Σ_{i∈r} a_i   (mod q)      — combinação de linhas de A
        v = Σ_{i∈r} b_i + bit·⌊q/2⌋  (mod q)

    O bit é "embutido" como deslocamento de ⌊q/2⌋ em v.
    O ruído acumulado no somatório é pequeno e não apaga o bit.

    Complexidade: O(m + n) — seleção e somatório.

    Parâmetros:
        bit           : 0 ou 1
        chave_publica : (A, b)
        q             : módulo

    Retorna:
        u : vetor n × 1 (parte do criptograma)
        v : inteiro     (parte do criptograma)
    """
    assert bit in (0, 1), "Bit deve ser 0 ou 1."
    A, b = chave_publica
    m = len(A)
    n = len(A[0])
    meio = q // 2

    # r: vetor de seleção aleatório em {0, 1}^m (esparso)
    r = [random.randint(0, 1) for _ in range(m)]

    # u = Σ r_i · a_i mod q
    u = [mod_positivo(sum(r[i] * A[i][j] for i in range(m)), q) for j in range(n)]

    # v = Σ r_i · b_i + bit · ⌊q/2⌋ mod q
    soma_b = sum(r[i] * b[i] for i in range(m))
    v = mod_positivo(soma_b + bit * meio, q)

    return u, v


def decifrar_bit_lwe(
    u: List[int],
    v: int,
    chave_privada: List[int],
    q: int
) -> int:
    """
    Decifra um bit do criptograma (u, v).

    Cálculo:
        w = v - <u, s> mod q
    Se bit = 0: w ≈ 0         (ruído pequeno)
    Se bit = 1: w ≈ ⌊q/2⌋   (ruído pequeno)

    Decisão pelo limiar ⌊q/4⌋:
        |w| < q/4    → bit = 0
        |w - q/2| < q/4 → bit = 1

    Complexidade: O(n) — produto interno u·s.

    IMPORTANTE: a decifração falha com probabilidade não nula se o
    ruído acumulado ultrapassar o limiar q/4. Por isso σ deve ser
    pequeno em relação a q. Para Kyber-512: σ ≈ 1.0, q = 3329.
    """
    s = chave_privada
    meio = q // 2
    limiar = q // 4

    # w = v - <u, s> mod q
    us = produto_interno_mod(u, s, q)
    w = mod_positivo(v - us, q)

    # Decisão: w próximo de 0 → bit 0; w próximo de q/2 → bit 1
    dist_zero = min(w, q - w)          # distância de w até 0 em Z_q
    dist_meio = min(abs(w - meio), q - abs(w - meio))  # distância até ⌊q/2⌋

    return 0 if dist_zero < dist_meio else 1



def eliminacao_gaussiana_mod(
    A: List[List[int]],
    b: List[int],
    q: int
) -> Optional[List[int]]:
    """
    Tentativa de resolver As = b mod q por eliminação gaussiana.
    Funciona apenas se e = 0 (sem ruído).

    Complexidade: O(n^3) — n pivôs, cada um processa n linhas × n colunas.

    Com ruído, o sistema é inconsistente e a eliminação falha ou
    retorna solução errada. Isso demonstra por que LWE é difícil:
    o ruído impede métodos algébricos exatos.

    Retorna o vetor solução s, ou None se o sistema for singular/inconsistente.
    """
    n = len(A[0])
    m = len(A)
    if m < n:
        return None  # sistema subdeterminado

    # Copiar e trabalhar apenas com as n primeiras linhas
    M = [A[i][:] + [b[i]] for i in range(n)]

    for col in range(n):
        # Encontrar pivô
        pivo = None
        for row in range(col, n):
            if M[row][col] % q != 0:
                pivo = row
                break
        if pivo is None:
            return None  # coluna singular

        M[col], M[pivo] = M[pivo], M[col]

        # Inverso do pivô mod q
        p = M[col][col] % q
        inv_p = pow(p, -1, q) if math.gcd(p, q) == 1 else None
        if inv_p is None:
            return None

        # Normalizar linha do pivô
        M[col] = [mod_positivo(x * inv_p, q) for x in M[col]]

        # Eliminar coluna nas outras linhas
        for row in range(n):
            if row != col and M[row][col] % q != 0:
                fator = M[row][col]
                M[row] = [mod_positivo(M[row][j] - fator * M[col][j], q) for j in range(n + 1)]

    return [M[i][n] for i in range(n)]



def demo_instancia_lwe():
    """Mostra uma instância LWE gerada e exibe todos os componentes."""
    print("\n" + "═" * 60)
    print("INSTÂNCIA LWE — COMPONENTES")
    print("═" * 60)

    n, q, sigma = 3, 17, 1.5
    print(f"\n  Parâmetros: n={n}, q={q}, σ={sigma}")
    print(f"  Amostras:   m={n + 4}\n")

    A, b, s, e = gerar_instancia_lwe(n, q, sigma)

    print("  Segredo s (OCULTO ao adversário):")
    print(f"    s = {s}")

    print("\n  Matriz A (pública):")
    for i, linha in enumerate(A):
        print(f"    a_{i} = {linha}")

    print(f"\n  Erros e (OCULTOS, σ={sigma}):")
    for i, ei in enumerate(e):
        print(f"    e_{i} = {ei:+d}")

    print(f"\n  Vetor b = As + e mod {q} (público):")
    for i, bi in enumerate(b):
        As_i = sum(A[i][j] * s[j] for j in range(n)) % q
        print(f"    b_{i} = {As_i} + {e[i]} = {bi}  (mod {q})")

    print(f"\n  Verificação: b - As mod {q} = {[( b[i] - sum(A[i][j]*s[j] for j in range(n))) % q for i in range(len(b))]}")
    print(f"  (deve ser igual ao vetor e reduzido mod {q})")


def demo_dificuldade_do_ruido():
    """Compara eliminação gaussiana com e sem ruído."""
    print("\n" + "═" * 60)
    print("PAPEL DO RUÍDO — ELIMINAÇÃO GAUSSIANA")
    print("═" * 60)

    n, q = 4, 23

    print(f"\n  Parâmetros: n={n}, q={q}")

    # Sem ruído: eliminação funciona
    print("\n  [1] σ = 0 (sem ruído) — sistema exato As = b")
    A0, b0, s0, _ = gerar_instancia_lwe(n, q, sigma=0.0, m=n)
    sol = eliminacao_gaussiana_mod(A0, b0, q)
    acerto = sol == s0 if sol else False
    print(f"      Segredo real:    s = {s0}")
    print(f"      Solução obtida:  s = {sol}")
    print(f"      Recuperou s? {'✓ SIM' if acerto else '✗ NÃO'}")

    # Com ruído: eliminação falha
    print("\n  [2] σ = 2.0 (com ruído) — sistema perturbado As + e = b")
    A1, b1, s1, e1 = gerar_instancia_lwe(n, q, sigma=2.0, m=n)
    sol1 = eliminacao_gaussiana_mod(A1, b1, q)
    acerto1 = sol1 == s1 if sol1 else False
    print(f"      Segredo real:    s = {s1}")
    print(f"      Ruído e:         e = {e1}")
    print(f"      Solução obtida:  s = {sol1}")
    print(f"      Recuperou s? {'✓ SIM (coincidência rara)' if acerto1 else '✗ NÃO — ruído corrompeu o sistema'}")

    print("\n  Conclusão: o ruído e transforma um sistema linear resolúvel")
    print("  em um problema para o qual nenhum algoritmo polinomial é")
    print("  conhecido — clássico ou quântico.")


def demo_cifracao_lwe():
    """Demonstra cifração e decifração de bits com Regev."""
    print("\n" + "═" * 60)
    print("CIFRAÇÃO LWE — REGEV SIMPLIFICADO")
    print("═" * 60)

    n, q, sigma = 4, 97, 1.0

    print(f"\n  Parâmetros: n={n}, q={q}, σ={sigma}")
    print(f"  Limiar de decifração: ⌊q/4⌋ = {q // 4}\n")

    pub, priv = gerar_chave_lwe(n, q, sigma)
    A, b = pub
    print(f"  Chave pública: A ({len(A)}×{n}), b ({len(b)}×1)")
    print(f"  Chave privada: s = {priv}\n")

    bits_teste = [0, 1, 0, 1, 1, 0]
    acertos = 0

    print(f"  {'Bit':>4}  {'u₁':>6}  {'v':>6}  {'w=v-⟨u,s⟩':>12}  {'Decifrado':>10}  {'OK?':>4}")
    print("  " + "─" * 52)

    for bit in bits_teste:
        u, v = cifrar_bit_lwe(bit, pub, q)
        bit_dec = decifrar_bit_lwe(u, v, priv, q)
        us = produto_interno_mod(u, priv, q)
        w = mod_positivo(v - us, q)
        ok = bit == bit_dec
        if ok:
            acertos += 1
        print(f"  {bit:>4}  {u[0]:>6}  {v:>6}  {w:>12}  {bit_dec:>10}  {'✓' if ok else '✗':>4}")

    print(f"\n  Taxa de acerto: {acertos}/{len(bits_teste)}")
    if acertos < len(bits_teste):
        print("  (falhas esperadas quando ruído acumulado ultrapassa q/4)")


def analise_parametros():
    """Mostra como parâmetros afetam a taxa de erro de decifração."""
    print("\n" + "═" * 60)
    print("ANÁLISE DE PARÂMETROS — TAXA DE ERRO")
    print("═" * 60)

    configuracoes = [
        (4,  17,  0.5, "σ pequeno, q pequeno"),
        (4,  17,  2.0, "σ grande, q pequeno — muitos erros"),
        (4,  97,  1.0, "σ médio, q maior    — poucos erros"),
        (8,  97,  1.5, "n maior, σ médio    — segurança maior"),
    ]

    N_TESTES = 200

    print(f"\n  {'n':>3} {'q':>5} {'σ':>5}  {'Erro(%)':>8}  Observação")
    print("  " + "─" * 60)

    for n, q, sigma, obs in configuracoes:
        pub, priv = gerar_chave_lwe(n, q, sigma)
        erros = 0
        for _ in range(N_TESTES):
            bit = random.randint(0, 1)
            u, v = cifrar_bit_lwe(bit, pub, q)
            if decifrar_bit_lwe(u, v, priv, q) != bit:
                erros += 1
        taxa = 100 * erros / N_TESTES
        print(f"  {n:>3} {q:>5} {sigma:>5.1f}  {taxa:>7.1f}%  {obs}")

    print(f"\n  Kyber-512 (produção): n=256, q=3329, σ≈1.0 → taxa de erro < 2^-139")


if __name__ == "__main__":
    print("LWE SIMPLIFICADO — Complexidade e Criptografia")
    print("Implementação educacional com análise de complexidade")
    print("Referência: Regev, JACM 2009 / NIST FIPS 203")

    demo_instancia_lwe()
    demo_dificuldade_do_ruido()
    demo_cifracao_lwe()
    analise_parametros()

    print("\n" + "═" * 60)
    print("FIM — veja também crypto_complexity_demo.html para")
    print("visualização interativa dos mesmos conceitos.")
    print("═" * 60)