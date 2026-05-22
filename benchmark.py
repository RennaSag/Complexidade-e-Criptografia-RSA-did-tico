import time
import random
import matplotlib.pyplot as plt

from rsa_didatico import (
    gerar_chaves_rsa,
    cifrar_rsa,
    decifrar_rsa,
    fatorar_tentativa
)

BITS = [16, 32, 64, 128, 256, 512]

def benchmark_rsa():
    tempos_geracao = []
    tempos_cifracao = []
    tempos_decifracao = []

    for bits in BITS:
        print(f"\nBenchmark {bits} bits")

        # geração
        t0 = time.perf_counter()
        pub, priv = gerar_chaves_rsa(bits)
        t_gen = (time.perf_counter() - t0) * 1000

        # mensagem aleatória
        m = random.randint(2, pub.n - 1)

        # cifração
        t0 = time.perf_counter()
        c = cifrar_rsa(m, pub)
        t_cif = (time.perf_counter() - t0) * 1000

        # decifração
        t0 = time.perf_counter()
        decifrar_rsa(c, priv)
        t_dec = (time.perf_counter() - t0) * 1000

        tempos_geracao.append(t_gen)
        tempos_cifracao.append(t_cif)
        tempos_decifracao.append(t_dec)

        print(f"Geração: {t_gen:.3f} ms")
        print(f"Cifração: {t_cif:.3f} ms")
        print(f"Decifração: {t_dec:.3f} ms")

    return tempos_geracao, tempos_cifracao, tempos_decifracao


def grafico(bits, valores, titulo, ylabel):
    plt.figure(figsize=(8, 5))
    plt.plot(bits, valores, marker='o')
    plt.title(titulo)
    plt.xlabel('Bits da chave RSA')
    plt.ylabel(ylabel)
    plt.grid(True)
    plt.show()


if __name__ == '__main__':
    tg, tc, td = benchmark_rsa()

    grafico(BITS, tg,
             'Tempo de geração de chaves RSA',
             'Tempo (ms)')

    grafico(BITS, tc,
             'Tempo de cifração RSA',
             'Tempo (ms)')

    grafico(BITS, td,
             'Tempo de decifração RSA',
             'Tempo (ms)')