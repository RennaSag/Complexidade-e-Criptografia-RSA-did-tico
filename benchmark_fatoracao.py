import time
import matplotlib.pyplot as plt

from rsa_didatico import fatorar_tentativa

CASOS = [
    (8, 143),
    (10, 1073),
    (14, 9797),
    (18, 265189),
    (20, 100160063),
]

bits_lista = []
tempos = []
divisoes = []

print("\nANÁLISE DE FATORAÇÃO")
print("-" * 50)

for bits, n in CASOS:

    print(f"\nFatorando n={n} ({bits} bits)")

    fator, divs, tempo = fatorar_tentativa(n)

    bits_lista.append(bits)
    tempos.append(tempo * 1000)
    divisoes.append(divs)

    print(f"Fator encontrado: {fator}")
    print(f"Divisões: {divs}")
    print(f"Tempo: {tempo*1000:.3f} ms")


# gráfico tempo
plt.figure(figsize=(8,5))
plt.plot(bits_lista, tempos, marker='o')
plt.title("Tempo de fatoração por divisão tentativa")
plt.xlabel("Bits")
plt.ylabel("Tempo (ms)")
plt.grid(True)
plt.savefig("graficos/fatoracao_tempo.png")
plt.show()

# gráfico divisões
plt.figure(figsize=(8,5))
plt.plot(bits_lista, divisoes, marker='o')
plt.title("Número de divisões na fatoração")
plt.xlabel("Bits")
plt.ylabel("Divisões")
plt.grid(True)
plt.savefig("graficos/fatoracao_divisoes.png")
plt.show()