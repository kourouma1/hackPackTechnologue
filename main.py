from hearder import print_ascii_art
from crackMtp.crack import main
import time
import typer
import random

motchargment = ["Chargement en cours...", "Préparation du script...", "Initialisation des modules...", "Vérification des dépendances...", "Configuration de l'environnement...", "Optimisation des performances...", "Finalisation..."]

with typer.progressbar(range(100), label=motchargment[random.randint(0,len(motchargment)-1)]) as progress:
        for _ in progress:
            time.sleep(50/1000)
print(print_ascii_art())

if __name__ == "__main__":
    typer.run(main)