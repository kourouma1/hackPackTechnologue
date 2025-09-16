from pyfiglet import Figlet
from termcolor import colored
from acistyle import get_models


def print_ascii_art():
    # Configurer une police grande et imposante pour le texte
    figlet = Figlet(font='slant', width=140, justify='center')

    # Définir le texte à afficher
    text = "TECHNOLOGUE"

    # Générer le texte en ASCII art
    ascii_art = figlet.renderText(text)

    # Définir un crâne de danger en ASCII art
    skull_art = """
                        _---------.
             .' #######   ;."
  .---,.    ;@             @@`;   .---,..
." @@@@@'.,'@@            @@@@@',.'@@@@ ".
'-.@@@@@@@@@@@@@          @@@@@@@@@@@@@ @;
   `.@@@@@@@@@@@@        @@@@@@@@@@@@@@ .'
     "--'.@@@  -.@        @ ,'-   .'--"
          ".@' ; @       @ `.  ;'
            |@@@@ @@@     @    .
             ' @@@ @@   @@    ,
              `.@@@@    @@   .
                ',@@     @   ;           _____________
                 (   3 C    )     /|___ / Technologue! \
                 ;@'. __*__,."    \|--- \_____________/
                  '(.,...."/
"""

    style = get_models()

    # Combiner le texte et le crâne
    combined_art = ascii_art + style

    # Ajouter une couleur rouge avec l'attribut bold pour le rendu
    colored_combined = colored(combined_art, color='red', attrs=['bold'])
    return colored_combined
  


