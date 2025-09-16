# hackPackTechnologue
un outils d'automatisation d'attaque reseau wifi


Outil Wi-Fi - Documentation
Créateur
Cet outil a été développé par Kourouma Martin, technologue diplômé en informatique.  

Email : martinkourouma9@gmail.com  
Téléphone : 610491631

Description
L'Outil Wi-Fi est une application Python avec une interface graphique (GUI) conçue pour analyser, surveiller et tester les réseaux Wi-Fi. Il utilise des outils comme airodump-ng, aircrack-ng, et wash pour effectuer des tâches telles que le scan des réseaux, la capture de paquets, les attaques Wi-Fi, et la détection des vulnérabilités. L'outil est destiné à un usage légal et éthique, comme des tests de sécurité sur des réseaux autorisés.
Prérequis
Dépendances

Python : Version 3.x
Bibliothèques Python :pip install rich requests scapy


Système :sudo apt install python3-tk aircrack-ng network-manager


Une carte réseau compatible avec le mode moniteur (ex. Atheros, Ralink).
Permissions root (sudo) pour exécuter les commandes réseau.

Configuration

Connexion Wi-Fi :Pour certaines fonctions (ex. comptage des appareils), connectez-vous à un réseau :nmcli dev wifi connect "SSID" password "MOTDEPASSE"


Mode moniteur :Pour le scan en temps réel ou les attaques :sudo airmon-ng start wlan0

Cela crée une interface comme wlan0mon.

Fonctionnalités
L'outil propose une interface graphique avec les fonctionnalités suivantes, accessibles via des boutons :

Scanner les réseaux Wi-Fi :

Détecte automatiquement le mode de l'interface (moniteur ou géré).
Mode moniteur : Utilise airodump-ng pour un scan détaillé (SSID, BSSID, sécurité, signal, fabricant).
Mode géré : Utilise nmcli pour un scan rapide.
Paramètres : Intensité minimale du signal, fichier de sortie (JSON).


Déchiffrer un fichier .cap :

Déchiffre les fichiers .cap pour WEP ou WPA/WPA2 avec aircrack-ng.
WEP : Utilise les IVs capturés.
WPA/WPA2 : Nécessite un fichier dictionnaire.
Entrées : Chemin du fichier .cap, type de sécurité, fichier dictionnaire (pour WPA).


Lancer une attaque Wi-Fi :

Types d'attaques : Déauthentification, Fake Auth, ARP Replay avec aireplay-ng.
Entrées : BSSID, interface, canal, type d'attaque.
Exemple : Déconnecter les clients (déauth) pour capturer un handshake.


Afficher l'historique Wi-Fi :

Liste les réseaux enregistrés dans /etc/NetworkManager/system-connections/.
Affiche SSID, UUID, type, mot de passe, et BSSID.


Compter les appareils connectés :

Compte les clients connectés au réseau auquel l'interface est connectée.
Utilise airodump-ng avec filtre BSSID.
Sauvegarde les résultats en JSON.


Capturer des paquets :

Capture les paquets pour un BSSID spécifique dans un fichier .cap.
Entrées : BSSID, interface, canal, nom du fichier de sortie.


Attaque automatisée :

Automatise : scan, sélection d'une cible (WEP/WPA), déauthentification (si WPA), capture de paquets, et déchiffrement.
Entrées : Interface, fichier dictionnaire (optionnel).


Surveiller le trafic IP :

Capture et analyse le trafic pour une adresse IP donnée avec scapy.
Entrées : Interface, IP cible, durée de capture.
Sauvegarde les paquets dans un fichier .pcap.


Détecter les vulnérabilités Wi-Fi :

Identifie les réseaux avec WPS activé ou SSID masqué via wash et airodump-ng.
Sauvegarde les résultats en JSON.


Surveillance en temps réel avec GUI :

Affiche un tableau actualisé des clients connectés (MAC, fabricant, signal).
Actualisation toutes les 5 secondes.
Entrée : Interface connectée à un réseau.


Afficher le récapitulatif graphique :

Affiche un tableau des actions effectuées (extraites de wifi_tool.log).
Colonnes : Fonction, Horodatage, Statut, Résumé.
Boutons : Actualiser, Quitter.


Aide / Documentation :

Affiche une description des fonctionnalités via une boîte de dialogue.


Quitter :

Ferme l'application.



Utilisation

Lancer l'outil :
sudo python3 GUIAttaque.py


Une fenêtre GUI s'ouvre avec des boutons numérotés correspondant aux fonctionnalités.
Cliquez sur un bouton pour lancer une action.


Entrées utilisateur :

Des boîtes de dialogue (simpledialog) s'ouvrent pour saisir les paramètres (ex. interface, BSSID, canal).
Les entrées sont validées (ex. format MAC, IP, canal entre 1-14).


Sorties :

Résultats affichés dans la console (rich) et via des pop-ups (messagebox).
Fichiers JSON/PCAP générés dans des dossiers spécifiques (ex. attaque_<BSSID>_<horodatage>).
Logs enregistrés dans wifi_tool.log.



Exemple de tableau récapitulatif (Option 11)
+-------------------------------+--------------------------+--------+-------------------------------+
| Fonction                      | Horodatage               | Statut | Résumé                        |
+-------------------------------+--------------------------+--------+-------------------------------+
| Scanner les réseaux Wi-Fi     | 2025-09-16 18:45:12,345  | Succès | 5 réseaux, 3 clients          |
| Attaque automatisée           | 2025-09-16 18:46:23,456  | Échec  | fichier=capture_123456.cap    |
+-------------------------------+--------------------------+--------+-------------------------------+

Gestion des erreurs

Validations :
Vérification des formats MAC, IP, interface, et canal.
Messages d'erreur via messagebox si les entrées sont invalides ou vides.


Interruptions :
Ctrl+C arrête les opérations avec un message dans la console/GUI.


Permissions :
Exécutez avec sudo pour les commandes réseau.
Pour éviter les erreurs de permission :sudo setcap cap_net_raw,cap_net_admin=eip $(which airodump-ng)
sudo setcap cap_net_raw,cap_net_admin=eip $(which wash)





Notes

Mode moniteur : Nécessaire pour les scans détaillés et attaques. Vérifiez l'interface avec iwconfig.
Logs :
Si wifi_tool.log est absent, l'option 11 affiche une erreur.
Purgez les logs si nécessaire :> wifi_tool.log




GUI :
Nécessite un environnement graphique (ex. X11).
Installez tkinter si absent :sudo apt install python3-tk





Limitations

L'outil nécessite des permissions root pour certaines fonctions.
Compatible uniquement avec Linux (en raison de airodump-ng, nmcli, etc.).
Les attaques doivent être effectuées sur des réseaux autorisés pour respecter la légalité.

Améliorations futures

Ajout de menus déroulants pour sélectionner les interfaces et types d'attaques.
Affichage des résultats directement dans la GUI.
Liste interactive des réseaux détectés pour les attaques/captures.
