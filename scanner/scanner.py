import nmap
from rich.console import Console
from rich.table import Table
from concurrent.futures import ThreadPoolExecutor

console = Console()

def scan_host(ip, scan_type, force_level):
    scanner = nmap.PortScanner()

    # Définition des arguments selon le type de scan
    if scan_type == '1':  # Scan simple
        args = '-p 1-1024'
    elif scan_type == '2':  # Scan version
        args = '-p 1-1024 -sV'
    elif scan_type == '3':  # Scan agressif
        args = '-p 1-1024 -A'
    elif scan_type == '4':  # Scan vulnérabilités
        args = '-p 1-1024 --script vuln'
    else:
        console.print("[red]Type de scan invalide ![/red]")
        return

    # Ajustement de la force
    if force_level == '1':  # Rapide
        args += ' -T4'
    elif force_level == '2':  # Moyen
        args += ' -T4 -p 1-65535'
    elif force_level == '3':  # Fort
        args += ' -T5 -p 1-65535 -A --script vuln,discovery'
    else:
        console.print("[red]Niveau de force invalide ![/red]")
        return

    console.print(f"\n[bold yellow]Scan en cours sur {ip} avec : {args}[/bold yellow]")

    try:
        scanner.scan(hosts=ip, arguments=args)
    except Exception as e:
        console.print(f"[red]Erreur pendant le scan de {ip}: {e}[/red]")
        return

    for host in scanner.all_hosts():
        hostname = scanner[host].hostname() or "N/A"
        state = scanner[host].state()
        console.print(f"\n[cyan]Hôte : {host}[/cyan]  |  [green]Status : {state}[/green]  |  [magenta]Nom : {hostname}[/magenta]")

        table = Table(title="Ports et Services", show_lines=True)
        table.add_column("Protocole", style="cyan", justify="center")
        table.add_column("Port", style="yellow", justify="center")
        table.add_column("Service", style="green")
        table.add_column("Version", style="magenta")

        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto].keys():
                if scanner[host][proto][port]['state'] == 'open':
                    service = scanner[host][proto][port]['name']
                    version = scanner[host][proto][port]['version'] or "N/A"
                    table.add_row(proto.upper(), str(port), service, version)

        console.print(table)

        # Affichage vulnérabilités si scan vulnérabilités ou scan fort
        if force_level in ['3'] or scan_type == '4':
            if 'hostscript' in scanner[host]:
                console.print("\n[bold red]Vulnérabilités détectées :[/bold red]")
                for script in scanner[host]['hostscript']:
                    console.print(f"[yellow]{script['id']}[/yellow] : {script['output']}")
            else:
                console.print("[green]Aucune vulnérabilité détectée[/green]")

def main():
    choix_machine = input("Voulez-vous scanner une seule machine (1) ou une plage d'IP (2) ? : ")
    
    if choix_machine == '1':
        ip_list = [input("Entrez l'adresse IP de la machine : ")]
    elif choix_machine == '2':
        plage = input("Entrez la plage d'IP (ex: 192.168.1.0/24) : ")
        # Séparation en IP individuelles pour le multithread
        ip_list = [str(ip) for ip in nmap.PortScanner().all_hosts() if plage in str(ip)]  # juste placeholder
        ip_list = [plage]  # pour simplifier, le scan supporte directement la plage
    else:
        console.print("[red]Choix invalide ![/red]")
        return

    console.print("\nChoisissez le type de scan :")
    console.print("1 - Scan simple (rapide)")
    console.print("2 - Scan version (ports + service + version)")
    console.print("3 - Scan agressif (OS, version, script Nmap)")
    console.print("4 - Scan vulnérabilités (--script vuln)")
    scan_type = input("Entrez le numéro du type de scan : ")

    console.print("\nChoisissez le niveau de force :")
    console.print("1 - Rapide")
    console.print("2 - Moyen")
    console.print("3 - Fort")
    force_level = input("Entrez le niveau de force : ")

    # Multi-thread pour accélérer le scan sur plusieurs IP
    with ThreadPoolExecutor(max_workers=10) as executor:
        for ip in ip_list:
            executor.submit(scan_host, ip, scan_type, force_level)


if __name__ == "__main__":
    main()
