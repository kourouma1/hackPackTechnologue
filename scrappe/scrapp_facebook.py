from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from rich.console import Console
from rich.table import Table
import time
import os

# === CONFIGURATION ===
CHROMEDRIVER_PATH = "/usr/bin/chromedriver"
PROFILE_PATH = "/home/ton_user/.config/google-chrome/Default"  # Modifie avec ton chemin
HEADLESS = False

console = Console()

def search_facebook(query):
    # Options Chrome
    chrome_options = Options()
    chrome_options.add_argument(f"user-data-dir={PROFILE_PATH}")  # Profil Chrome réel
    chrome_options.add_argument("--start-maximized")
    chrome_options.add_argument("--disable-notifications")
    if HEADLESS:
        chrome_options.add_argument("--headless")

    service = Service(CHROMEDRIVER_PATH)
    driver = webdriver.Chrome(service=service, options=chrome_options)
    driver.get("https://www.facebook.com")

    # Attendre le chargement de la page principale
    WebDriverWait(driver, 15).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
    time.sleep(2)

    # Recherche avec wait explicite et XPath multi-langue
    try:
        search_box = WebDriverWait(driver, 15).until(
            EC.presence_of_element_located(
                (By.XPATH, "//input[@aria-label='Rechercher' or @placeholder='Search Facebook']")
            )
        )
    except:
        console.print("[red]Impossible de trouver le champ de recherche. Vérifie la langue de Facebook.[/red]")
        driver.quit()
        return []

    search_box.clear()
    search_box.send_keys(query)
    search_box.send_keys(Keys.ENTER)

    # Attendre que les résultats s'affichent
    time.sleep(5)

    # Récupérer les 10 premiers profils visibles
    profiles = driver.find_elements(By.XPATH, "//a[contains(@href,'facebook.com') and @role='link']")
    results = []
    seen_links = set()
    for p in profiles:
        name = p.text
        link = p.get_attribute("href")
        if name and link not in seen_links:
            results.append({"name": name, "profile_link": link})
            seen_links.add(link)
        if len(results) >= 10:
            break

    driver.quit()
    return results

def display_results(results):
    if not results:
        console.print("[yellow]Aucun résultat trouvé.[/yellow]")
        return

    table = Table(title="Résultats Facebook", show_lines=True)
    table.add_column("N°", justify="center", style="cyan")
    table.add_column("Nom", justify="left", style="green")
    table.add_column("Lien du profil", justify="left", style="magenta")

    for idx, user in enumerate(results, start=1):
        table.add_row(str(idx), user["name"], user["profile_link"])

    console.print(table)

if __name__ == "__main__":
    query = input("Entrez le nom/email/téléphone à rechercher : ").strip()
    users = search_facebook(query)
    display_results(users)
