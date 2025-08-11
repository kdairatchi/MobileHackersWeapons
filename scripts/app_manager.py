import requests
from bs4 import BeautifulSoup
import os

def search_apkpure(query):
    print(f"Searching APKPure for '{query}'...")
    search_url = f"https://apkpure.com/search/{query}"
    headers = {'User-Agent': 'Mozilla/5.0'}
    try:
        response = requests.get(search_url, headers=headers)
        response.raise_for_status()  # Raise an exception for HTTP errors
        soup = BeautifulSoup(response.text, 'html.parser')

        app_list = soup.find_all('li', class_='apk_item')
        if not app_list:
            print("No apps found on APKPure.")
            return []

        results = []
        for app in app_list:
            title_tag = app.find('p', class_='p1')
            link_tag = app.find('a', class_='da')
            if title_tag and link_tag:
                title = title_tag.text.strip()
                app_url = "https://apkpure.com" + link_tag['href']
                results.append({'title': title, 'url': app_url})
        return results
    except requests.exceptions.RequestException as e:
        print(f"Error searching APKPure: {e}")
        return []

def download_apk(app_url, download_dir='./downloads'):
    print(f"Attempting to download APK from: {app_url}")
    os.makedirs(download_dir, exist_ok=True)
    headers = {'User-Agent': 'Mozilla/5.0'}
    try:
        # Navigate to the app's page to find the download link
        response = requests.get(app_url, headers=headers)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find the actual download button/link
        download_button = soup.find('a', class_='download-btn')
        if not download_button or not download_button.has_attr('href'):
            print("Could not find download button on the app page.")
            return None

        apk_download_url = download_button['href']
        if not apk_download_url.startswith('http'):
            apk_download_url = "https://apkpure.com" + apk_download_url

        file_name = apk_download_url.split('/')[-1]
        if not file_name.endswith('.apk'):
            file_name = "downloaded_app.apk" # Fallback if filename is not clear

        file_path = os.path.join(download_dir, file_name)

        print(f"Downloading {file_name} from {apk_download_url}...")
        with requests.get(apk_download_url, stream=True, headers=headers) as r:
            r.raise_for_status()
            with open(file_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        print(f"Downloaded to: {file_path}")
        return file_path
    except requests.exceptions.RequestException as e:
        print(f"Error downloading APK: {e}")
        return None

def install_apk(apk_path):
    if not os.path.exists(apk_path):
        print(f"Error: APK file not found at {apk_path}")
        return False
    print(f"Installing APK: {apk_path} using ADB...")
    # This assumes ADB is installed and configured in the system's PATH
    # and a device is connected and authorized.
    os.system(f"adb install {apk_path}")
    print("APK installation command sent. Check your device for confirmation.")
    return True

def search_and_install_apk():
    query = input("Enter app name to search for (Android APK): ")
    results = search_apkpure(query)

    if not results:
        print("No results found.")
        return

    print("\nSearch Results:")
    for i, app in enumerate(results):
        print(f"{i+1}. {app['title']}")

    try:
        choice = int(input("Enter the number of the app to download and install (0 to cancel): "))
        if choice == 0:
            print("Operation cancelled.")
            return
        selected_app = results[choice - 1]
    except (ValueError, IndexError):
        print("Invalid choice.")
        return

    apk_file = download_apk(selected_app['url'])
    if apk_file:
        install_apk(apk_file)

def search_and_install_ios_app():
    print("iOS app search and installation is complex due to Apple's ecosystem.")
    print("For jailbroken devices, you might use tools like 'ideviceinstaller' or 'sideloadly'.")
    print("For non-jailbroken devices, manual sideloading via Xcode or third-party tools is required.")
    print("This script will not automate iOS app searching/installation directly.")

if __name__ == '__main__':
    print("Mobile App Manager")
    print("1. Search and Install Android APK")
    print("2. iOS App Information (Manual)")
    choice = input("Enter your choice: ")

    if choice == '1':
        search_and_install_apk()
    elif choice == '2':
        search_and_install_ios_app()
    else:
        print("Invalid choice.")


