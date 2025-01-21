import time
import datetime
import numpy as np
import pandas as pd
from collections import Counter
import threading
import pywintypes
import win32api
import win32ctypes
import csv
import os
from scapy.all import sniff, IP, TCP, UDP, ICMP
import paho.mqtt.client as mqtt
from class_functions import calculate_entropy
import smtplib
import joblib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import subprocess
import tkinter as tk
from tkinter import scrolledtext, ttk
from threading import Thread, Lock

active_attacks = Counter()  # Compteur pour suivre les attaques actives
is_connected = False  # Variable de statut de connexion
current_attack_type = "Normal"
attack_lock = Lock() 
detected_attacks = []  # Liste pour stocker les attaques détectées
email_sent_attacks = set()  # Set de suivi pour suivre les attaques pour lesquelles un email a été envoyé

# Charger les objets pour utilisation du modele
model_path = 'modeles/random_forest_model_ibra_seul_fonctionnel.pkl'
rf_model = joblib.load(model_path)

# Fichiers pour les IPs
green_ip_file = 'validations_ip/green_ip.csv'
red_ip_file = 'validations_ip/red_ip.csv'
pending_validation_ip_file = 'validations_ip/pending_validation_ip.csv'

# Méthode évenement pour la connexion au broker MQTT
def on_connect(client, userdata, flags, rc, properties=None):
    global is_connected
    if rc == 0:
        is_connected = True
        print("Connecté au broker MQTT avec succès ! " + str(rc))
        client.subscribe("attack/type")
    else:
        print("Échec de la connexion au broker MQTT " + str(rc))
        is_connected = False

# Méthode d'envoi d'emails en cas d'alerte attaque        
def send_email(subject, body, to_email):
    sender_email = "ibra.sgn@outlook.com"
    password = "***"

    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = to_email
    message["Subject"] = subject

    message.attach(MIMEText(body, "html"))

    server = smtplib.SMTP('smtp.office365.com', 587)
    server.starttls()
    server.login(sender_email, password)
    server.sendmail(sender_email, to_email, message.as_string())
    server.quit()

# Méthode pour envoyer une notification de validation d'IP
def send_validation_request(ip_list):
    subject = "FIRE-CONNECT - Validation de l'adresse IP requise"
    body = f"""
    <html>
    <body>
        <p>Bonjour,</p>
        <p>Les adresses IP suivantes sont détectées à la fois dans green_ip et red_ip :</p>
        <ul>
            {''.join(f'<li>{ip}</li>' for ip in ip_list)}
        </ul>
        <p>Veuillez confirmer leur validité.</p>
        <p>Cordialement,<br>Votre système de surveillance FireConnect</p>
    </body>
    </html>
    """
    send_email(subject, body, "ibra.investissement@gmail.com")

# Méthode pour envoyer une alerte d'attaque
def send_attack_alert(attack_type, detection_time):
    subject = "FIRE-CONNECT - Alerte d'attaque détectée"
    body = f"""
    <html>
    <body>
        <p>Bonjour,</p>
        <p>Une attaque de type <b>{attack_type}</b> a été détectée sur le réseau.</p>
        <p><b>Heure de détection :</b> {detection_time}</p>
        <p>Cordialement,<br>Votre système de surveillance FireConnect</p>
    </body>
    </html>
    """
    send_email(subject, body, "ibra.investissement@gmail.com")

# Méthode pour envoyer une notification de retour à la normale
def send_normal_traffic_alert(detection_time):
    subject = "Trafic réseau de retour à la normale"
    body = f"""
    <html>
    <body>
        <p>Bonjour,</p>
        <p>Le trafic réseau est revenu à la normale.</p>
        <p><b>Heure de retour à la normale :</b> {detection_time}</p>
        <p>Cordialement,<br>Votre système de surveillance FireConnect</p>
    </body>
    </html>
    """
    send_email(subject, body, "ibra.investissement@gmail.com")

# Méthode évenement en cas de deconnexion du broker MQTT
def on_disconnect(client, userdata, flags, rc, properties=None):
    global is_connected
    is_connected = False
    print("Déconnexion du broker MQTT.")

# Méthode évenement pour la reconnexion au broker MQTT
def manage_connection(client):
    while True:
        if not is_connected:
            print("Attente de connexion...")
            try:
                client.reconnect()
            except Exception as e:
                print(f"Echec de reconnexion : {e}")
        time.sleep(10)

# Méthode évenement lors de la réception de messages MQTT
def on_message(client, userdata, msg):
    global current_attack_type
    message = msg.payload.decode()
    attack_info = message.split(':')
    attack_type, attack_id, status = attack_info

    with attack_lock:
        if 'start' in status:
            active_attacks[attack_id] = attack_type
            if attack_id not in email_sent_attacks:
                detection_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                send_attack_alert(attack_type, detection_time)  # Envoi d'email en cas de début d'attaque
                email_sent_attacks.add(attack_id)
        elif 'end' in status and attack_id in active_attacks:
            del active_attacks[attack_id]

        current_attack_types = set(active_attacks.values())
        previous_attack_type = current_attack_type
        current_attack_type = ', '.join(current_attack_types) if current_attack_types else "Normal"

        if current_attack_type == "Normal" and previous_attack_type != "Normal":
            detection_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            send_normal_traffic_alert(detection_time)

class NetworkDataCollector:
    # Classe pour collecter et analyser les données réseau
    def __init__(self, window_size=4, filename=""):
        self.window_size = window_size  # Taille de la fenêtre temporelle pour l'analyse
        self.window_packets = []  # Stocke les paquets dans la fenêtre actuelle
        self.filename = filename  # Nom du fichier pour stocker les données
        self.ensure_file()  # Vérifie que le fichier existe, sinon le crée
        self.last_write_time = datetime.datetime.now()
        self.tcp_count = 0  # Compte les paquets TCP
        self.udp_count = 0  # Compte les paquets UDP
        self.icmp_count = 0  # Compte les paquets ICMP

    def ensure_file(self):
        if not os.path.isfile(self.filename):
            with open(self.filename, 'w', newline='') as file:
                writer = csv.DictWriter(file, fieldnames=self.get_fieldnames())
                writer.writeheader()

    def get_fieldnames(self):
        # Retourne les noms des colonnes pour le fichier CSV
        return ['timestamp', 'entropy_src_ip', 'entropy_dst_ip', 'window_tx',
                'median_packet_size', 'mean_packet_size', 'std_dev_packet_size',
                'packet_frequency', 'unique_ip', 'tcp_count', 'udp_count', 'icmp_count', 'type_attack']

    def calculate_in_out_ratio(self):
        # Calcul du ratio des paquets entrants et sortants
        input_packets = sum(1 for (_, src, _, _) in self.window_packets if src == 'local_IP')
        output_packets = sum(1 for (_, _, dst, _) in self.window_packets if dst == 'local_IP')
        return input_packets / output_packets if output_packets else 0

    def unique_ip_count(self):
        # Retourne le nombre d'adresses IP uniques
        src_ips = [src for (_, src, _, _) in self.window_packets]
        return len(src_ips)

    def calculate_active_window_duration(self):
        # Calcul de la durée d'activité réelle de la fenêtre
        if self.window_packets:
            start_time = min(t for (t, _, _, _) in self.window_packets)
            end_time = max(t for (t, _, _, _) in self.window_packets)
            return (end_time - start_time).total_seconds()
        return 0

    def write_window_statistics(self):
        if not self.window_packets:
            return  # Si aucune donnée, ne rien faire

        current_time = datetime.datetime.now()
        src_ips = [s for (_, s, _, _) in self.window_packets]
        dst_ips = [d for (_, _, d, _) in self.window_packets]
        total_tx = sum(l for (_, _, _, l) in self.window_packets)
        entropy_src = calculate_entropy(src_ips)
        entropy_dst = calculate_entropy(dst_ips)
        median_packet_size, mean_packet_size, std_dev_packet_size = self.packet_statistics(self.window_packets)
        packet_frequency = self.calculate_packet_frequency()
        unique_ips = self.unique_ip_count()

        # Création d'une matrice de caractéristiques pour la prédiction
        features = pd.DataFrame([{
            'entropy_src_ip': entropy_src,
            'entropy_dst_ip': entropy_dst,
            'window_tx': total_tx,
            'median_packet_size': median_packet_size,
            'mean_packet_size': mean_packet_size,
            'std_dev_packet_size': std_dev_packet_size,
            'packet_frequency': packet_frequency,
            'unique_ip': unique_ips,
            'tcp_count': self.tcp_count,
            'udp_count': self.udp_count,
            'icmp_count': self.icmp_count
        }])
        
        # Prédiction
        prediction = rf_model.predict(features)
        # Récupérer le nom de l'attaque prédit
        with attack_lock:
            global current_attack_type
            previous_attack_type = current_attack_type
            current_attack_type = prediction[0] if prediction else "Normal"
            detected_attacks.append((current_time.strftime("%Y-%m-%d %H:%M:%S"), current_attack_type))
        
        # Imprimer la prédiction numérique
        print("Raw Prediction:", prediction)  
        # Logging pour diagnostic
        print(f"Predicted: {current_attack_type}, Features: {features.iloc[0].to_dict()}")
        
        # Gérer les adresses IP en fonction du type d'attaque détecté
        if current_attack_type == "Normal":
            self.update_ip_list(green_ip_file, src_ips, add=True)
            print(f"Trafic {current_attack_type}")
            if previous_attack_type != "Normal":
                detection_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                send_normal_traffic_alert(detection_time)
        else:
            self.update_ip_list(red_ip_file, src_ips, add=True)
            print(f"Attaque detectée : {current_attack_type}")
            detection_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
            send_attack_alert(current_attack_type, detection_time)  # Envoi d'email en cas de détection d'attaque

        # Vérification des correspondances d'adresses ip entre les fichiers green_ip et red_ip
        conflicting_ips = self.check_conflicting_ips()
        if conflicting_ips:
            print("Il y a eu conflit entre des adresses ip")
            send_validation_request(conflicting_ips)
            self.update_ip_list(pending_validation_ip_file, conflicting_ips, add=True)

        new_row = {
            'timestamp': current_time.strftime("%Y-%m-%d %H:%M:%S"),
            'entropy_src_ip': entropy_src,
            'entropy_dst_ip': entropy_dst,
            'window_tx': total_tx,
            'median_packet_size': median_packet_size,
            'mean_packet_size': mean_packet_size,
            'std_dev_packet_size': std_dev_packet_size,
            'unique_ip': unique_ips,
            'packet_frequency': packet_frequency,
            'tcp_count': self.tcp_count,
            'udp_count': self.udp_count,
            'icmp_count': self.icmp_count,
            'type_attack': current_attack_type
        }

        with open(self.filename, 'a', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=self.get_fieldnames())
            writer.writerow(new_row)

        self.window_packets = []  # Efface la fenetre de paquets utilisé 
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0

        # Exécuter le playbook Ansible pour les IPs rouges
        # self.run_ansible_playbook_for_red_ips()

    def update_ip_list(self, filename, ip_list, add=True):
        existing_ips = set()
        if os.path.isfile(filename):
            with open(filename, 'r') as file:
                existing_ips = set(line.strip() for line in file)
        
        if add:
            updated_ips = existing_ips | set(ip_list)
        else:
            updated_ips = existing_ips - set(ip_list)
        
        with open(filename, 'w') as file:
            for ip in updated_ips:
                file.write(f"{ip}\n")

    def check_conflicting_ips(self):
        green_ips = set()
        red_ips = set()
        pending_ips = set()
        
        if os.path.isfile(green_ip_file):
            with open(green_ip_file, 'r') as file:
                green_ips = set(line.strip() for line in file)
        
        if os.path.isfile(red_ip_file):
            with open(red_ip_file, 'r') as file:
                red_ips = set(line.strip() for line in file)
        
        if os.path.isfile(pending_validation_ip_file):
            with open(pending_validation_ip_file, 'r') as file:
                pending_ips = set(line.strip() for line in file)

        # Retirer les IPs déjà en attente de validation
        conflicting_ips = (green_ips & red_ips) - pending_ips
        return list(conflicting_ips)

    def packet_statistics(self, packets):
        lengths = [l for (_, _, _, l) in packets]
        if not lengths:
            return 0, 0, 0
        return np.median(lengths), np.mean(lengths), np.std(lengths)

    def calculate_packet_frequency(self):
        if not self.window_packets:
            return 0
        start_time = min(t for (t, _, _, _) in self.window_packets)
        end_time = max(t for (t, _, _, _) in self.window_packets)
        duration = (end_time - start_time).total_seconds()
        if duration > 0:
            return len(self.window_packets) / duration
        return 0

    def process_packet(self, packet):
        current_time = datetime.datetime.now()

        if IP not in packet:
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        if TCP in packet:
            self.tcp_count += 1
        elif UDP in packet:
            self.udp_count += 1
        elif ICMP in packet:
            self.icmp_count += 1

        length = len(packet)

        self.window_packets.append((current_time, src_ip, dst_ip, length))
        if (current_time - self.last_write_time).total_seconds() >= self.window_size:
            self.write_window_statistics()
            self.last_write_time = current_time

    def start_capture(self):
        sniff(prn=self.process_packet, store=False)

    def run_ansible_playbook_for_red_ips(self):
        red_ips = set()
        pending_ips = set()

        # Lire les IPs des fichiers
        if os.path.isfile(red_ip_file):
            with open(red_ip_file, 'r') as file:
                red_ips = set(line.strip() for line in file)
        
        if os.path.isfile(pending_validation_ip_file):
            with open(pending_validation_ip_file, 'r') as file:
                pending_ips = set(line.strip() for line in file)
        
        # Filtrer les IPs pour exclure celles en attente de validation
        filtered_red_ips = red_ips - pending_ips

        if not filtered_red_ips:
            print("Aucune IP rouge à traiter.")
            return
        
        # Créer un inventaire Ansible dynamique
        inventory_content = "[ddos_targets]\n" + "\n".join(filtered_red_ips)
        inventory_path = "red_ips_inventory.ini"

        with open(inventory_path, 'w') as inventory_file:
            inventory_file.write(inventory_content)
        
        # Exécuter le playbook Ansible
        playbook_path = "ddos_mitigation_playbook.yml"
        subprocess.run(["ansible-playbook", "-i", inventory_path, playbook_path])

class NetworkMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Monitor")
        self.root.geometry("800x600")  # Définir la taille de la fenêtre
        
        self.create_widgets()
        self.update_gui()
    
    def create_widgets(self):
        # Section pour les attaques en cours
        frame_current_attacks = tk.LabelFrame(self.root, text="Attaques en cours", padx=10, pady=10)
        frame_current_attacks.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.label_current_attack = tk.Label(frame_current_attacks, text=f"Santé du réseau : {current_attack_type}", font=("Arial", 14))
        self.label_current_attack.pack(anchor="w")
        
        self.text_area_current = scrolledtext.ScrolledText(frame_current_attacks, width=80, height=5, font=("Arial", 12))
        self.text_area_current.pack(fill="both", expand=True)

        # Section pour l'historique des attaques
        frame_attack_history = tk.LabelFrame(self.root, text="Historique des attaques détectées", padx=10, pady=10)
        frame_attack_history.pack(fill="both", expand=True, padx=10, pady=5)

        columns = ('#1', '#2')
        self.tree = ttk.Treeview(frame_attack_history, columns=columns, show='headings')
        self.tree.heading('#1', text='Temps')
        self.tree.heading('#2', text='Type d\'attaque')
        self.tree.pack(fill="both", expand=True)

    def update_gui(self):
        with attack_lock:
            self.label_current_attack.config(text=f"Santé du réseau: {current_attack_type}")
            
            self.text_area_current.delete(1.0, tk.END)
            
            # L'ancien contenu du tableau
            for row in self.tree.get_children():
                self.tree.delete(row)
            
            # Ajouter les nouvelles entrées
            for timestamp, attack in detected_attacks:
                self.tree.insert('', tk.END, values=(timestamp, attack))
        
        self.root.after(1000, self.update_gui)  # Mettre à jour toutes les secondes

def main():
    collector = NetworkDataCollector(window_size=5, filename='datasets/network_data_grouped_model_ibra_rm_ansible.csv')
    thread = Thread(target=collector.start_capture)
    thread.start()
    
    client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message
    client.on_disconnect = on_disconnect

    try:
        client.connect("192.168.3.109", 1883)
    except Exception as e:
        print(f"Une erreur est survenue : {e}")
        
    thread2 = Thread(target=manage_connection, args=(client,))
    thread2.start()
    client.loop_start()

    # Initialisation de l'interface graphique
    root = tk.Tk()
    gui = NetworkMonitorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
