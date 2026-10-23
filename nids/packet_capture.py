import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from scapy.all import sniff, IP, TCP, UDP

from nids.feature_extraction import (
    add_packet,
    get_features_for_flow
)

from nids.detector import detect

from nids.database_logger import save_detection


PACKETS_PER_CHECK = 10


# ========================================
# GET PACKET CONNECTION INFORMATION
# ========================================

def get_packet_connection_info(packet):

    if not packet.haslayer(IP):
        return None

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

    source_port = 0
    destination_port = 0

    if packet.haslayer(TCP):

        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif packet.haslayer(UDP):

        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    return (
        source_ip,
        destination_ip,
        source_port,
        destination_port
    )


# ========================================
# PROCESS PACKET
# ========================================

def process_packet(packet, user_id, app):

    try:

        connection = get_packet_connection_info(packet)

        if connection is None:
            return

        (
            source_ip,
            destination_ip,
            source_port,
            destination_port
        ) = connection


        flow_key, packet_count = add_packet(packet)

        if flow_key is None:
            return


        protocol = flow_key[4]


        print(
            f"\n[PACKET] "
            f"{source_ip}:{source_port} -> "
            f"{destination_ip}:{destination_port} "
            f"| Protocol: {protocol} "
            f"| Flow packets: {packet_count}",
            flush=True
        )


        if packet_count % PACKETS_PER_CHECK != 0:
            return


        print(
            "\n[DETECTION] Analyzing network flow...",
            flush=True
        )


        features = get_features_for_flow(flow_key)

        result = detect(features)


        flow_duration = features.get(
            "Flow Duration",
            0
        )


        total_fwd_bytes = features.get(
            "Total Length of Fwd Packets",
            0
        )


        total_bwd_bytes = features.get(
            "Total Length of Bwd Packets",
            0
        )


        total_bytes = int(
            total_fwd_bytes +
            total_bwd_bytes
        )


        print("\n")
        print("=" * 60)
        print("NIDS DETECTION RESULT")
        print("=" * 60)


        print(
            f"User ID     : {user_id}"
        )


        print(
            f"Source      : "
            f"{source_ip}:{source_port}"
        )


        print(
            f"Destination : "
            f"{destination_ip}:{destination_port}"
        )


        print(
            f"Protocol    : {protocol}"
        )


        print(
            f"Prediction  : "
            f"{result['prediction']}"
        )


        print(
            f"Confidence  : "
            f"{result['confidence']}%"
        )


        print(
            f"Normal Prob : "
            f"{result['normal_probability']}%"
        )


        print(
            f"Attack Prob : "
            f"{result['attack_probability']}%"
        )


        print(
            f"Risk Score  : "
            f"{result['risk_score']}"
        )


        print(
            f"Severity    : "
            f"{result['severity']}"
        )


        print("=" * 60)


        print("\nFeatures used by XGBoost:")

        for feature, value in result["features"].items():

            print(
                f"{feature}: {value}"
            )


        save_detection(

            source_ip=source_ip,

            destination_ip=destination_ip,

            source_port=source_port,

            destination_port=destination_port,

            protocol=protocol,

            packet_count=packet_count,

            flow_duration=flow_duration,

            total_bytes=total_bytes,

            result=result,

            user_id=user_id,

            app=app
        )


    except Exception as e:

        print(
            f"\n[ERROR] Packet processing failed: {e}",
            flush=True
        )


# ========================================
# START PACKET CAPTURE
# ========================================

def start_capture(user_id, app):

    print("\n")
    print("=" * 60)
    print("NIDS LIVE PACKET CAPTURE")
    print("=" * 60)


    print(
        f"\nMonitoring for logged-in user ID: {user_id}"
    )


    print(
        "\nStarting network monitoring..."
    )


    print(
        "Press CTRL+C to stop."
    )


    print(
        f"\nDetection interval: "
        f"every {PACKETS_PER_CHECK} "
        f"packets per flow."
    )


    print(
        "\nWaiting for network traffic...\n"
    )


    try:

        sniff(
            prn=lambda packet: process_packet(
                packet,
                user_id,
                app
            ),
            store=False
        )


    except KeyboardInterrupt:

        print(
            "\n\nPacket capture stopped by user."
        )


    except PermissionError:

        print(
            "\n[ERROR] Permission denied."
        )

        print(
            "Run PowerShell as Administrator."
        )


    except Exception as e:

        print(
            f"\n[ERROR] Packet capture failed: {e}"
        )


# ========================================
# DIRECT BACKEND TESTING
# ========================================

if __name__ == "__main__":

    print("\n")
    print("=" * 60)
    print("NIDS PACKET CAPTURE - DIRECT TEST")
    print("=" * 60)

    try:

        # Import app only when this file
        # is directly executed.
        #
        # This does NOT create the circular
        # import problem during normal Flask use.

        from app import app

        print("\nFlask application loaded successfully.")

        user_id_input = input(
            "\nEnter user ID to monitor: "
        ).strip()

        if not user_id_input:

            print(
                "\n[ERROR] User ID is required."
            )

            sys.exit(1)

        try:

            user_id = int(
                user_id_input
            )

        except ValueError:

            print(
                "\n[ERROR] User ID must be an integer."
            )

            sys.exit(1)


        print(
            f"\nStarting capture for user ID: {user_id}"
        )


        start_capture(
            user_id,
            app
        )


    except KeyboardInterrupt:

        print(
            "\n\nPacket capture stopped."
        )


    except Exception as e:

        print(
            "\n[ERROR] Could not start packet capture:"
        )

        print(
            f"{type(e).__name__}: {e}"
        )