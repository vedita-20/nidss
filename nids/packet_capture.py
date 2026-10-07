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


def process_packet(packet):

    try:

        # --------------------------------
        # GET ACTUAL PACKET INFORMATION
        # --------------------------------

        connection = get_packet_connection_info(packet)

        if connection is None:
            return

        source_ip, destination_ip, source_port, destination_port = connection


        # --------------------------------
        # ADD PACKET TO FLOW
        # --------------------------------

        flow_key, packet_count = add_packet(packet)

        if flow_key is None:
            return

        protocol = flow_key[4]


        # --------------------------------
        # DISPLAY PACKET
        # --------------------------------

        print(
            f"\n[PACKET] "
            f"{source_ip}:{source_port} -> "
            f"{destination_ip}:{destination_port} "
            f"| Protocol: {protocol} "
            f"| Flow packets: {packet_count}"
        )


        # --------------------------------
        # DETECT EVERY 10 PACKETS
        # --------------------------------

        if packet_count % PACKETS_PER_CHECK != 0:
            return


        print("\n[DETECTION] Analyzing network flow...")


        # --------------------------------
        # EXTRACT FEATURES
        # --------------------------------

        features = get_features_for_flow(flow_key)


        # --------------------------------
        # XGBOOST DETECTION
        # --------------------------------

        result = detect(features)


        # --------------------------------
        # CALCULATE FLOW INFORMATION
        # --------------------------------

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
            total_fwd_bytes + total_bwd_bytes
        )


        # --------------------------------
        # DISPLAY RESULT
        # --------------------------------

        print("\n")
        print("=" * 60)
        print("NIDS DETECTION RESULT")
        print("=" * 60)

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


        # --------------------------------
        # DISPLAY FEATURES
        # --------------------------------

        print("\nFeatures used by XGBoost:")

        for feature, value in result["features"].items():

            print(
                f"{feature}: {value}"
            )


        # --------------------------------
        # SAVE TO NEON DATABASE
        # --------------------------------

        save_detection(
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            protocol=protocol,
            packet_count=packet_count,
            flow_duration=flow_duration,
            total_bytes=total_bytes,
            result=result
        )


    except Exception as e:

        print(
            f"\n[ERROR] Packet processing failed: {e}"
        )


def start_capture():

    print("\n")
    print("=" * 60)
    print("NIDS LIVE PACKET CAPTURE")
    print("=" * 60)

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
            prn=process_packet,
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


if __name__ == "__main__":

    start_capture()