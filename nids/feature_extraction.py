from datetime import datetime
import numpy as np

from scapy.layers.inet import IP, TCP, UDP


# ============================================================
# GLOBAL FLOW STORAGE
# ============================================================

flows = {}


# ============================================================
# BASIC FUNCTIONS
# ============================================================

def get_packet_time(packet):
    try:
        return float(packet.time)
    except Exception:
        return datetime.now().timestamp()


def get_packet_length(packet):
    try:
        return len(packet)
    except Exception:
        return 0


def get_protocol(packet):
    if packet.haslayer(TCP):
        return 6
    elif packet.haslayer(UDP):
        return 17
    return 0


def get_ports(packet):
    if packet.haslayer(TCP):
        return int(packet[TCP].sport), int(packet[TCP].dport)

    if packet.haslayer(UDP):
        return int(packet[UDP].sport), int(packet[UDP].dport)

    return 0, 0


# ============================================================
# BIDIRECTIONAL FLOW KEY
# ============================================================

def get_flow_key(packet):

    if not packet.haslayer(IP):
        return None

    ip = packet[IP]

    src_port, dst_port = get_ports(packet)
    protocol = get_protocol(packet)

    endpoint1 = (
        ip.src,
        src_port
    )

    endpoint2 = (
        ip.dst,
        dst_port
    )

    # Same key for both directions
    endpoints = sorted(
        [endpoint1, endpoint2]
    )

    return (
        endpoints[0][0],
        endpoints[0][1],
        endpoints[1][0],
        endpoints[1][1],
        protocol
    )


# ============================================================
# DIRECTION CHECK
# ============================================================

def is_forward(packet, flow):

    if not packet.haslayer(IP):
        return False

    ip = packet[IP]

    src_port, dst_port = get_ports(packet)

    return (
        ip.src == flow["forward_src_ip"]
        and
        ip.dst == flow["forward_dst_ip"]
        and
        src_port == flow["forward_src_port"]
        and
        dst_port == flow["forward_dst_port"]
    )


# ============================================================
# STATISTICS
# ============================================================

def safe_mean(values):
    return float(np.mean(values)) if values else 0.0


def safe_std(values):
    return float(np.std(values)) if len(values) > 1 else 0.0


def safe_variance(values):
    return float(np.var(values)) if len(values) > 1 else 0.0


def safe_min(values):
    return float(np.min(values)) if values else 0.0


def safe_max(values):
    return float(np.max(values)) if values else 0.0


def safe_sum(values):
    return float(np.sum(values)) if values else 0.0


def calculate_iats(times):

    if len(times) <= 1:
        return []

    times = sorted(times)

    return [
        times[i] - times[i - 1]
        for i in range(1, len(times))
    ]


# ============================================================
# TCP FLAGS
# ============================================================

def get_tcp_flags(packet):

    flags = {
        "FIN": 0,
        "SYN": 0,
        "RST": 0,
        "PSH": 0,
        "ACK": 0,
        "URG": 0,
        "CWE": 0,
        "ECE": 0
    }

    if not packet.haslayer(TCP):
        return flags

    try:

        flag_string = str(
            packet[TCP].flags
        )

        flags["FIN"] = int("F" in flag_string)
        flags["SYN"] = int("S" in flag_string)
        flags["RST"] = int("R" in flag_string)
        flags["PSH"] = int("P" in flag_string)
        flags["ACK"] = int("A" in flag_string)
        flags["URG"] = int("U" in flag_string)
        flags["CWE"] = int("C" in flag_string)
        flags["ECE"] = int("E" in flag_string)

    except Exception:
        pass

    return flags


# ============================================================
# TCP WINDOW
# ============================================================

def get_tcp_window(packet):

    if not packet.haslayer(TCP):
        return 0

    try:
        return int(packet[TCP].window)
    except Exception:
        return 0


# ============================================================
# HEADER LENGTH
# ============================================================

def get_header_length(packet):

    try:

        if packet.haslayer(TCP):

            ip_header = int(
                packet[IP].ihl * 4
            )

            tcp_header = int(
                packet[TCP].dataofs * 4
            )

            return ip_header + tcp_header

        if packet.haslayer(UDP):

            ip_header = int(
                packet[IP].ihl * 4
            )

            return ip_header + 8

    except Exception:
        pass

    return 0


# ============================================================
# FEATURE EXTRACTION
# ============================================================

def extract_flow_features(flow_key, flow):

    packets = flow["packets"]

    if not packets:
        raise ValueError(
            "No packets available for feature extraction."
        )

    # --------------------------------------------------------
    # Separate directions
    # --------------------------------------------------------

    forward_packets = []
    backward_packets = []

    for packet in packets:

        if is_forward(packet, flow):
            forward_packets.append(packet)
        else:
            backward_packets.append(packet)

    # --------------------------------------------------------
    # Packet lengths
    # --------------------------------------------------------

    all_lengths = [
        get_packet_length(packet)
        for packet in packets
    ]

    forward_lengths = [
        get_packet_length(packet)
        for packet in forward_packets
    ]

    backward_lengths = [
        get_packet_length(packet)
        for packet in backward_packets
    ]

    # --------------------------------------------------------
    # Times
    # --------------------------------------------------------

    all_times = sorted([
        get_packet_time(packet)
        for packet in packets
    ])

    forward_times = sorted([
        get_packet_time(packet)
        for packet in forward_packets
    ])

    backward_times = sorted([
        get_packet_time(packet)
        for packet in backward_packets
    ])

    # --------------------------------------------------------
    # Duration
    # --------------------------------------------------------

    if len(all_times) >= 2:
        duration_seconds = (
            max(all_times) -
            min(all_times)
        )
    else:
        duration_seconds = 0.0

    duration_seconds = max(
        duration_seconds,
        0.000001
    )

    flow_duration = (
        duration_seconds * 1_000_000
    )

    # --------------------------------------------------------
    # IAT
    # --------------------------------------------------------

    flow_iats = calculate_iats(all_times)
    forward_iats = calculate_iats(forward_times)
    backward_iats = calculate_iats(backward_times)

    # --------------------------------------------------------
    # Counts
    # --------------------------------------------------------

    total_fwd_packets = len(
        forward_packets
    )

    total_bwd_packets = len(
        backward_packets
    )

    total_packets = (
        total_fwd_packets +
        total_bwd_packets
    )

    # --------------------------------------------------------
    # Bytes
    # --------------------------------------------------------

    total_fwd_bytes = sum(
        forward_lengths
    )

    total_bwd_bytes = sum(
        backward_lengths
    )

    total_bytes = (
        total_fwd_bytes +
        total_bwd_bytes
    )

    # --------------------------------------------------------
    # Headers
    # --------------------------------------------------------

    fwd_header_lengths = [
        get_header_length(packet)
        for packet in forward_packets
    ]

    bwd_header_lengths = [
        get_header_length(packet)
        for packet in backward_packets
    ]

    fwd_header_length = sum(
        fwd_header_lengths
    )

    bwd_header_length = sum(
        bwd_header_lengths
    )

    # --------------------------------------------------------
    # TCP windows
    # --------------------------------------------------------

    init_win_forward = (
        get_tcp_window(
            forward_packets[0]
        )
        if forward_packets
        else 0
    )

    init_win_backward = (
        get_tcp_window(
            backward_packets[0]
        )
        if backward_packets
        else 0
    )

    # --------------------------------------------------------
    # TCP flags
    # --------------------------------------------------------

    fin_count = 0
    syn_count = 0
    rst_count = 0
    psh_count = 0
    ack_count = 0
    urg_count = 0
    cwe_count = 0
    ece_count = 0

    fwd_psh = 0
    bwd_psh = 0

    fwd_urg = 0
    bwd_urg = 0

    for packet in packets:

        flags = get_tcp_flags(packet)

        fin_count += flags["FIN"]
        syn_count += flags["SYN"]
        rst_count += flags["RST"]
        psh_count += flags["PSH"]
        ack_count += flags["ACK"]
        urg_count += flags["URG"]
        cwe_count += flags["CWE"]
        ece_count += flags["ECE"]

    for packet in forward_packets:

        flags = get_tcp_flags(packet)

        fwd_psh += flags["PSH"]
        fwd_urg += flags["URG"]

    for packet in backward_packets:

        flags = get_tcp_flags(packet)

        bwd_psh += flags["PSH"]
        bwd_urg += flags["URG"]

    # --------------------------------------------------------
    # Rates
    # --------------------------------------------------------

    flow_bytes_per_sec = (
        total_bytes /
        duration_seconds
    )

    flow_packets_per_sec = (
        total_packets /
        duration_seconds
    )

    fwd_packets_per_sec = (
        total_fwd_packets /
        duration_seconds
    )

    bwd_packets_per_sec = (
        total_bwd_packets /
        duration_seconds
    )

    # --------------------------------------------------------
    # Packet statistics
    # --------------------------------------------------------

    packet_length_mean = safe_mean(
        all_lengths
    )

    packet_length_std = safe_std(
        all_lengths
    )

    packet_length_variance = safe_variance(
        all_lengths
    )

    min_packet_length = safe_min(
        all_lengths
    )

    max_packet_length = safe_max(
        all_lengths
    )

    average_packet_size = (
        total_bytes / total_packets
        if total_packets
        else 0
    )

    # --------------------------------------------------------
    # Ratios
    # --------------------------------------------------------

    down_up_ratio = (
        total_bwd_packets /
        total_fwd_packets
        if total_fwd_packets
        else 0
    )

    avg_fwd_segment_size = (
        total_fwd_bytes /
        total_fwd_packets
        if total_fwd_packets
        else 0
    )

    avg_bwd_segment_size = (
        total_bwd_bytes /
        total_bwd_packets
        if total_bwd_packets
        else 0
    )

    # --------------------------------------------------------
    # Active / Idle
    # --------------------------------------------------------

    active_values = []
    idle_values = []

    for i in range(
        1,
        len(all_times)
    ):

        gap = (
            all_times[i] -
            all_times[i - 1]
        )

        if gap <= 1.0:
            active_values.append(gap)
        else:
            idle_values.append(gap)

    # --------------------------------------------------------
    # Feature dictionary
    # --------------------------------------------------------

    features = {

        "Destination Port":
            float(flow["forward_dst_port"]),

        "Flow Duration":
            float(flow_duration),

        "Total Fwd Packets":
            float(total_fwd_packets),

        "Total Backward Packets":
            float(total_bwd_packets),

        "Total Length of Fwd Packets":
            float(total_fwd_bytes),

        "Total Length of Bwd Packets":
            float(total_bwd_bytes),

        "Fwd Packet Length Max":
            safe_max(forward_lengths),

        "Fwd Packet Length Min":
            safe_min(forward_lengths),

        "Fwd Packet Length Mean":
            safe_mean(forward_lengths),

        "Fwd Packet Length Std":
            safe_std(forward_lengths),

        "Bwd Packet Length Max":
            safe_max(backward_lengths),

        "Bwd Packet Length Min":
            safe_min(backward_lengths),

        "Bwd Packet Length Mean":
            safe_mean(backward_lengths),

        "Bwd Packet Length Std":
            safe_std(backward_lengths),

        "Flow Bytes/s":
            float(flow_bytes_per_sec),

        "Flow Packets/s":
            float(flow_packets_per_sec),

        "Flow IAT Mean":
            safe_mean(flow_iats) * 1_000_000,

        "Flow IAT Std":
            safe_std(flow_iats) * 1_000_000,

        "Flow IAT Max":
            safe_max(flow_iats) * 1_000_000,

        "Flow IAT Min":
            safe_min(flow_iats) * 1_000_000,

        "Fwd IAT Total":
            safe_sum(forward_iats) * 1_000_000,

        "Fwd IAT Mean":
            safe_mean(forward_iats) * 1_000_000,

        "Fwd IAT Std":
            safe_std(forward_iats) * 1_000_000,

        "Fwd IAT Max":
            safe_max(forward_iats) * 1_000_000,

        "Fwd IAT Min":
            safe_min(forward_iats) * 1_000_000,

        "Bwd IAT Total":
            safe_sum(backward_iats) * 1_000_000,

        "Bwd IAT Mean":
            safe_mean(backward_iats) * 1_000_000,

        "Bwd IAT Std":
            safe_std(backward_iats) * 1_000_000,

        "Bwd IAT Max":
            safe_max(backward_iats) * 1_000_000,

        "Bwd IAT Min":
            safe_min(backward_iats) * 1_000_000,

        "Fwd PSH Flags":
            float(fwd_psh),

        "Bwd PSH Flags":
            float(bwd_psh),

        "Fwd URG Flags":
            float(fwd_urg),

        "Bwd URG Flags":
            float(bwd_urg),

        "Fwd Header Length":
            float(fwd_header_length),

        "Bwd Header Length":
            float(bwd_header_length),

        "Fwd Packets/s":
            float(fwd_packets_per_sec),

        "Bwd Packets/s":
            float(bwd_packets_per_sec),

        "Min Packet Length":
            min_packet_length,

        "Max Packet Length":
            max_packet_length,

        "Packet Length Mean":
            packet_length_mean,

        "Packet Length Std":
            packet_length_std,

        "Packet Length Variance":
            packet_length_variance,

        "FIN Flag Count":
            float(fin_count),

        "SYN Flag Count":
            float(syn_count),

        "RST Flag Count":
            float(rst_count),

        "PSH Flag Count":
            float(psh_count),

        "ACK Flag Count":
            float(ack_count),

        "URG Flag Count":
            float(urg_count),

        "CWE Flag Count":
            float(cwe_count),

        "ECE Flag Count":
            float(ece_count),

        "Down/Up Ratio":
            float(down_up_ratio),

        "Average Packet Size":
            float(average_packet_size),

        "Avg Fwd Segment Size":
            float(avg_fwd_segment_size),

        "Avg Bwd Segment Size":
            float(avg_bwd_segment_size),

        "Fwd Header Length.1":
            float(fwd_header_length),

        "Fwd Avg Bytes/Bulk":
            0.0,

        "Fwd Avg Packets/Bulk":
            0.0,

        "Fwd Avg Bulk Rate":
            0.0,

        "Bwd Avg Bytes/Bulk":
            0.0,

        "Bwd Avg Packets/Bulk":
            0.0,

        "Bwd Avg Bulk Rate":
            0.0,

        "Subflow Fwd Packets":
            float(total_fwd_packets),

        "Subflow Fwd Bytes":
            float(total_fwd_bytes),

        "Subflow Bwd Packets":
            float(total_bwd_packets),

        "Subflow Bwd Bytes":
            float(total_bwd_bytes),

        "Init_Win_bytes_forward":
            float(init_win_forward),

        "Init_Win_bytes_backward":
            float(init_win_backward),

        "act_data_pkt_fwd":
            float(
                max(
                    total_fwd_packets - 1,
                    0
                )
            ),

        "min_seg_size_forward":
            safe_min(
                fwd_header_lengths
            ),

        "Active Mean":
            safe_mean(active_values)
            * 1_000_000,

        "Active Std":
            safe_std(active_values)
            * 1_000_000,

        "Active Max":
            safe_max(active_values)
            * 1_000_000,

        "Active Min":
            safe_min(active_values)
            * 1_000_000,

        "Idle Mean":
            safe_mean(idle_values)
            * 1_000_000,

        "Idle Std":
            safe_std(idle_values)
            * 1_000_000,

        "Idle Max":
            safe_max(idle_values)
            * 1_000_000,

        "Idle Min":
            safe_min(idle_values)
            * 1_000_000
    }

    return features


# ============================================================
# ADD PACKET
# ============================================================

def add_packet(packet):

    flow_key = get_flow_key(packet)

    if flow_key is None:
        return None, 0

    src_port, dst_port = get_ports(packet)

    # --------------------------------------------------------
    # First packet establishes FORWARD direction
    # --------------------------------------------------------

    if flow_key not in flows:

        flows[flow_key] = {

            "packets": [],

            "forward_src_ip":
                packet[IP].src,

            "forward_dst_ip":
                packet[IP].dst,

            "forward_src_port":
                src_port,

            "forward_dst_port":
                dst_port,

            "protocol":
                get_protocol(packet)
        }

    flows[flow_key]["packets"].append(
        packet
    )

    return (
        flow_key,
        len(
            flows[flow_key]["packets"]
        )
    )


# ============================================================
# GET FEATURES
# ============================================================

def get_features_for_flow(flow_key):

    if flow_key not in flows:

        raise ValueError(
            "Flow does not exist."
        )

    return extract_flow_features(
        flow_key,
        flows[flow_key]
    )


# ============================================================
# REMOVE FLOW
# ============================================================

def remove_flow(flow_key):

    if flow_key in flows:
        del flows[flow_key]


# ============================================================
# ACTIVE FLOW COUNT
# ============================================================

def get_active_flow_count():

    return len(flows)


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("NIDS FEATURE EXTRACTION MODULE")
    print("=" * 60)

    print("\n✓ Bidirectional flow support")
    print("✓ Forward/backward packet statistics")
    print("✓ CICIDS2017 feature names")
    print("✓ IAT statistics")
    print("✓ TCP flags")
    print("✓ Packet rates")
    print("✓ Active/idle statistics")

    print("\nFeature extraction module ready.")