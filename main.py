import csv
from collections import defaultdict
import sys

# Define the protocol lookup table
protocol_lookup = {
    0: "HOPOPT",
    1: "ICMP",
    2: "IGMP",
    3: "GGP",
    4: "IPv4",
    5: "ST",
    6: "TCP",
    7: "CBT",
    8: "EGP",
    9: "IGP",
    10: "BBN-RCC-MON",
    11: "NVP-II",
    12: "PUP",
    13: "ARGUS (deprecated)",
    14: "EMCON",
    15: "XNET",
    16: "CHAOS",
    17: "UDP",
    18: "MUX",
    19: "DCN-MEAS",
    20: "HMP",
    21: "PRM",
    22: "XNS-IDP",
    23: "TRUNK-1",
    24: "TRUNK-2",
    25: "LEAF-1",
    26: "LEAF-2",
    27: "RDP",
    28: "IRTP",
    29: "ISO-TP4",
    30: "NETBLT",
    31: "MFE-NSP",
    32: "MERIT-INP",
    33: "DCCP",
    34: "3PC",
    35: "IDPR",
    36: "XTP",
    37: "DDP",
    38: "IDPR-CMTP",
    39: "TP++",
    40: "IL",
    41: "IPv6",
    42: "SDRP",
    43: "IPv6-Route",
    44: "IPv6-Frag",
    45: "IDRP",
    46: "RSVP",
    47: "GRE",
    48: "DSR",
    49: "BNA",
    50: "ESP",
    51: "AH",
    52: "I-NLSP",
    53: "SWIPE (deprecated)",
    54: "NARP",
    55: "Min-IPv4",
    56: "TLSP",
    57: "SKIP",
    58: "IPv6-ICMP",
    59: "IPv6-NoNxt",
    60: "IPv6-Opts",
    61: "any host internal protocol",
    62: "CFTP",
    63: "any local network",
    64: "SAT-EXPAK",
    65: "KRYPTOLAN",
    66: "RVD",
    67: "IPPC",
    68: "any distributed file system",
    69: "SAT-MON",
    70: "VISA",
    71: "IPCV",
    72: "CPNX",
    73: "CPHB",
    74: "WSN",
    75: "PVP",
    76: "BR-SAT-MON",
    77: "SUN-ND",
    78: "WB-MON",
    79: "WB-EXPAK",
    80: "ISO-IP",
    81: "VMTP",
    82: "SECURE-VMTP",
    83: "VINES",
    84: "IPTM",
    85: "NSFNET-IGP",
    86: "DGP",
    87: "TCF",
    88: "EIGRP",
    89: "OSPFIGP",
    90: "Sprite-RPC",
    91: "LARP",
    92: "MTP",
    93: "AX.25",
    94: "IPIP",
    95: "MICP (deprecated)",
    96: "SCC-SP",
    97: "ETHERIP",
    98: "ENCAP",
    99: "any private encryption scheme",
    100: "GMTP",
    101: "IFMP",
    102: "PNNI",
    103: "PIM",
    104: "ARIS",
    105: "SCPS",
    106: "QNX",
    107: "A/N",
    108: "IPComp",
    109: "SNP",
    110: "Compaq-Peer",
    111: "IPX-in-IP",
    112: "VRRP",
    113: "PGM",
    114: "any 0-hop protocol",
    115: "L2TP",
    116: "DDX",
    117: "IATP",
    118: "STP",
    119: "SRP",
    120: "UTI",
    121: "SMP",
    122: "SM (deprecated)",
    123: "PTP",
    124: "ISIS over IPv4",
    125: "FIRE",
    126: "CRTP",
    127: "CRUDP",
    128: "WESP",
    129: "ROHC",
    130: "Ethernet",
    131: "VLAN",
    132: "PPP",
    133: "RSTP",
    134: "MPLS",
    135: "IPv6-ICMP",
    136: "KARP",
    137: "PIM-SM",
    138: "PIM-DM",
    139: "RSVP-TE",
    140: "MPLS-TP",
    141: "IPSEC",
    142: "SCTP",
    143: "BGP",
    144: "SPX",
    145: "NAT"
}


def load_lookup_table(file_path):
    """
    Loads a lookup table from a CSV file.
    Each entry is a combination of destination port and protocol with a tag.
    Handles duplicate entries by keeping the last occurrence.
    Returns: dict{(int, str): str}
    """
    lookup_table = {}
    with open(file_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            key = (int(row['dstport']), row['protocol'].lower())
            lookup_table[key] = row['tag']
    return lookup_table


def parse_flow_logs(log_file_path, lookup_table):
    """
    Parses flow logs to count tags and port/protocol combinations.
    Reads data in 1MB chunks for memory efficiency.
    Returns: tuple(dict{str: int}, dict{(int, str): int})
    """
    chunk_size = 1024 * 1024 # Read in 1MB chunks
    tag_counts = defaultdict(int)
    port_protocol_counts = defaultdict(int)

    with open(log_file_path, 'r') as f:
        while True:
            lines = f.readlines(chunk_size)
            if not lines:
                break

            for line in lines:
                columns = line.strip().split()
                if len(columns) < 8:
                    continue  # Skip lines that don't have enough columns

                srcport = int(columns[5])

                dstport = int(columns[6])
                protocol_number = int(columns[7])
                protocol = protocol_lookup.get(protocol_number, 'unknown').lower()

                # Check for matching tag
                tag = lookup_table.get((dstport, protocol))
                if tag:
                    tag_counts[tag] += 1
                    port_protocol_counts[(dstport, protocol)] += 1  # Count for matched tag
                else:
                    # port_protocol_counts[(dstport, protocol)] += 1
                    tag_counts["Untagged"] += 1
    return tag_counts, port_protocol_counts


def write_output_to_file(tag_counts, port_protocol_counts, output_file_path):
    """
    Writes tag counts and port/protocol counts to an output file.
    Format: Tag, Count | Port, Protocol, Count
    Returns: None
    """
    with open(output_file_path, 'w') as f:
        # Write tag counts
        f.write("Tag Counts:\n")
        for tag, count in tag_counts.items():
            f.write(f"{tag},{count}\n")

        # Write port/protocol counts
        f.write("\nPort,Protocol,Count\n")
        for (port, protocol), count in port_protocol_counts.items():
            f.write(f"{port},{protocol},{count}\n")


def validate_file(file_path):
    """
    Validates that a file exists and is non-empty.
    If invalid, prints an error and exits.
    Returns: None
    """
    try:
        with open(file_path, 'r') as f:
            if f.readable() and f.read().strip() == '':
                print(f"Error: The file '{file_path}' is empty.")
                sys.exit(1)
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' does not exist.")
        sys.exit(1)


if __name__ == "__main__":
    # Check for correct number of arguments
    if len(sys.argv) != 3:
        print("Usage: python main.py <flow_logs_file.txt> <lookup_file.csv> ")
        sys.exit(1)

    flow_logs_file = sys.argv[1]  # Input flow logs file
    lookup_file = sys.argv[2]  # Input lookup table file

    # Validate file extensions
    if not flow_logs_file.endswith('.txt'):
        print("Error: The flow logs file must be a .txt file.")
        sys.exit(1)

    if not lookup_file.endswith('.csv'):
        print("Error: The lookup table file must be a .csv file.")
        sys.exit(1)

    # Validate the files
    validate_file(flow_logs_file)
    validate_file(lookup_file)

    lookup_table = load_lookup_table(lookup_file)

    tag_counts, port_protocol_counts = parse_flow_logs(flow_logs_file, lookup_table)

    output_file = 'output_file.txt'
    # Write the results to the output file
    write_output_to_file(tag_counts, port_protocol_counts, output_file)

    print("please check output_file for generated output")
