import re
import paramiko
import json
import subprocess
import configparser

# Step 1: Read JSON file and extract IP address
with open('data.json') as file:
    data = json.load(file)

source_ip = data['IPV4_SRC_ADDR']
print("Source IP Address:", source_ip)        #output src addr


def ssh_command(ip, username, password, command):
    """Execute a command over SSH and return the output."""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password)
        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode()
        ssh.close()
        return output
    except Exception as e:
        print(f"Error executing SSH command: {e}")
        return ""

def get_mac_table(ip, username, password):
    """Get the MAC address table from the FortiGate device."""
    command = 'diagnose switch-controller switch-info mac-table'
    mac_table = ssh_command(ip, username, password, command)

    # Regex to capture each switch ID section
    switch_sections = re.split(r'^\S+        0\s*:\s*$', mac_table, flags=re.MULTILINE)

    switch_data = {}

    # Parse each switch section
    for section in switch_sections:
        if not section.strip():
            continue
        lines = section.strip().split('\n')
        switch_id = lines[0].strip()
        entries = lines[1:]
        mac_entries = re.findall(r'(\S+)\s+(\S+)\s+(\d+)', '\n'.join(entries))
        switch_data[switch_id] = mac_entries

    return switch_data

def find_mac_from_ip(ip_address, ip, username, password):
    """Find the MAC address from the ARP table using the IP address."""
    command = 'get system arp'
    arp_table = ssh_command(ip, username, password, command)
    arp_entries = re.findall(r'(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\S+)', arp_table)

    for ip, mac in arp_entries:
        if ip == ip_address:
            return mac
    return None

def find_switch_and_port(mac_address, switch_data):
    """Find the switch ID and port from the MAC address table using the MAC address."""
    for switch_id, entries in switch_data.items():
        for mac, interface, vlan in entries:
            if mac == mac_address:
                return switch_id, interface
    return None, None

def main(ip_address, fortigate_ip, username, password):
    """Main function to find the switch ID and port from the IP address."""
    mac_address = find_mac_from_ip(ip_address, fortigate_ip, username, password)

    if mac_address:
        switch_data = get_mac_table(fortigate_ip, username, password)
        switch_id, port = find_switch_and_port(mac_address, switch_data)

        if switch_id and port:
            print(f"IP Address: {ip_address}")
            print(f"MAC Address: {mac_address}")
            print(f"Switch ID: {switch_id}")
            print(f"Port: {port}")

            # Prepare command to disable the port
            disable_port_command = f"""
            config switch-controller managed-switch
            edit "S448DNTF19001580"
            config ports
            edit {port}
            set status down
            next
            end
            end
            """
            block_switch_port(fortigate_ip, username, password, disable_port_command)

        else:
            print(f"MAC address {mac_address} not found in MAC address table.")
    else:
        print(f"IP address {ip_address} not found in ARP table.")

def block_switch_port(fortigate_ip, username, password, command):
    """Block the specified port on the switch."""
    try:
        # Establish SSH connection
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(fortigate_ip, username=username, password=password)

        # Execute the command
        stdin, stdout, stderr = ssh.exec_command(command)
        stdout.channel.recv_exit_status()

        # Print output and close connection
        print(stdout.read().decode())
        ssh.close()

    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
     # Create a ConfigParser object
    config = configparser.ConfigParser()
     # Read the configuration file
    config.read('config.ini')

    debug_mode = config.getboolean('General', 'debug')
    log_level = config.get('General', 'log_level')

    ip = config.get('Settings', 'fortigate_ip')
    user = config.get('Settings', 'username')
    psw = config.get('Settings', 'password')

    ip_to_lookup = source_ip  # Replace with the IP address you want to look up
    
    fortigate_ip = config.get('Settings', 'fortigate_ip')  # Replace in config your FortiGate IP address
    username = config.get('Settings', 'username') # Replace in config with your FortiGate username
    password = config.get('Settings', 'password')  # Replace in config with your FortiGate password
    main(ip_to_lookup, fortigate_ip, username, password)
