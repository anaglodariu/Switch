#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

SW_CAM = {}

root_bridge_ID = 0

# variables for a switch when doing STP
ports = {}
own_bridge_ID = 0
root_path_cost = 0

# set all trunk ports to listening
def setListening():
    for i in range(0, 4):
        if i in ports:
            ports[i] = 'Listening'

# initialize the switch
def initSwitch(switch_id):
    # set all trunk ports to blocking
    for i in range(0, 4):
        interface_name = get_interface_name(i)
        vlan = getVLANInterface(switch_id, i)
        if (vlan == 'T'):
            ports[i] = 'Blocking'
    global own_bridge_ID 
    own_bridge_ID = getPriority(switch_id)
    global root_bridge_ID
    root_bridge_ID = own_bridge_ID
    global root_path_cost
    root_path_cost = 0

    if own_bridge_ID == root_bridge_ID:
        setListening()


def getPriority(switch_id):
    with open('configs/switch' + switch_id + '.cfg', 'r') as config_file:
        line = config_file.readline()
        line = line.rstrip()
        priority = int(line)
        return priority
    
def create_bpdu_message():
    # get src mac of the switch
    src_MAC = get_switch_mac()
    # get dest mac in bytes
    dest_MAC = bytes([0x01, 0x80, 0xC2, 0x00, 0x00, 0x00])
    data = dest_MAC + src_MAC

    # create the LLC_HEADER
    # the DSAP, the SSAP, the control field
    llc_header = struct.pack('!BBB', 0x42, 0x42, 0x03)

    # reserve 35 bytes for the bpdu and make all the bytes 0
    bpdu_config = b'\x00' * 5
    # the sixth byte is the root bridge ID
    bpdu_config += struct.pack('!H', root_bridge_ID & 0x00FF)
    bpdu_config += b'\x00' * 6
    # the 14th byte is the root path cost
    bpdu_config += struct.pack('!I', root_path_cost)
    # the 18th byte is the sender bridge ID
    bpdu_config += struct.pack('!H', own_bridge_ID & 0x00FF)
    bpdu_config += b'\x00' * 16
    llc_length = len(llc_header) + len(bpdu_config)

    data += struct.pack('!H', llc_length) 
    data += llc_header + bpdu_config
    
    length = len(data)

    return data, length

def parse_bpdu(data):
    # get the root bridge ID
    root_bridge_ID = data[24]
    root_bridge_ID = int.from_bytes(data[23:25], byteorder='little')
    # get the root path cost
    root_path_cost = int.from_bytes(data[31:35], byteorder='little')
    # get the sender bridge ID
    sender_bridge_ID = int.from_bytes(data[35:37], byteorder='little')
    return root_bridge_ID, root_path_cost, sender_bridge_ID



def getVLANInterface(switch_id, interface):
    # look up in the configs folder in the file for the right switch
    # and return the VLAN of the interface or if it's type trunk
    interface_name = get_interface_name(interface)
    with open('configs/switch' + switch_id + '.cfg', 'r') as config_file:
        for line in config_file:
            if line.startswith(interface_name):
                line = line.split(' ')
                # take the endline character out
                line[1] = line[1].rstrip()
                return line[1]

# if the packet is received from a switch with bigger priority, then the packet is discarded
# otherwise the destination switch sends the packet to all the other switches with the updated info
def receive_bpdu(bpdu_root_bridge_ID, bpdu_cost, bpdu_sender_bridge_id, interface):
    global root_bridge_ID
    global root_path_cost
    if bpdu_root_bridge_ID < root_bridge_ID:
        # if the sender is still root (the priority is smaller)
        # then update the root bridge ID and the root path cost on the destination switch
        root_bridge_ID = bpdu_root_bridge_ID
        root_path_cost = bpdu_cost + 10
        # on what port the bpdu was received by the destination switch
        listening_port = interface

        if own_bridge_ID != root_bridge_ID:
            # at the beggining, every switch thinks he is the root bridge so
            # all the trunk ports are set to listening in function initSwitch
            # if the destination switch is not actually the root bridge
            # then change the state of the ports
            for i in range(0, 4):
                if i in ports and i != listening_port:
                    # all trunk ports are set to Blocking, except the port on which
                    # the packet was received
                    ports[i] = 'Blocking'
        
        if ports[listening_port] == 'Blocking':
            # if the port on which the bpdu was received was in blocking state
            # then it is changed to listening
            ports[listening_port] = 'Listening'

        # send the bpdu on all other trunk ports with updated root bridge ID and root path cost
        for i in range(0, 4):
            if i in ports and i != listening_port:
                data, length = create_bpdu_message()
                send_to_link(i, data, length)
    elif bpdu_sender_bridge_id == own_bridge_ID:
        # if the switch got the bpdu from itself then it is a loop
        ports[interface] = 'Blocking'
    else:
        # discards the bpdu
        pass

    if own_bridge_ID == root_bridge_ID:
        setListening()


def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def send_bdpu_every_sec():
    while True:
        if root_bridge_ID == own_bridge_ID:
            for i in range(0, 4):
                if i in ports:
                    data, length = create_bpdu_message()
                    send_to_link(i, data, length)
        time.sleep(1)

def is_unicast(dest_mac):
    # if it is not a broadcast MAC address = (ff:ff:ff:ff:ff:ff) and
    # if it is not a multicast MAC address = (the first octet is odd)
    first_byte_int = int(dest_mac.split(':')[0], 16)
    first_byte1_str = dest_mac.split(':')[0]
    if first_byte1_str != 'ff' and first_byte_int & 1 == 0:
        return True
    return False

            
def to_send_or_not_to_send(vlan_id, src_interf, dest_interf):
    if src_interf != dest_interf and src_interf != 'T' and dest_interf != 'T':
        # if the packet comes from an access interface and goes to another
        # access interface with different VLANs then the packet is dropped
        return False
    elif src_interf == 'T' and dest_interf != 'T' and vlan_id != int(dest_interf):
        # if the packet comes from a trunk interface and goes to an access
        # interface with different VLANs then the packet is dropped
        return False
    return True

            
def createDataWithVLAN(vlan_id, src_interf, dest_interf, data, length):
    if vlan_id == -1:
        vlan_id = src_interf
    if src_interf == dest_interf == 'T':
        # if both interfaces are trunk then the tag is kept
        return data, length
    elif src_interf == dest_interf:
        # if both interfaces are access and are in the same vlan
        # then there is no need for a tag
        return data, length
    elif src_interf == 'T' and dest_interf != 'T' and vlan_id == int(dest_interf):
        # if the packet comes from a trunk interface and goes to an access
        # interface then the tag is removed, the packet has to come from the same vlan
        nontagged_frame = data[0:12] + data[16:] # 4 bytes are removed = the tag
        return nontagged_frame, length - 4
    elif src_interf != 'T' and dest_interf == 'T':
        # if the packet comes from an access interface and goes to a trunk
        # interface then the tag is added
        # turn vlan_id into int from str
        vlan_id = int(vlan_id)
        tagged_frame = data[0:12] + create_vlan_tag(vlan_id) + data[12:]
        # 4 bytes are added = the tag
        return tagged_frame, length + 4


def MAC_address_learning(switch_id, src_MAC, dest_MAC, interface, data, length, vlan_id):
    # update the CAM table with the source MAC address and the interface
    # the MAC address is unique to the switch so we can use it as a key
    # put value in the right CAM table depending on the switch_id
    
    SW_CAM[src_MAC] = interface
    src_interface_type = getVLANInterface(switch_id, interface)

    # if the destination MAC address is unicast?
    if is_unicast(dest_MAC):
        if dest_MAC in SW_CAM:
            # if the destination MAC address is in the CAM table
            # then forward the frame to the interface in the CAM table
            dest_interface_type = getVLANInterface(switch_id, SW_CAM[dest_MAC])
            new_data, new_length = createDataWithVLAN(vlan_id, src_interface_type, dest_interface_type, data, length)
            send_to_link(SW_CAM[dest_MAC], new_data, new_length)
            
        else:
            # if the destination MAC address is not in the CAM table
            # then flood the frame to all interfaces except the one it came from
            for i in range(0, 4):
                if i != interface:
                    dest_interface_type = getVLANInterface(switch_id, i)
                    if dest_interface_type == 'T' and ports[i] == 'Blocking':
                        continue
                    if to_send_or_not_to_send(vlan_id, src_interface_type, dest_interface_type) == True:
                        new_data, new_length = createDataWithVLAN(vlan_id, src_interface_type, dest_interface_type, data, length)
                        send_to_link(i, new_data, new_length)
    else:
        # if the destination MAC address is broadcast or multicast
        # then flood the frame to all interfaces except the one it came from
        for i in range(0, 4):
            if i != interface:
                dest_interface_type = getVLANInterface(switch_id, i)
                if dest_interface_type == 'T' and ports[i] == 'Blocking':
                    continue
                if to_send_or_not_to_send(vlan_id, src_interface_type, dest_interface_type) == True:
                    new_data, new_length = createDataWithVLAN(vlan_id, src_interface_type, dest_interface_type, data, length)
                    send_to_link(i, new_data, new_length)
                    
def get_dest_mac(data):
    dest_mac = data[0:6]
    return dest_mac

def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    initSwitch(switch_id)

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()

    while True:
        interface, data, length = recv_from_any_link()

        verify_dest_mac = get_dest_mac(data)
        multicast_mac = bytes([0x01, 0x80, 0xC2, 0x00, 0x00, 0x00])
        if (verify_dest_mac == multicast_mac):
            root_bridge_ID, root_path_cost, sender_bridge_ID = parse_bpdu(data)
            receive_bpdu(root_bridge_ID, root_path_cost, sender_bridge_ID, interface)
        else:
            dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

            dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
            src_mac = ':'.join(f'{b:02x}' for b in src_mac)

            MAC_address_learning(switch_id, src_mac, dest_mac, interface, data, length, vlan_id)


if __name__ == "__main__":
    main()
