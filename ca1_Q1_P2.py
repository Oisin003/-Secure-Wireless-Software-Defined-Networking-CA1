# Oisin Gibson
# CA1 - Q1 - Part 2
# Secure SDN Application with Firewall, DDoS Mitigation, and ACL


from ryu.base import app_manager # Ryu application base
from ryu.controller import ofp_event # OpenFlow events
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER # Dispatcher states
from ryu.controller.handler import set_ev_cls # Event handler decorator
from ryu.ofproto import ofproto_v1_3 # OpenFlow 1.3 protocol
from ryu.lib.packet import packet, ethernet, ipv4, icmp, tcp, arp # Packet parsing
from ryu.lib import hub # Ryu's cooperative threading
import time # Time functions
from collections import defaultdict, deque # Data structures

# ========================================
# CONFIGURATION CONSTANTS
# ========================================
# DDoS Protection Settings
DDOS_PKT_THRESHOLD = 20        # Maximum packet-ins per window tolerated before mitigation
DDOS_WINDOW = 10               # Time window (in seconds) to count packet-ins
DDOS_BLOCK_TIME = 30           # Duration (in seconds) to block offending host

# Flow Table Settings
FLOW_IDLE_TIMEOUT = 30         # Default idle timeout (seconds) for installed flows
TABLE_ID = 0                   # OpenFlow table ID to use (default table)

# ========================================
# SECURITY POLICY CONFIGURATION
# ========================================
# Firewall Rules - Explicit traffic blocks (high priority)
# Each rule is a dictionary with match fields: eth_type, nw_src, nw_dst, proto
# These rules are installed proactively on switch connection
FIREWALL_BLOCKS = [
    # Block ICMP (ping) traffic from subnet 10.0.1.0/24 to subnet 10.0.2.0/24
    # eth_type 0x0800 = IPv4, proto 1 = ICMP
    {"eth_type": 0x0800, "nw_src": "10.0.1.0/24", "nw_dst": "10.0.2.0/24", "proto": 1},
    
    # Block TCP traffic from specific host 10.0.1.10 to host 10.0.2.20
    # eth_type 0x0800 = IPv4, proto 6 = TCP, /32 = single host
    {"eth_type": 0x0800, "nw_src": "10.0.1.10/32", "nw_dst": "10.0.2.20/32", "proto": 6}
]

# Access Control List (ACL) - Whitelist approach
# Only traffic between these subnet pairs is allowed (bi-directional)
# All other inter-subnet traffic is denied by default
ACL_ALLOW = [
    # Allow communication between subnet 10.0.1.0/24 and 10.0.3.0/24 (both directions)
    ("10.0.1.0/24", "10.0.3.0/24"),
]

# ========================================
# DDoS STATE TRACKING CLASS
# ========================================
# Maintains state information for each source IP to detect DDoS attacks
class DDoSState:
    def __init__(self):
        # Deque to store timestamps of recent packet-in events for this IP
        # Used to count packet rate within the detection window
        self.packet_times = deque()
        
        # Unix timestamp indicating when the block expires
        # 0 means not currently blocked
        self.blocked_until = 0

# ========================================
# MAIN SDN CONTROLLER APPLICATION
# ========================================
class SecureSDNApp(app_manager.RyuApp):
    # Specify which OpenFlow version(s) this application supports
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        # Initialize the parent Ryu application class
        super(SecureSDNApp, self).__init__(*args, **kwargs)
        
        # MAC learning table: {datapath_id: {mac_address: output_port}}
        # Used for learning switch functionality
        self.mac_to_port = {}
        
        # ARP table: {ip_address: mac_address}
        # Maintains IP to MAC address mappings learned from ARP packets
        self.arp_table = {}
        
        # DDoS state tracking: {source_ip: DDoSState}
        # Tracks packet-in rates and block status for each source IP
        self.ddos_state = defaultdict(DDoSState)
        
        # Start background thread for cleaning up expired DDoS blocks
        self.monitor_thread = hub.spawn(self._ddos_cleanup_thread)
        
        # Dictionary to track all connected switches: {datapath_id: datapath}
        self.datapaths = {}
        
        # Log application startup
        self.logger.info("SecureSDNApp starting: firewall + ddos + acl enabled")

    # ========================================
    # HELPER METHOD: CONSTRUCT OPENFLOW MATCH OBJECT
    # ========================================
    def _build_match(self, parser, eth_type=None, in_port=None, source_mac=None, destination_mac=None,
                     network_source=None, network_destination=None, eth_proto=None, ip_protocol=None, tcp_destination=None):
        # Create empty match object
        match_object = parser.OFPMatch()
        
        # Set Ethernet type if provided (e.g., IPv4, ARP)
        if eth_type is not None:
            match_object.set_dl_type(eth_type)
            
        # Set input port if provided
        if in_port is not None:
            match_object.set_in_port(in_port)
            
        # Set source MAC address if provided
        if source_mac is not None:
            match_object.set_dl_src(source_mac)
            
        # Set destination MAC address if provided
        if destination_mac is not None:
            match_object.set_dl_dst(destination_mac)
            
        # Set source IP address/network if provided
        if network_source is not None:
            match_object.set_ipv4_src(network_source)
            
        # Set destination IP address/network if provided
        if network_destination is not None:
            match_object.set_ipv4_dst(network_destination)
            
        # Set IP protocol if provided
        if ip_protocol is not None:
            match_object.set_ip_proto(ip_protocol)
            
        return match_object

    # ========================================
    # EVENT HANDLER: SWITCH FEATURES (CONNECTION)
    # ========================================
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, event):
        """
        Handles the initial switch connection event (handshake complete).
        This is called when a switch first connects to the controller.
        
        Responsibilities:
        1. Install table-miss flow entry (lowest priority, sends unknown packets to controller)
        2. Install proactive firewall and ACL rules
        3. Track the connected switch
        """
        # Log the switch connection with its datapath ID
        self.logger.info("Switch connected: %s", event.msg.datapath.id)
        
        # Extract datapath object (represents the connected switch)
        datapath = event.msg.datapath
        
        # Add this switch to our tracking dictionary
        self.datapaths[datapath.id] = datapath
        
        # Get OpenFlow protocol version and parser for this switch
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # ---- Install Table-Miss Flow Entry ----
        # This catches all packets that don't match any other flow
        # Priority 0 = lowest priority (only matches if nothing else does)
        table_miss_match = parser.OFPMatch()  # Empty match = match all packets
        
        # Action: send packet to controller for processing
        # OFPP_CONTROLLER = special port representing the controller
        # OFPCML_NO_BUFFER = send entire packet, don't buffer on switch
        controller_actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        
        # Install the table-miss flow with priority 0
        self._add_flow(datapath, priority=0, match=table_miss_match, actions=controller_actions)

        # ---- Install Security Policies ----
        # Proactively install firewall blocks and ACL rules
        # These have higher priority than learning switch flows
        self._install_firewall_and_acl(datapath)

    def _add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0, table_id=TABLE_ID):
        """
        Installs a flow entry in the switch's flow table.
        
        Args:
            datapath: The switch to install the flow on
            priority: Flow priority (higher = higher priority)
            match: Match conditions (OFPMatch object)
            actions: List of actions to apply (e.g., output to port, drop)
            idle_timeout: Remove flow if inactive for this many seconds (0 = never)
            hard_timeout: Remove flow after this many seconds regardless (0 = never)
            table_id: Which flow table to install into
        """
        # Get protocol references
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Create instruction to apply the actions immediately
        # OFPIT_APPLY_ACTIONS = apply actions without going to another table
        instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        # Create the flow modification message
        flow_mod = parser.OFPFlowMod(datapath=datapath, table_id=table_id,
                                priority=priority, match=match, instructions=instructions,
                                idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        
        # Send the flow mod message to the switch
        datapath.send_msg(flow_mod)

    # ========================================
    # PROACTIVE SECURITY POLICY INSTALLATION
    # ========================================
    def _install_firewall_and_acl(self, datapath):
        """
        Proactively installs firewall and ACL rules on switch connection.
        These rules have higher priority than learning switch flows.
        
        Priority levels:
        - 300: Firewall blocks (explicit deny rules)
        - 250: ACL denies (default deny between subnets)
        - 100: Learning switch flows (reactive, installed on packet-in)
        - 0:   Table-miss (send to controller)
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # ---- FIREWALL RULES ----
        # Install explicit drop rules for blocked traffic (priority 300)
        for firewall_rule in FIREWALL_BLOCKS:
            # Create match based on the firewall rule configuration
            firewall_match = parser.OFPMatch(eth_type=firewall_rule.get("eth_type"),
                                    ipv4_src=firewall_rule.get("nw_src"),
                                    ipv4_dst=firewall_rule.get("nw_dst"),
                                    ip_proto=firewall_rule.get("proto"))
            
            # Empty actions list = drop the packet (no forwarding)
            # idle_timeout=0 means the rule never expires
            self._add_flow(datapath, priority=300, match=firewall_match, actions=[], idle_timeout=0)
            
            # Log the installed firewall rule
            self.logger.info("Installed firewall block on dpid=%s rule=%s", datapath.id, firewall_rule)

        # ---- ACCESS CONTROL LIST (ACL) RULES ----
        # Implement default-deny policy between subnets
        # Only traffic matching ACL_ALLOW pairs is permitted
        # This example shows denying traffic between two specific subnets
        # In production, you would iterate over all subnet pairs
        
        # Define an example subnet pair to control
        example_subnet_pair = ("10.0.1.0/24", "10.0.2.0/24")
        
        # Check if this pair is allowed in either direction
        # If NOT in ACL_ALLOW, install deny rules
        if example_subnet_pair not in ACL_ALLOW and (example_subnet_pair[1], example_subnet_pair[0]) not in ACL_ALLOW:
            # Create match for forward direction (subnet1 -> subnet2)
            acl_match_forward = parser.OFPMatch(eth_type=0x0800, ipv4_src=example_subnet_pair[0], ipv4_dst=example_subnet_pair[1])
            
            # Create match for reverse direction (subnet2 -> subnet1)
            acl_match_reverse = parser.OFPMatch(eth_type=0x0800, ipv4_src=example_subnet_pair[1], ipv4_dst=example_subnet_pair[0])
            
            # Install both deny rules with priority 250 (below firewall, above learning switch)
            self._add_flow(datapath, priority=250, match=acl_match_forward, actions=[], idle_timeout=0)
            self._add_flow(datapath, priority=250, match=acl_match_reverse, actions=[], idle_timeout=0)
            
            # Log the ACL installation
            self.logger.info("Installed ACL deny between %s and %s on dpid=%s", example_subnet_pair[0], example_subnet_pair[1], datapath.id)

    # ========================================
    # EVENT HANDLER: PACKET-IN (MAIN PROCESSING LOGIC)
    # ========================================
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, event):
        """
        Handles packet-in events from the switch.
        This is called when a packet doesn't match any flow entry (table-miss).
        
        Processing pipeline:
        1. Parse the packet (extract headers)
        2. Learn source MAC address and port (learning switch)
        3. DDoS detection (count packet-ins per source IP)
        4. Firewall checking (enforce block rules)
        5. ACL checking (enforce access control)
        6. Make forwarding decision (flood or forward to learned port)
        7. Install flow entry to handle future packets
        8. Send packet out
        """
        # ---- Extract packet and switch information ----
        message = event.msg                          # The packet-in message
        datapath = message.datapath                  # The switch that sent this packet
        datapath_id = datapath.id                    # Unique ID of the switch
        ofproto = datapath.ofproto                   # OpenFlow protocol reference
        parser = datapath.ofproto_parser             # Protocol parser

        # Get the port where the packet arrived
        input_port = message.match.get('in_port')
        
        # ---- Parse the packet ----
        parsed_packet = packet.Packet(message.data)  # Parse raw packet data
        ethernet_frame = parsed_packet.get_protocol(ethernet.ethernet)  # Get Ethernet header
        
        # If no Ethernet header, invalid packet - ignore it
        if ethernet_frame is None:
            return

        # Extract Ethernet header fields
        source_mac = ethernet_frame.src              # Source MAC address
        destination_mac = ethernet_frame.dst         # Destination MAC address
        ethertype = ethernet_frame.ethertype         # Ethernet type (IPv4, ARP, etc.)

        # ---- STEP 1: MAC LEARNING (Learning Switch Functionality) ----
        # Create entry for this switch if it doesn't exist
        self.mac_to_port.setdefault(datapath_id, {})
        
        # Learn: source MAC arrived on input_port
        # This allows us to forward future packets to this MAC through the correct port
        self.mac_to_port[datapath_id][source_mac] = input_port

        # ---- STEP 2: ARP LEARNING ----
        # Extract ARP packet if present (for IP-to-MAC mapping)
        arp_packet = parsed_packet.get_protocol(arp.arp)
        if arp_packet:
            # Store the mapping: IP address -> MAC address
            self.arp_table[arp_packet.src_ip] = arp_packet.src_mac

        # ---- STEP 3: EXTRACT IP INFORMATION ----
        # Try to get IPv4 header (None if not an IPv4 packet)
        ipv4_packet = parsed_packet.get_protocol(ipv4.ipv4)

        # Initialize IP-related variables
        source_ip = None
        destination_ip = None
        ip_protocol = None
        
        # If this is an IPv4 packet, extract IP information
        if ipv4_packet:
            source_ip = ipv4_packet.src           # Source IP address
            destination_ip = ipv4_packet.dst      # Destination IP address
            ip_protocol = ipv4_packet.proto       # IP protocol (1=ICMP, 6=TCP, 17=UDP, etc.)

        # ========================================
        # STEP 4: DDoS DETECTION AND MITIGATION
        # ========================================
        # Only check DDoS for IPv4 packets (need source IP)
        if source_ip:
            # Get or create DDoS tracking state for this source IP
            # defaultdict automatically creates DDoSState() if key doesn't exist
            ddos_state = self.ddos_state[source_ip]
            
            # Get current timestamp (seconds since Unix epoch)
            current_time = time.time()
            
            # Record this packet-in event by adding timestamp to deque
            ddos_state.packet_times.append(current_time)

            # Clean up old timestamps: remove entries older than the detection window
            # This maintains a sliding window of recent packet-in events
            while ddos_state.packet_times and ddos_state.packet_times[0] < current_time - DDOS_WINDOW:
                ddos_state.packet_times.popleft()

            # Check if this host is currently blocked
            if ddos_state.blocked_until > current_time:
                # Block is still active - drop packet silently
                self.logger.info("Dropping packet from blocked host %s (still blocked)", source_ip)
                return  # Stop processing this packet
            else:
                # Check if packet rate exceeds threshold (potential DDoS attack)
                if len(ddos_state.packet_times) > DDOS_PKT_THRESHOLD:
                    # DDOS DETECTED!
                    self.logger.warning("DDOS detected from %s: %d pkt-ins in %ds -> blocking for %ds",
                                        source_ip, len(ddos_state.packet_times), DDOS_WINDOW, DDOS_BLOCK_TIME)
                    
                    # Create match to block ALL traffic from this source IP
                    ddos_match = parser.OFPMatch(eth_type=0x0800, ipv4_src=source_ip)
                    
                    # Install high-priority (400) drop rule that expires after DDOS_BLOCK_TIME
                    # Priority 400 is higher than firewall (300) to ensure it takes effect
                    # idle_timeout causes the rule to automatically expire
                    self._add_flow(datapath, priority=400, match=ddos_match, actions=[],
                                   idle_timeout=DDOS_BLOCK_TIME)
                    
                    # Record when the block expires
                    ddos_state.blocked_until = current_time + DDOS_BLOCK_TIME
                    
                    # Reset packet counter for this IP
                    ddos_state.packet_times.clear()
                    
                    # Drop this packet (don't forward or process further)
                    return

        # ========================================
        # STEP 5: FIREWALL ENFORCEMENT
        # ========================================
        # Apply firewall rules to IPv4 packets only
        if ipv4_packet:
            # Check each firewall block rule
            for block_rule in FIREWALL_BLOCKS:
                # Extract rule criteria
                rule_protocol = block_rule.get("proto")              # IP protocol to block
                rule_source_network = block_rule.get("nw_src")       # Source IP/network
                rule_destination_network = block_rule.get("nw_dst")  # Destination IP/network
                
                # If rule specifies a protocol, check if it matches
                if rule_protocol is not None and rule_protocol != ip_protocol:
                    continue  # Protocol doesn't match, skip to next rule
                
                # Check if packet's source and destination IPs match the rule
                if self._ip_in_net(source_ip, rule_source_network) and self._ip_in_net(destination_ip, rule_destination_network):
                    # FIREWALL BLOCK TRIGGERED
                    self.logger.info("Dropping per-firewall rule: %s -> %s proto=%s", source_ip, destination_ip, rule_protocol)
                    # Drop packet (don't install flow, don't forward)
                    return

            # ========================================
            # STEP 6: ACL ENFORCEMENT
            # ========================================
            # Whitelist approach: only explicitly allowed subnet pairs can communicate
            is_traffic_allowed = False
            
            # Check if traffic matches any allowed ACL pair
            for allowed_subnet1, allowed_subnet2 in ACL_ALLOW:
                # Check bi-directional: (subnet1 -> subnet2) OR (subnet2 -> subnet1)
                if (self._ip_in_net(source_ip, allowed_subnet1) and self._ip_in_net(destination_ip, allowed_subnet2)) or \
                   (self._ip_in_net(source_ip, allowed_subnet2) and self._ip_in_net(destination_ip, allowed_subnet1)):
                    is_traffic_allowed = True  # Found matching ACL rule
                    break  # No need to check further
            
            # If traffic is not explicitly allowed, apply default-deny
            if not is_traffic_allowed:
                # Check if traffic is between controlled subnets
                # (In production, this would be more comprehensive)
                if (self._ip_in_net(source_ip, "10.0.1.0/24") and self._ip_in_net(destination_ip, "10.0.2.0/24")) or \
                   (self._ip_in_net(source_ip, "10.0.2.0/24") and self._ip_in_net(destination_ip, "10.0.1.0/24")):
                    # ACL DENY TRIGGERED
                    self.logger.info("Dropping per-ACL default deny: %s -> %s", source_ip, destination_ip)
                    return  # Drop packet

        # ========================================
        # STEP 7: FORWARDING DECISION 
        # ========================================
        # Determine where to send the packet
        # Default to flooding (broadcast to all ports except input port)
        output_port = ofproto.OFPP_FLOOD
        
        # Check if we've learned the destination MAC's location
        if destination_mac in self.mac_to_port[datapath_id]:
            # We know which port leads to this MAC - use unicast forwarding
            output_port = self.mac_to_port[datapath_id][destination_mac]
        
        # Create action: output packet to the determined port
        forwarding_actions = [parser.OFPActionOutput(output_port)]

        # ========================================
        # STEP 8: INSTALL PROACTIVE FLOW ENTRY
        # ========================================
        # If we know the destination (not flooding), install a flow entry
        # This allows the switch to handle future packets without controller involvement
        if output_port != ofproto.OFPP_FLOOD:
            # Create appropriate match based on packet type
            if ipv4_packet:
                # For IPv4: match on source IP, destination IP, and protocol
                # This provides more specific matching
                flow_match = parser.OFPMatch(eth_type=0x0800, ipv4_src=source_ip, ipv4_dst=destination_ip, ip_proto=ip_protocol)
            else:
                # For non-IPv4: match on Ethernet type and destination MAC
                flow_match = parser.OFPMatch(eth_type=ethertype, eth_dst=destination_mac)

            # Install flow with priority 100 (below security rules, above table-miss)
            # idle_timeout: flow expires if unused for FLOW_IDLE_TIMEOUT seconds
            self._add_flow(datapath, priority=100, match=flow_match, actions=forwarding_actions, idle_timeout=FLOW_IDLE_TIMEOUT)

        # ========================================
        # STEP 9: SEND PACKET OUT
        # ========================================
        # Forward this packet according to our decision
        # Construct packet-out message
        packet_out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=message.buffer_id,  # Reference to buffered packet on switch (if any)
            in_port=input_port,            # Port where packet arrived
            actions=forwarding_actions,    # What to do with packet
            # If packet is buffered on switch, don't send data; otherwise include packet data
            data=None if message.buffer_id != ofproto.OFP_NO_BUFFER else message.data
        )
        # Send the packet-out message to the switch
        datapath.send_msg(packet_out)

    # ========================================
    # UTILITY METHOD: IP ADDRESS NETWORK MEMBERSHIP TEST
    # ========================================
    def _ip_in_net(self, ip_address, network):
        """
        Checks if an IP address belongs to a network (CIDR notation).
        
        Args:
            ip_address: IP address as string 
            network: Network in CIDR notation or single IP
            
        Returns:
            True if ip_address is in network, False otherwise
        """
        # Handle None values (safety check)
        if ip_address is None or network is None:
            return False
        
        # If network is not in CIDR format (no /), do exact string comparison
        if '/' not in network:
            return ip_address == network
        
        # Use Python's ipaddress module for proper CIDR matching
        import ipaddress
        # strict=False allows host bits to be set in network address
        return ipaddress.IPv4Address(ip_address) in ipaddress.IPv4Network(network, strict=False)

    # ========================================
    # EVENT HANDLER: SWITCH STATE CHANGES
    # ========================================
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, event):
        """
        Tracks switch connection and disconnection events.
        Maintains a registry of active switches in self.datapaths.
        
        States:
        - MAIN_DISPATCHER: Switch is fully connected and operational
        - DEAD_DISPATCHER: Switch has disconnected
        """
        datapath = event.datapath
        
        # Switch entered active state (fully connected)
        if event.state == MAIN_DISPATCHER:
            # Add to tracking dictionary
            self.datapaths[datapath.id] = datapath
            self.logger.info("Switch %s entered MAIN_DISPATCHER", datapath.id)
            
        # Switch disconnected
        elif event.state == DEAD_DISPATCHER:
            # Remove from tracking dictionary if present
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
                self.logger.info("Switch %s disconnected (DEAD_DISPATCHER)", datapath.id)

    # ========================================
    # BACKGROUND THREAD: DDoS STATE CLEANUP
    # ========================================
    def _ddos_cleanup_thread(self):
        """
        Background maintenance thread for DDoS state cleanup.
        Runs continuously (once per second) to:
        1. Reset expired block timers
        2. Remove old packet timestamps outside the detection window
        3. Delete entries for IPs with no recent activity (memory management)
        
        This prevents memory leaks and ensures accurate DDoS detection.
        """
        # Infinite loop - runs for lifetime of controller
        while True:
            current_time = time.time()  # Get current Unix timestamp
            
            # Iterate over all tracked IPs
            # list() creates a copy to allow safe deletion during iteration
            for tracked_ip, ip_state in list(self.ddos_state.items()):
                
                # ---- Check and reset expired blocks ----
                if ip_state.blocked_until and ip_state.blocked_until < current_time:
                    # Block period has expired, reset to 0
                    ip_state.blocked_until = 0
                    self.logger.info("DDoS block expired for %s", tracked_ip)
                
                # ---- Clean up old packet timestamps ----
                # Remove timestamps that are outside the detection window
                while ip_state.packet_times and ip_state.packet_times[0] < current_time - DDOS_WINDOW:
                    ip_state.packet_times.popleft()
                
                # ---- Memory cleanup ----
                # If IP has no recent activity and is not blocked, remove the entry
                if not ip_state.packet_times and ip_state.blocked_until == 0:
                    del self.ddos_state[tracked_ip]
            
            # Sleep for 1 second before next cleanup cycle
            # hub.sleep() is Ryu's cooperative sleep (eventlet-based)
            hub.sleep(1)