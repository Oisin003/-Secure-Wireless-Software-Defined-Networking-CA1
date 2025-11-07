#!/usr/bin/python
"""
Author: Oisin Gibson
Date: 22/10/2025
Description: Mininet topology for a departmental network with Admin, Student, and IoT segments.

This topology implements a hierarchical network design with:
- Three access layer switches (one per department/segment)
- Two core layer switches (for redundancy and load balancing)
- One aggregation switch (connecting access switches to core)
- Six hosts distributed across three network segments
- Multiple redundant paths for high availability
"""

# Import required Mininet modules for topology creation and network simulation
from mininet.topo import Topo  # Base topology class
from mininet.net import Mininet  # Main Mininet network class
from mininet.node import RemoteController, OVSSwitch  # Controller and switch types
from mininet.link import TCLink  # Link class with traffic control capabilities
from mininet.log import setLogLevel  # Logging configuration

class ca1_Q1_topo(Topo):
    """
    Custom topology class for CA1 Question 1 Part 1.
    
    This class defines a departmental network topology with hierarchical design:
    - Access Layer: Switches s1, s2, s3 (department-specific)
    - Aggregation Layer: Switch s4 (aggregates access switches)
    - Core Layer: Switches s5, s6 (high-speed backbone with redundancy)
    
    Network Segments:
    - Admin segment: 10.0.0.0/24 (connected to s1)
    - Student segment: 10.0.1.0/24 (connected to s2)
    - IoT segment: 10.0.2.0/24 (connected to s3)
    """
    
    def build(self):
        """
        Build the network topology by adding switches, hosts, and links.
        This method is called automatically when the topology is instantiated.
        """
        
        # ===== SWITCH CONFIGURATION =====
        # All switches use OpenFlow 1.3 protocol for SDN controller communication
        # OpenFlow 1.3 provides improved flow table management and group tables
        
        # Access Layer Switches - Connect end hosts to the network
        switch1 = self.addSwitch('s1', protocols='OpenFlow13')  # Admin access switch (10.0.0.0/24)
        switch2 = self.addSwitch('s2', protocols='OpenFlow13')  # Student access switch (10.0.1.0/24)
        switch3 = self.addSwitch('s3', protocols='OpenFlow13')  # IoT access switch (10.0.2.0/24)
        
        # Aggregation Layer Switch - Aggregates traffic from access switches
        switch4 = self.addSwitch('s4', protocols='OpenFlow13')  # Aggregation switch
        
        # Core Layer Switches - High-speed backbone with redundancy
        switch5 = self.addSwitch('s5', protocols='OpenFlow13')  # Primary core switch
        switch6 = self.addSwitch('s6', protocols='OpenFlow13')  # Secondary core switch (redundancy)

        # Core Layer Switches - High-speed backbone with redundancy
        switch5 = self.addSwitch('s5', protocols='OpenFlow13')  # Primary core switch
        switch6 = self.addSwitch('s6', protocols='OpenFlow13')  # Secondary core switch (redundancy)

        # ===== HOST CONFIGURATION =====
        # Hosts are assigned IP addresses based on their department/segment
        # Each segment uses a different /24 subnet for network isolation
        
        # Admin Department Hosts (10.0.0.0/24 network)
        host1 = self.addHost('h1', ip='10.0.0.1/24')  # Admin workstation 1
        host2 = self.addHost('h2', ip='10.0.0.2/24')  # Admin workstation 2
        
        # Student Department Hosts (10.0.1.0/24 network)
        host3 = self.addHost('h3', ip='10.0.1.1/24')  # Student workstation 1
        host4 = self.addHost('h4', ip='10.0.1.2/24')  # Student workstation 2
        
        # IoT Department Hosts (10.0.2.0/24 network)
        host5 = self.addHost('h5', ip='10.0.2.1/24')  # IoT device 1 
        host6 = self.addHost('h6', ip='10.0.2.2/24')  # IoT device 2 

        # IoT Department Hosts (10.0.2.0/24 network)
        host5 = self.addHost('h5', ip='10.0.2.1/24')  # IoT device 1 
        host6 = self.addHost('h6', ip='10.0.2.2/24')  # IoT device 2 

        # ===== ACCESS LAYER LINKS =====
        # Connect end hosts to their respective access layer switches
        # These links represent the connection from hosts to their local switch
        
        # Admin hosts connected to Admin access switch (s1)
        self.addLink(host1, switch1)  # h1 -> s1
        self.addLink(host2, switch1)  # h2 -> s1
        
        # Student hosts connected to Student access switch (s2)
        self.addLink(host3, switch2)  # h3 -> s2
        self.addLink(host4, switch2)  # h4 -> s2
        
        # IoT devices connected to IoT access switch (s3)
        self.addLink(host5, switch3)  # h5 -> s3
        self.addLink(host6, switch3)  # h6 -> s3

        # IoT devices connected to IoT access switch (s3)
        self.addLink(host5, switch3)  # h5 -> s3
        self.addLink(host6, switch3)  # h6 -> s3

        # ===== INTER-SWITCH LINKS =====
        # Create a hierarchical topology with redundant paths for fault tolerance
        # This design ensures network availability even if a single link or switch fails
        
        # Access to Aggregation Layer Links
        # Admin and Student switches connect to aggregation switch (s4)
        self.addLink(switch1, switch4)  # s1 (Admin) -> s4 (Aggregation)
        self.addLink(switch2, switch4)  # s2 (Student) -> s4 (Aggregation)
        
        # Access to Core Layer Links
        # IoT switch connects directly to primary core switch (s5)
        self.addLink(switch3, switch5)  # s3 (IoT) -> s5 (Core)
        
        # Aggregation to Core Layer Link
        # Aggregation switch connects to primary core switch
        self.addLink(switch4, switch5)  # s4 (Aggregation) -> s5 (Core)
        
        # Core Layer Interconnection
        # Connect both core switches for high availability and load distribution
        self.addLink(switch5, switch6)  # s5 (Core) <-> s6 (Core)
        
        # ===== REDUNDANT PATHS =====
        # These links provide alternate paths for network resilience
        # If the primary path fails, traffic can be rerouted through these links
        
        # Redundant path from Admin access to secondary core switch
        self.addLink(switch1, switch6)  # s1 (Admin) -> s6 (Redundant Core)
        
        # Redundant path from Student access to secondary core switch
        self.addLink(switch2, switch6)  # s2 (Student) -> s6 (Redundant Core)

        # Redundant path from Student access to secondary core switch
        self.addLink(switch2, switch6)  # s2 (Student) -> s6 (Redundant Core)

# ===== TOPOLOGY REGISTRATION =====
# Register this topology with Mininet so it can be loaded by name
# Usage: sudo mn --custom ca1_Q1_P1.py --topo ca1_Q1_P1 --controller remote
topos = { 'ca1_Q1_P1': ca1_Q1_topo }
