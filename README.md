# -Secure-Wireless-Software-Defined-Networking-CA1

Part 1: Network Design (Topology + Controller Setup) (40 Marks)
• Use Mininet to design a custom topology (minimum 6 switches, 1 or 2 controllers, and at
least 6 hosts).
• Include redundant links or multiple paths between sub-networks.
• Label hosts as belonging to different “departments” or “services” (e.g., Admin, Students,
IoT).
• Connect the topology to a Ryu or POX controller.
• Configure OpenFlow version 1.3 or later.

Part 2: Implement Secure SDN Flows (60 Marks)
Implement and demonstrate the following security features using OpenFlow rules or
controller logic. Create a simple topology like in part 1 for this task.
1. Firewall Functionality:
• Block specific traffic (e.g., deny ping or TCP from one subnet to another).
• Permit only defined flows.
2. DDoS Detection/Mitigation:
• Monitor packet-in rate per host; if traffic exceeds the threshold, block or limit that host.
3. Access Control Lists (ACL):
• Only allow traffic between certain VLANs or IP ranges.
