NETWORK SECURITY CONCEPTS

Firewall
A network device that controls network traffic based on predetermined rules. Firewalls can also be software-based or hardware-based, depending on your network requirements.
 
Intrusion Detection System (IDS)
A network security system designed to detect malicious activity within a network. IDS systems can be either network-based or host-based and are often used in conjunction with other network security mechanisms such as firewalls.

Intrusion Prevention System (IPS) 
A network security system designed to prevent malicious activity within a network by monitoring network traffic for suspicious patterns and blocking any activities that appear dangerous or potentially malicious. 

User Datagram Protocol (UDP) 
A protocol used for communication throughout the internet. It is specifically chosen for time-sensitive applications like gaming, playing videos, or Domain Name System (DNS) lookups.

Transmission Control Protocol (TCP) 
A communications standard that enables application programs and computing devices to exchange messages over a network. It is designed to send packets across the internet and ensure the successful delivery of data and messages over networks.
TCP is one of the basic standards that define the rules of the internet and is included within the standards defined by the Internet Engineering Task Force (IETF).
TCP organizes data so that it can be transmitted between a server and a client

Address Resolution Protocol (ARP) 
A protocol or procedure that connects an ever-changing Internet Protocol (IP) address to a fixed physical machine address, also known as a media access control (MAC) address, in a local-area network (LAN). 

Dynamic Host Configuration Protocol (DHCP) 
A client/server protocol that automatically provides an Internet Protocol (IP) host with its IP address and other related configuration information such as the subnet mask and default gateway. 
Without DHCP, IP addresses for new computers or computers that are moved from one subnet to another must be configured manually; IP addresses for computers that are removed from the network must be manually reclaimed.

Domain Name System (DNS) 
The phonebook of the Internet. Humans access information online through domain names, like nytimes.com or espn.com. Web browsers interact through Internet Protocol (IP) addresses. DNS translates domain names to IP addresses so browsers can load Internet resources.
The process of DNS resolution involves converting a hostname (such as www.example.com) into a computer-friendly IP address (such as 192.168.1.1).

Internet Control Message Protocol (ICMP) 
A protocol that devices within a network use to communicate problems with data transmission.
ICMP is used is to determine if data is getting to its destination and at the right time

Border Gateway Protocol (BGP) 
A gateway protocol that enables the internet to exchange routing information between autonomous systems (AS). As networks interact with each other, they need a way to communicate. This is accomplished through peering. 

Simple Mail Transfer Protocol (SMTP)
A method to transfer mail from one user to another

IMAP 
Allows you to access your email wherever you are, from any device. When you read an email message using IMAP, you aren't actually downloading or storing it on your computer; instead, you're reading it from the email service. As a result, you can check your email from different devices, anywhere in the world: your phone, a computer, a friend's computer.
IMAP only downloads a message when you click on it, and attachments aren't automatically downloaded. This way you're able to check your messages a lot more quickly than POP.

POP 
Works by contacting your email service and downloading all of your new messages from it. Once they are downloaded onto your PC or Mac, they are deleted from the email service. This means that after the email is downloaded, it can only be accessed using the same computer. If you try to access your email from a different device, the messages that have been previously downloaded won't be available to you.

File Transfer Protocol (FTP) 
A standard network protocol used for the transfer of files from one host to another over a TCP-based network, such as the Internet.

Hypertext Transfer Protocol (HTTP) 
The foundation of the World Wide Web, and is used to load webpages using hypertext links. HTTP is an application layer protocol designed to transfer information between networked devices and runs on top of other layers of the network protocol stack.
A typical HTTP request contains:
HTTP version type
a URL
an HTTP method
HTTP request headers
Optional HTTP body.

Internet Group Management Protocol (IGMP) 
A protocol that allows several devices to share one IP address so they can all receive the same data. IGMP is a network layer protocol used to set up multicasting on networks that use the Internet Protocol version 4 (IPv4).

Access Control List (ACL) 
A list of rules used to control access to resources on a network, including specific IP addresses, users, and ports. ACLs can be configured for either read or write operations on specific network.

Network Access Control (NAC)
A network security solution that allows administrators to restrict access to a network based on the user’s identity, device type, and other criteria. 

Virtual Private Networks (VPN) 
An encrypted network connection used to securely connect two or more private networks over a public network such as the Internet. 

Cryptography 
The study of how data is protected through encryption algorithms and cryptographic protocols. 

SSL/TLS
Secure Sockets Layer (SSL) and Transport Layer Security (TLS) are network protocols used to secure network traffic. 

Public Key Infrastructure (PKI) 
A network security solution that uses public-key cryptography to authenticate network users and their devices. 

Network Address Translation (NAT) 
A network security technique that allows private networks to use one or more public IP addresses for outgoing traffic. 

Distributed Denial of Service (DDoS) 
attacks are malicious attempts to overwhelm network resources with large amounts of network traffic from multiple sources or locations. 

Internet Protocol Security (IPSec) 
An internet standard protocol suite for establishing secure, encrypted connections between network devices. 

Terminal Access Controller Access Control System (TACACS)
A network security protocol used to authenticate network users and their devices. 

Remote Authentication Dial-In User Service (RADIUS) 
A network authentication protocol used to securely connect network users with network services such as VPNs, network access control (NAC), and wireless networks. 

Wi-Fi Protected Access (WPA/WPA2) 
Most commonly used wireless network security protocol for encrypting traffic between Wi-Fi access points and clients. 

Simple Authentication and Security Layer (SASL) 
A network authentication protocol used to securely authenticate network users. 

Intrusion Prevention System/Intrusion Detection System (IPSO) 
A network security solution that combines network intrusion detection with network intrusion prevention capabilities. 

Security Information and Event Management (SIEM) 
A network security solution that consolidates log data from multiple sources into one centralized repository for monitoring, analysis, and reporting. 
These security systems (called SIEMs) combine host-based and network-based intrusion detection systems that combine real-time network traffic monitoring with historical data log file scanning to provide administrators with a comprehensive picture of all activity across the network. SIEMs are similar to intrusion prevention systems (IPS), which scan network traffic for suspicious activity, policy violations, unauthorized access, and other signs of potentially malicious behavior in order to actively block the attempted intrusions. An IPS can also log security events and send notifications to the necessary players in the interest of keeping network administrators informed.

Endpoint Security 
A network security solution designed to protect network devices from malicious activity and threats, including malware and unsecured network connections. 

Unified Threat Management (UTM) 
A network security solution that combines multiple network security solutions, such as firewalls, intrusion detection/prevention systems, antivirus software, and more into one unified platform. 

Access control
This refers to controlling which users have access to the network or especially sensitive sections of the network. Using security policies, you can restrict network access to only recognized users and devices or grant limited access to noncompliant devices or guest users.

Antivirus and anti-malware software
Malware, or “malicious software,” is a common form of cyberattack that comes in many different shapes and sizes. Some variations work quickly to delete files or corrupt data, while others can lie dormant for long periods of time and quietly allow hackers a back door into your systems. The best antivirus software will monitor network traffic in real time for malware, scan activity log files for signs of suspicious behavior or long-term patterns, and offer threat remediation capabilities.

Application security
Each device and software product used within your networking environment offers a potential way in for hackers. For this reason, it is important that all programs be kept up-to-date and patched to prevent cyberattackers from exploiting vulnerabilities to access sensitive data. Application security refers to the combination of hardware, software, and best practices you use to monitor issues and close gaps in your security coverage.

Behavioral analytics 
In order to identify abnormal behavior, security support personnel need to establish a baseline of what constitutes normal behavior for a given customer’s users, applications, and network. Behavioral analytics software is designed to help identify common indicators of abnormal behavior, which can often be a sign that a security breach has occurred. By having a better sense of each customer’s baselines, MSPs can more quickly spot problems and isolate threats.




SYSTEMS SECURITY CONCEPTS
Principles of network security
CIA TRIAD
The fundamentals of security → Confidentiality, Integrity, Availability 

Confidentiality 
Prevents disclosure of information to unauthorized individuals or systems
Certain information should only be known to certain people
Use Encryption
Encode messages so only certain people can read it
Implement access controls
Selectively restrict access to a resource
Use steganography
Conceal information within another piece of information
Commonly associated with hiding information in an image		

Integrity
Messages can’t be modified without detection  
Data is stored and transferred as intended
	Any modification to the data would be identified
Use Hashing 
	Map data of an arbitrary length to data of a fixed length
Use digital signatures
	Mathematical scheme to verify the integrity of data
Use certificates
	Combine with a digital signature to verify an individual
Non-repudiation
	Provides proof of integrity, can be asserted to be genuine

Availability 
Systems and networks must be up and running
Information is accessible to authorized users
Always at your fingertips
Use redundancy
Build services that will always be available  
Fault tolerance 
	The system will continue to run, even when a failure occurs
Patching
	Stability, close security holes


Common Network Security Vulnerabilities
Improperly installed hardware or software
Operating systems or firmware that have not been updated
Misused hardware or software
Poor or a complete lack of physical security
Insecure passwords

Design flaws in a device’s operating system or in the network

System Architecture
Reflects how the system is used and how it interacts with other systems and the outside world. 
It describes the interconnection of all the system’s components and the data link between them. 
	Kernel
The kernel in the operating system is responsible for managing the resources of the system such as memory, CPU, and input-output devices. The kernel is responsible for the implementation of the essential functions.
Shell
The shell in an Operating System acts as an interface for the user to interact with the computer system. The shell can be a command line interface or a graphical interface.

System Architecture Diagram
A visual representation of the system architecture. 
It shows the connections between the various components of the system and indicates what functions each component performs.

Operating System Architecture
A design that enables user application programs to communicate with the hardware of the machine. 
The operating system should be built with the utmost care because it is such a complicated structure and should be simple to use and modify. 

Operating System Diagram


Operating System Structure
Simple Structure
The most straightforward operating system structure, but it lacks definition and is only appropriate for usage with tiny and restricted systems.
	Advantages of Simple Structure
		Because there are only a few interfaces and levels, it is simple to develop.	
Because there are fewer layers between the hardware and the applications, it offers superior performance.
Disadvantages of Simple Structure:
The entire operating system breaks if just one user program malfunctions.
Since the layers are interconnected, and in communication with one another, there is no abstraction or data hiding.
The operating system's operations are accessible to layers, which can result in data tampering and system failure.

	Monolithic Structure
Controls all aspects of the operating system's operation, including file management, memory management, device management, and operational operations.
		Advantages of Monolithic Structure
Because layering is unnecessary and the kernel alone is responsible for managing all operations, it is easy to design and execute.
Due to the fact that functions like memory management, file management, process scheduling, etc., are implemented in the same address area, the monolithic kernel runs rather quickly when compared to other systems. Utilizing the same address speeds up and reduces the time required for address allocation for new processes.
Disadvantages of Monolithic Structure
The monolithic kernel's services are interconnected in address space and have an impact on one another, so if any of them malfunctions, the entire system does as well.
It is not adaptable. Therefore, launching a new service is difficult.

	Layered Structure
	The OS is separated into layers or levels in this kind of arrangement. 
Layer 0 (the lowest layer) contains the hardware, and layer 1 (the highest layer) contains the user interface (layer N). 
These layers are organized hierarchically, with the top-level layers making use of the capabilities of the lower-level ones.
Advantages of Layered Structure
Work duties are separated since each layer has its own functionality, and there is some amount of abstraction.
Debugging is simpler because the lower layers are examined first, followed by the top layers.
Disadvantages of Layered Structure
Performance is compromised in layered structures due to layering.
Construction of the layers requires careful design because upper layers only make use of lower layers' capabilities.

Micro-Kernel Structure
	Strips the kernel of any unnecessary parts.
Each Micro-Kernel is created separately and is kept apart from the others. As a result, the system is now more trustworthy and secure. 
If one Micro-Kernel malfunctions, the remaining operating system is unaffected and continues to function normally.

Advantages of Micro-Kernel Structure
It enables portability of the operating system across platforms.
Due to the isolation of each Micro-Kernel, it is reliable and secure.
The reduced size of Micro-Kernels allows for successful testing.
The remaining operating system remains unaffected and keeps running properly even if a component or Micro-Kernel fails.
Disadvantages of Micro-Kernel Structure

The performance of the system is decreased by increased inter-module communication.
The construction of a system is complicated.

		
	Exokernel
Goal is to enable application-specific customization by separating resource management from protection. 
Exokernel size tends to be minimal due to its limited operability.	
	Exokernel operating systems have a number of features, including:
Enhanced application control support.
Splits management and security apart.
A secure transfer of abstractions is made to an unreliable library operating system.
Brings up a low-level interface.
Operating systems for libraries provide compatibility and portability.
Advantages of Exokernel Structure
Application performance is enhanced by it.
Accurate resource allocation and revocation enable more effective utilisation of hardware resources.
New operating systems can be tested and developed more easily.
Every user-space program is permitted to utilise its own customised memory management.
Disadvantages of Exokernel Structure
A decline in consistency
Exokernel interfaces have a complex architecture.


	Virtual Machines (VMs)
The hardware of our personal computer, including the CPU, disc drives, RAM, and NIC (Network Interface Card), is abstracted by a virtual machine into a variety of various execution contexts based on our needs, giving us the impression that each execution environment is a separate computer.

Using CPU scheduling and virtual memory techniques, an operating system allows us to execute multiple processes simultaneously while giving the impression that each one is using a separate processor and virtual memory.
Advantages of Virtual Machines
Due to total isolation between each virtual machine and every other virtual machine, there are no issues with security.
A virtual machine may offer an architecture for the instruction set that is different from that of actual computers.
Simple availability, accessibility, and recovery convenience.
Disadvantages of Virtual Machines
Depending on the workload, operating numerous virtual machines simultaneously on a host computer may have an adverse effect on one of them.
When it comes to hardware access, virtual computers are less effective than physical ones.


System Exploits (hardware, operating system, and memory)
A computer exploit is a type of malware that takes advantage of bugs or vulnerabilities, which cybercriminals use to gain illicit access to a system.	
These vulnerabilities are hidden in the code of the operating system and its applications just waiting to be discovered and put to use by cybercriminals. Commonly exploited software includes the operating system itself, browsers, Microsoft Office, and third-party applications
	
The Seven Layers Of Cybersecurity 
Mission-Critical Assets
This is data that is absolutely critical to protect.
An example of mission-critical assets in the Healthcare industry is Electronic Medical Record (EMR) software. In the financial sector, its customer’s financial records.

Data Security
 	When there are security controls put in place to protect both the transfer and the storage of data
There has to be a backup security measure in place to prevent the loss of data, This will also require the use of encryption and archiving.  
Data security is an important focus for all businesses as a breach of data can have dire consequences. 

Endpoint Security
Makes sure that the endpoints of user devices are not exploited by breaches. This includes the protection of mobile devices, desktops, and laptops. 
Endpoint security systems enable protection either on a network or in the cloud depending on the needs of a business.

Application Security
This involves the security features that control access to an application and that application’s access to your assets. It also includes the internal security of the app itself.  
Most of the time, applications are designed with security measures that continue to provide protection when the app is in use.

Network Security
This is where security controls are put in place to protect the business’s network. The goal is to prevent unauthorized access to the network.  
It is crucial to regularly update all systems on the business network with the necessary security patches, including encryption. It’s always best to disable unused interfaces to further guard against any threats.


Perimeter Security
This security layer ensures that both the physical and digital security methods protect a business as a whole. 
It includes things like firewalls that protect the business network against external forces.  

The Human Layer
Despite being known as the weakest link in the security chain, the human layer is a very necessary layer. 
It incorporates management controls and phishing simulations as an example.  
These human management controls aim to protect that which is most critical to a business in terms of security. 
This includes the very real threat that humans, cyber attackers, and malicious users pose to a business.

CYBER THREAT INTELLIGENCE
What is Cyber Threat Intelligence?
Detailed, actionable threat information for preventing and fighting cyberthreats targeting an organization
Threat intelligence helps security teams be more proactive, enabling them to take effective, data-driven actions to prevent cyber attacks before they occur. It can also help an organization better detect and respond to attacks in progress.
Security analysts create threat intelligence by gathering raw threat information and security-related from multiple sources, then correlating and analyzing the data to uncover trends, patterns and relationships that provide in-depth understand of the actual or potential threats.

The Threat Intelligence Lifecycle
Planning
Threat Data Collection
Processing
Analysis
Dissemination/ Distribution of insights and recommendation
Feedback

Types Of Threat Intelligence
Tactical threat intelligence 
Used by the security operations center (SOC) to detect and respond to cyberattacks in progress.
It focuses typically on common IoCs—e.g., IP addresses associated with command and control servers, file hashes related to known malware and ransomware attacks, or email subject lines associated with phishing attacks.
In addition to helping incident response teams filter out false positives and intercept genuine attacks, tactical threat intelligence is also used by threat-hunting teams to track down advanced persistent threats (APTs) and other active but hidden attackers.

Operational threat intelligence 
Helps organizations anticipate and prevent future attacks. It is sometimes called ‘technical threat intelligence’ because it details the TTPs and behaviors of known threat actors—e.g., the attack vectors they use, the vulnerabilities they exploit, and the assets they target. CISOs, CIOs, and other information security decision-makers use operational threat intelligence to identify threat actors who are likely to attack their organizations, and respond with security controls and other actions aimed specifically at thwart their attacks.

Strategic threat intelligence 
High-level intelligence about the global threat landscape and an organization’s place within it. Strategic threat intelligence gives decision-makers outside of IT, such as CEOs and other executives, an understanding of the cyber threats their organizations face. Strategic threat intelligence usually focuses on issues such as geopolitical situations, cyber threat trends in a particular industry, or how or why certain of the organization’s strategic assets may be targeted. Stakeholders use strategic threat intelligence to align broader organizational risk management strategies and investments with the cyber threat landscape.



