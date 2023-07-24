
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
Malware, or “malicious software,” is a common form of cyberattack that comes in many different shapes and sizes. Some variations work quickly to delete files or corrupt data, while others can lie dormant for long periodsof time and quietly allow hackers a back door into your systems. The best antivirus software will monitor network traffic in real time for malware, scan activity log files for signs of suspicious behavior or long-term patterns, and offer threat remediation capabilities.

Application security
Each device and software product used within your networking environment offers a potential way in for hackers. For this reason, it is important that all programs be kept up-to-date and patched to prevent cyberattackers from exploiting vulnerabilities to access sensitive data. Application security refers to the combination of hardware, software, and best practices you use to monitor issues and close gaps in your security coverage.

Behavioral analytics 
In order to identify abnormal behavior, security support personnel need to establish a baseline of what constitutes normal behavior for a given customer’s users, applications, and network. Behavioral analytics software is designed to help identify common indicators of abnormal behavior, which can often be a sign that a security breach has occurred. By having a better sense of each customer’s baselines, MSPs can more quickly spot problems and isolate threats.

Data loss prevention
Data loss prevention (DLP) technologies are those that prevent an organization’s employees from sharing valuable company information or sensitive data—whether unwittingly or with ill intent—outside the network. DLP technologies can prevent actions that could potentially expose data to bad actors outside the networking environment, such as uploading and downloading files, forwarding messages, or printing.

Email security
Email is an especially important factor to consider when implementing networking security tools. Numerous threat vectors, like scams, phishing, malware, and suspicious links, can be attached to or incorporated into emails. Because so many of these threats will often use elements of personal information in order to appear more convincing, it is important to ensure an organization’s employees undergo sufficient security awareness training to detect when an email is suspicious. Email security software works to filter out incoming threats and can also be configured to prevent outgoing messages from sharing certain forms of data.

Mobile device security
The vast majority of us have mobile devices that carry some form of personal or sensitive data we would like to keep protected. This is a fact that hackers are aware of and can easily take advantage of. Implementing mobile device security measures can limit device access to a network, which is a necessary step to ensuring network traffic stays private and doesn’t leak out through vulnerable mobile connections.

Network segmentation
Dividing and sorting network traffic based on certain classifications streamlines the job for security support personnel when it comes to applying policies. Segmented networks also make it easier to assign or deny authorization credentials for employees, ensuring no one is accessing information they should not be. Segmentation also helps to sequester potentially compromised devices or intrusions.

Web security 
Web security software serves a few purposes. First, it limits internet access for employees, with the intention of preventing them from accessing sites that could contain malware. It also blocks other web-based threats and works to protect a customer’s web gateway.

Encryption
The process of scrambling data to the point of unintelligibility and providing only authorized parties the key (usually a decryption key or password) to decode it. This way, even if data is intercepted or seen by an unauthorized user, they are unable to read it.

Multi-Factor Authentication
Simple: users must provide two separate methods of identification to log into an account (for instance, typing in a password and then typing in a numeric code that was sent to another device). Users should present unique credentials from two out of three categories — something you know, something you have and something you are — for multi-factor authentication to be fully effective.


Network Troubleshooting Applications

Packet Sniffer
Provides a comprehensive view of a given network. You can use this application to analyze traffic on the network, figure out which ports are open and identify network vulnerabilities.

Port Scanner
Looks for open ports on the target device and gathers information, including whether the port is open or closed, what services are running on a given port and information about the operating system on that machine. This application can be used to figure out which ports are in use and identify points in a network that could be vulnerable to outside attacks.

Protocol Analyzer
Integrates diagnostic and reporting capabilities to provide a comprehensive view of an organization's network. You can use analyzers to troubleshoot network problems and detect intrusions into your network.
Wi-Fi Analyzer: Detects devices and points of interference in a Wi-Fi signal. This tool can help you to troubleshoot issues in network connectivity over a wireless network.

Bandwidth Speed Tester
Tests the bandwidth and latency of a user’s internet connection. This application is typically accessed through a third-party website and can be used to confirm user reports about slow connections or download speeds.

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



