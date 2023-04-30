# Intrusion-Detection-Using-Zeek
Zeek Scripts for detecting various types of attacks including Password Guessing, HTTP Dos ,DNS DDos and SYN Flood Attack  


Zeek (formerly known as Bro) is an open-source network security monitoring platform. It analyzes network traffic in real-time to detect and report on network events, such as malware infections, intrusion attempts, and network misconfigurations. Zeek uses a script-based approach to monitoring network traffic, where scripts are used to specify what data to collect and how to process it. This approach allows for flexible and customizable network monitoring, as users can write their own scripts to analyze network traffic specific to their environment.

Zeek scripting refers to the process of writing scripts to define what data to capture and how to analyze it within Zeek. Zeek scripts are written in a high-level programming language that is specific to the platform, which provides access to a rich set of built-in functionality and data structures. This allows users to write scripts to extract and process specific data from network traffic, such as identifying specific network protocols or extracting data from specific packets. Zeek scripting also provides the ability to write custom scripts to detect and respond to specific security threats or events, enabling organizations to tailor their network monitoring to their specific security needs.


<br>
<b> Brute Force Attack </b> <br> 

A brute force attack, also known as a password guessing attack, is a method of trying to crack a password by guessing all possible combinations of characters until the correct one is found. It is often used by hackers to gain access to secure systems and can be prevented by using strong passwords, different passwords for different accounts, and changing them regularly. Systems can also have built-in security measures to prevent brute force attacks.

<br> <b> CTF </b> <br>
CTF stands for "Capture The Flag". It is a type of cybersecurity competition or game where participants, typically individuals or teams, compete to solve a variety of challenges related to computer security, cryptography, reverse engineering, and other related fields.

The goal of a CTF competition is to find and capture digital "flags" that have been hidden within various challenges. These flags are typically unique strings of characters or data that are meant to be discovered by the competitors, either by exploiting vulnerabilities or by solving puzzles. <br>

<b> HTTP DoS Attack</b>

HTTP DoS is a type of cyber attack that floods a web server or web application with a high volume of requests in a short amount of time, causing it to become overwhelmed and unavailable. This can be prevented through security measures such as rate-limiting and intrusion detection systems.


<b> SYN Flood Attack</b>


A SYN flood attack is a type of cyber attack that exploits a weakness in the TCP protocol by flooding a server with a high volume of incomplete TCP connection requests, causing it to become overwhelmed and unavailable.


<b> DNS DDoS </b>


DNS DDoS is a type of cyber attack that targets the Domain Name System (DNS) infrastructure by flooding DNS servers with a high volume of traffic, causing them to become overwhelmed and unavailable. This can be prevented through security measures such as rate-limiting, traffic filtering, and DNS caching, as well as keeping DNS server software up-to-date with the latest security patches.


# Installation
You must have installed zeek in your machine for running and executing the pcap files and zeek scripts.
For downloading zeek you can refer too : https://zeek.org/get-zeek/

# Usage 
You can run the scripts using the following command : <b> "path-to-zeek -C -r nameofpcap.pcap nameofscript.zeek"</b><br>
For example "/opt/zeek/bin/zeek -Cr sshguess.pcap brtforce.zeek"

# Credits:
<b>Harsh Rawat,Gaurav Agarwal,Amit Prakhar Pandey,Ashis J Kalthil </b>


https://www.malware-traffic-analysis.net/index.html :A huge thanks to this site for helping us find out the pcaps and also knowledge to detect these attacks 


And a special thanks to our guide and mentor <b> Dr. Radhika B S </b> 
