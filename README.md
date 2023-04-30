# Intrusion-Detection-Using-Zeek
Zeek Scripting for detecting various types of attacks including Password Guessing, HTTP Dos ,DNS DDos and SYN Flood Attack  
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
