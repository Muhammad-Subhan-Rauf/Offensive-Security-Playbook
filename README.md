# Offensive-Security-Playbook

# Advanced Offensive Security & Mobile Exploitation Project

This repository contains the source code for a multi-stage cybersecurity project completed for the CSCS 495 Cyber Security course. The project demonstrates a full attack chain, from initial network intrusion via Man-in-the-Middle (MitM) attacks to client-side exploitation and payload delivery on an Android device.

---

## ⛓️ Attack Chain Overview

The project simulates a real-world attack scenario where an attacker on a local network gains control over a victim's traffic and uses that position to compromise their devices.

1.  **Gain Network Control (MitM):** The attacker first performs an **ARP Spoofing** attack to poison the ARP cache of the victim machine and the network gateway. This forces all of the victim's traffic to pass through the attacker's machine.

2.  **Redirect Maliciously (DNS Spoofing):** With traffic redirected, the attacker runs a **DNS Spoofer**. When the victim tries to access a specific website (e.g., `vulnweb.com`), the spoofer intercepts the DNS query and responds with the IP address of the attacker's own web server, leading the victim to a malicious page.

3.  **Compromise Mobile Device (APK Trojanizing):** The project demonstrates how to create a native reverse shell payload using the **Android NDK**. This C-based binary is then injected into a legitimate Android application (APK). The APK is decompiled, the payload and execution code (in Smali) are added, and the application is recompiled and signed, turning it into a trojan. When the unsuspecting user runs the app, it executes the payload, giving the attacker a reverse shell.

4.  **Client-Side Exploitation (Browser Hooking - Optional Task):** As an extension, the project includes a `mitmproxy` script to inject a **BeEF (Browser Exploitation Framework)** hook into any unencrypted HTTP web page the victim visits. This effectively hijacks the victim's browser, allowing for further client-side attacks.

---

## ⚙️ Core Components & Scripts

This repository includes the following key scripts:

#### `arpspoofer2.py`
*   **Purpose:** Establishes the Man-in-the-Middle position.
*   **Functionality:**
    *   Identifies the MAC addresses of the victim and the gateway.
    *   Sends crafted ARP packets to the victim, telling it the attacker's MAC address belongs to the gateway.
    *   Sends crafted ARP packets to the gateway, telling it the attacker's MAC address belongs to the victim.
    *   Includes a `finally` block to automatically restore the network's ARP tables upon exit (`Ctrl+C`), preventing permanent network disruption.

#### `dnsspoofer2.py`
*   **Purpose:** To perform DNS hijacking once MitM is active.
*   **Functionality:**
    *   Uses `scapy.sniff` with a BPF filter to efficiently capture DNS queries (UDP port 53) from the victim.
    *   Checks if the queried domain is on a target list.
    *   If a match is found, it crafts a fake DNS response packet, mapping the domain to the attacker's IP address.
    *   Sends the spoofed response directly to the victim, racing against the real DNS server's response.

#### Android Reverse Shell (`revshell.c` - *not provided, but created as part of the project*)
*   **Purpose:** The native payload to be executed on the Android device.
*   **Functionality:**
    *   A standard C program that opens a socket connection back to the attacker's IP and port.
    *   Duplicates the `stdin`, `stdout`, and `stderr` file descriptors to the socket, effectively spawning `/bin/sh` and giving the attacker a remote shell.
    *   Compiled using the Android NDK for the target architecture (e.g., `x86` for an emulator).

#### `SplashScreen.smali.txt` (Payload Dropper & Executor)
*   **Purpose:** The injected code that runs the native payload.
*   **Functionality:**
    *   This is Smali assembly code injected into a decompiled APK's `onCreate` method.
    *   It copies the native `revshell` binary from the APK's `assets` folder to the app's private, executable data directory.
    *   It changes the file permissions to make the binary executable (`setExecutable(true)`).
    *   It uses `Runtime.getRuntime().exec()` to execute the binary, triggering the reverse shell.

#### `beef_injector.py` (Optional Task)
*   **Purpose:** To hook browsers using the BeEF framework.
*   **Functionality:**
    *   A `mitmproxy` addon script.
    *   Intercepts all HTTP responses.
    *   If a response is of type `text/html`, it injects the BeEF `hook.js` script tag just before the `</head>` or `</body>` tag.
    *   This hooks the victim's browser to the attacker-controlled BeEF panel.

---

## 🚀 Execution Guide

### Prerequisites
*   A Linux environment (Kali Linux recommended).
*   Python 3 and required libraries: `pip install scapy mitmproxy`
*   Android NDK installed and configured.
*   An Android emulator (Genymotion recommended).
*   A benign target APK for trojanizing.
*   `apktool` for decompiling/recompiling the APK.

### Task 1: MitM Attack & DNS Spoofing

1.  **Configure Scripts:** Update the IP addresses in `dnsspoofer2.py` and `arpspoofer2.py` to match your network setup (Kali IP, Victim IP, Gateway IP).
2.  **Enable IP Forwarding:** On the attacker machine, enable packet forwarding to allow victim traffic to pass through to the internet.
    ```bash
    sudo sysctl -w net.ipv4.ip_forward=1
    ```
3.  **Start Web Server:** Host a fake website on the attacker machine.
    ```bash
    sudo systemctl start apache2
    # Place your index.html in /var/www/html/
    ```
4.  **Launch Attacks:** Open two separate terminals on the attacker machine.
    *   **Terminal 1 (ARP Spoofer):**
        ```bash
        sudo python3 arpspoofer2.py
        ```
    *   **Terminal 2 (DNS Spoofer):**
        ```bash
        sudo python3 dnsspoofer2.py
        ```
5.  **Test:** On the victim machine, try to access `http://vulnweb.com` or `http://example.com`. You should be served the page from your attacker's web server.

### Task 2: Android APK Trojanizing

1.  **Create Payload:** Write and compile your `revshell.c` using the Android NDK.
    ```bash
    # (Inside your NDK project directory)
    $NDK_HOME/ndk-build
    ```
    This will create the `revshell` binary in the `libs/<architecture>/` directory.
2.  **Decompile APK:**
    ```bash
    apktool d original_app.apk -o decompiled_app
    ```
3.  **Inject Payload:**
    *   Copy the compiled `revshell` binary into the `decompiled_app/assets/` directory.
    *   Open the target Smali file (e.g., `decompiled_app/smali/com/dotgears/flappy/SplashScreen.smali`).
    *   Carefully insert the code from `SplashScreen.smali.txt` into the `onCreate` method.
4.  **Recompile & Sign:**
    ```bash
    # Recompile
    apktool b decompiled_app -o trojan_app.apk

    # Sign the APK (requires a keystore)
    jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-release-key.keystore trojan_app.apk alias_name
    ```
5.  **Execute:**
    *   Start a `netcat` listener on the attacker machine: `nc -lvnp 5555`.
    *   Install and run `trojan_app.apk` on the Android emulator.
    *   Check your `netcat` listener for an incoming reverse shell connection.

---

## 🛠️ Technologies Used

*   **Languages:** Python, C, Smali
*   **Core Libraries:** Scapy, Netfilterqueue, mitmproxy
*   **Tools:**
    *   Kali Linux
    *   Android NDK
    *   Genymotion (Android Emulator)
    *   APKTool
    *   BeEF (Browser Exploitation Framework)
    *   Wireshark (for analysis and debugging)

---

## ⚠️ Disclaimer

This project and all associated code are intended for **educational and research purposes only**. The techniques demonstrated here should only be used in a controlled, authorized lab environment. Using these tools or techniques against networks or devices without explicit permission is illegal and unethical. The author is not responsible for any misuse or damage caused by this code.
