# Sandbox isolation

CAPEv2 detonates live malware in a Windows 10 KVM guest (label `win10`). The guest must never reach the
internet, the lab LAN, or the Tailscale network that connects the analyzer to the Wazuh manager.

## 1. CAPE routing

`/opt/CAPEv2/conf/routing.conf`

```ini
[routing]
route = none
```

With `route = none` CAPE adds no NAT or forwarding for the guest, so samples run fully offline. This is why
network-based signatures (for example T1071, application-layer C2) show attempts that never connect.

## 2. Host firewall

Traffic from the guest bridge (`virbr0`) to private ranges and Tailscale is dropped on the CAPE host. The guest
can still reach the CAPE result server on `192.168.122.1`, which it needs to send results back.

Example rules (check them against what is actually applied with `sudo iptables -S FORWARD`):

```bash
sudo iptables -I FORWARD -i virbr0 -o tailscale0 -j DROP
sudo iptables -I FORWARD -i virbr0 -d 100.64.0.0/10 -j DROP
sudo iptables -I FORWARD -i virbr0 -d 10.0.0.0/8 -j DROP
sudo iptables -I FORWARD -i virbr0 -d 172.16.0.0/12 -j DROP
sudo iptables -I FORWARD -i virbr0 -d 192.168.0.0/16 ! -d 192.168.122.1 -j DROP
sudo netfilter-persistent save
```

## 3. Handling rules

- Payloads stay inside the lab VMs. They are never copied to a host laptop or sent by real email.
- Downloaded files are saved with restricted permissions and never executed on the analyzer VM.
- The phishing link is never opened from a personal browser; only the analyzer's isolated Chromium fetches it.
