# CAPEv2 configuration

These are the settings changed from CAPEv2's defaults in `/opt/CAPEv2/conf/` after following the
[setup guide](../docs/setup.md#2-capev2-sandbox). Everything not listed here was left at its default.

To list your own changes against the defaults:

```bash
cd /opt/CAPEv2/conf && for f in *.conf; do [ -f default/$f.default ] && diff -u default/$f.default $f; done
```

Restart CAPE after editing: `sudo systemctl restart cape cape-processor cape-web`.

## kvm.conf: the Windows 10 guest

```ini
[kvm]
machines = win10
interface = virbr0
dsn = qemu:///system

[win10]
label = win10
platform = windows
ip = 192.168.122.153
arch = x64
snapshot = snapshot1
resultserver_ip = 192.168.122.1
reserved = no
```

- `label` must match the libvirt VM name (`virsh list --all`). The analyzer submits with `machine="win10"`.
- `ip` is the guest's static address on the libvirt default network (`virbr0`, 192.168.122.0/24). Set the same
  address inside Windows.
- `snapshot` is the clean, running snapshot CAPE reverts to before every run. Take it with the CAPE agent
  already running in the guest.
- `arch = x64` matches the 64-bit Windows 10 build.

## cuckoo.conf: result server and database

```ini
[resultserver]
ip = 192.168.122.1
port = 2042

[database]
connection = postgresql://cape:<db-password>@localhost:5432/cape
```

- The result server listens on the host side of `virbr0`, so the guest can send results back. This is the one
  address the [firewall rules](isolation.md) leave reachable.
- PostgreSQL instead of the default SQLite, which CAPE recommends for anything beyond a quick test. Use your own
  database password.

## auxiliary.conf: packet capture and AMSI

```ini
[auxiliary_modules]
amsi_etw = yes

[sniffer]
interface = virbr0
```

- `interface = virbr0` points tcpdump at the bridge the guest actually uses (the default is `virbr1`), so
  network attempts are recorded even though they go nowhere.
- `amsi_etw = yes` logs what scripts hand to Windows AMSI (PowerShell, VBScript, JScript), which shows
  deobfuscated script content. It needs pywintrace installed in the guest.

## reporting.conf: MongoDB

```ini
[mongodb]
enabled = yes
```

The CAPE web interface and the `/apiv2` endpoints the analyzer reads (task status, reports) need MongoDB.

## api.conf: local API access

```ini
[api]
ratelimit = no

[cuckoostatus]
enabled = yes
```

- Rate limiting is off because the only API client is the analyzer on the same VM, which polls each task
  until it finishes. Keep the API bound to localhost if you do this.
- `cuckoostatus` exposes the host status endpoint, used to check CAPE is up.

## routing.conf

`route = none` is already CAPE's default and was left that way, so the guest gets no internet route. See
[isolation.md](isolation.md).
