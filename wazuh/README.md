# Wazuh

The analyzer writes one JSON event per line to `~/analyzer/logs/analyzer.json`. A Wazuh agent on the analyzer VM
ships that file to a Wazuh manager.

- Agent install and `ossec.conf` entry: [`docs/setup.md`](../docs/setup.md#6-wazuh-agent)
- Event types and fields: [`docs/how-it-works.md`](../docs/how-it-works.md#logging)
- Example manager rules: [`local_rules.example.xml`](local_rules.example.xml), which goes in
  `/var/ossec/etc/rules/local_rules.xml` on the manager

The Wazuh manager, its rules and the Grafana dashboards used in this lab are in
[Lucas's repo](https://github.com/Lucas952-eng/Wazuh-SIEM-CAPEV2-LAB).
