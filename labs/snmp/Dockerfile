FROM python:3-slim

# SNMP lab: a deterministic UDP/161 agent. app.py answers ONLY the
# "private-lab" community (real-agent behavior: wrong community =
# silence), serving a small fixed OID set. snmp_codec.py is the repo's
# own core/snmp.py copied in — the lab and the modules share one codec.
WORKDIR /app
COPY labs/snmp/app.py /app/app.py
COPY core/snmp.py /app/snmp_codec.py
EXPOSE 161/udp
CMD ["python", "-u", "app.py"]
