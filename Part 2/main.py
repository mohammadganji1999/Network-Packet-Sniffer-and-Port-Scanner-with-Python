from services import*


def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

host = input("Enter Host: ")
sp = int(input("Enter Lower Range: "))
ep = int(input("Enter Upper Range: "))
print("1.Connect Scan")
print("2.Ack Scan")
print("3.Syn Scan")
print("4.Fin Scan")
print("5.Windows Scan")
sType = int(input("Enter Scan Type:"))
delay = int(input("Enter Delay: "))

try:
    assert sp > 0 and ep > 0 and sp <= ep
except AssertionError:
    print("[ERROR] Port range is invalid")
    sys.exit()

openPorts = []
closedPorts = []
filteredPorts = []
unfilteredPorts = []

def con_scan(target, sP, eP, dl):

    for i in range(sP, eP+1):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(3)
        result = s.connect_ex((target, i))
        if result == 0:
            if str(i) in services:
                print("Port " + str(i) + ' ' + services[str(i)] + " Is Open")
            else:
                print("Port " + str(i) + " Is Open")
            openPorts.append(i)
        else:
            if str(i) in services:
                print("Port " + str(i) + ' ' + services[str(i)] + " Is Closed")
            else:
                print("Port " + str(i) + " Is Closed")
            closedPorts.append(i)
        s.close()
        time.sleep(dl)

    summary()

def ack_scan(target, sP, eP, dl):
    for i in range(sP, eP + 1):
        p = Packet(local_ip(), target, i, 0)#[Ack=1]
        p.generate_packet()
        result = p.send_packet()
        conts = binascii.hexlify(result)
        if conts[65:68] == b"004" or conts[65:68] == b"014": #(0x04=[RST], 0x14=[RST,Ack])
            if str(i) in services:
                print("Port " + str(i) + ' ' + services[str(i)] + " Is Unfiltered")
            else:
                print("Port " + str(i) + " Is Unfiltered")
            unfilteredPorts.append(i)
        else:
            if str(i) in services:
                print("Port " + str(i) + ' ' + services[str(i)] + " Is Filtered")
            else:
                print("Port " + str(i) + " Is Filtered")
            filteredPorts.append(i)
        time.sleep(dl)

    summary()

def syn_scan(target, sP, eP, dl):
    for i in range(sP, eP+1):
        p = Packet(local_ip(), target, i, 1)#[Syn=1]
        p.generate_packet()
        result = p.send_packet()
        cont = binascii.hexlify(result)
        if cont[65:68] == b"012" or cont[65:68] == b"010":#(0x12=[Syn,Ack])
            if str(i) in services:
                print("Port " + str(i) + ' ' + services[str(i)] + " Is Open")
            else:
                print("Port " + str(i) + " Is Open")
            openPorts.append(i)
        elif cont[65:68] == b"004" or cont[65:68] == b"014":# (0x04=[RST], 0x14=[RST,Ack])
            if str(i) in services:
                print("Port " + str(i) + ' ' + services[str(i)] + " Is Closed")
            else:
                print("Port " + str(i) + " Is Closed")
            closedPorts.append(i)
        else:
            if str(i) in services:
                print("Port " + str(i) + ' ' + services[str(i)] + " Is Filtered")
            else:
                print("Port " + str(i) + " Is Filtered")
            filteredPorts.append(i)
        time.sleep(dl)

    summary()

def fin_scan(target, sP, eP, dl):
    for i in range(sP, eP + 1):
        p = Packet(local_ip(), target, i, 2)  # [Fin=1]
        p.generate_packet()
        result = p.send_packet()
        conts = binascii.hexlify(result)
        if conts[65:68] == b"004" or conts[65:68] == b"014":  # (0x04=[RST], 0x14=[RST,Ack])
            if str(i) in services:
                print("Port " + str(i) + ' ' + services[str(i)] + " Is Closed")
            else:
                print("Port " + str(i) + " Is Closed")
            closedPorts.append(i)
        else:
            if str(i) in services:
                print("Port " + str(i) + ' ' + services[str(i)] + " Is Open|Filtered")
            else:
                print("Port " + str(i) + " Is Open|Filtered")
            openPorts.append(i)
            filteredPorts.append(i)
        time.sleep(dl)
    summary()

def win_scan(target, sP, eP, dl):
    for i in range(sP, eP + 1):
        p = Packet(local_ip(), target, i, 0)  # [Ack=1]
        p.generate_packet()
        result = p.send_packet()
        cont = binascii.hexlify(result)
        if cont[65:68] == b"004" or cont[65:68] == b"014" and cont[69:84] != b"0":  # (0x04=[RST], 0x14=[RST,Ack]) and window field != 0
            if str(i) in services:
                print("Port " + str(i) + ' ' + services[str(i)] + " Is Open")
            else:
                print("Port " + str(i) + " Is Open")
            openPorts.append(i)
        elif cont[65:68] == b"004" or cont[65:68] == b"014" and cont[69:84] == b"0":  # (0x04=[RST], 0x14=[RST,Ack]) and window field == 0
            if str(i) in services:
                print("Port " + str(i) + ' ' + services[str(i)] + " Is Closed")
            else:
                print("Port " + str(i) + " Is Closed")
            closedPorts.append(i)
        else:
            if str(i) in services:
                print("Port " + str(i) + ' ' + services[str(i)] + " Is Filtered")
            else:
                print("Port " + str(i) + " Is Filtered")
            filteredPorts.append(i)
        time.sleep(dl)

    summary()


def summary():
        print("============================================================================================")
        print("There are {0} open ports, {1} filtered ports, {2} closed ports and {3} unfilterd ports".format(len(openPorts), len(filteredPorts), len(closedPorts), len(unfilteredPorts)))
        print("The following ports are open:")
        print("Port\t\tService")
        for port in openPorts:
            p = str(port)
            if p in services:
                print(p+"\t\t\t"+services[p])
            else:
                print(p+"\t\t\tUnknown")


def scan(tgt, bP, eP, mode,dl):
    scanModes = {1: con_scan,
                 2: ack_scan,
                 3: syn_scan,
                 4: fin_scan,
                 5: win_scan,
                 }

    scanModes[mode](tgt, bP, eP,dl)

hostaddr = socket.gethostbyname(host)
scan(hostaddr, sp, ep, sType, delay)