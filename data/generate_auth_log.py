import random, datetime
random.seed(42)
host = "ubuntu-srv01"
end = datetime.datetime(2026,10,23,17,0,0)
start = end - datetime.timedelta(days=7)
total = (end-start).total_seconds()

def rip():
    while True:
        a = random.choice([45,46,58,61,80,89,91,103,109,113,117,119,122,125,138,141,144,159,167,171,178,185,188,193,194,195,203,212,218,222])
        return f"{a}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"

attackers = [rip() for _ in range(60)]
heavy = attackers[:8]
bad_users = ["admin","root","administrator","test","oracle","ubuntu","user","postgres","git","ftpuser","guest","pi","support","dev","mysql","deploy","jenkins","tomcat"]
good_users = ["alice","bob","devops","carol"]
internal = ["10.0.2.15","10.0.2.21","192.168.1.50","192.168.1.77"]
lines = []

def ts(t): return t.strftime("%b %d %H:%M:%S").replace(" 0"," ",1) if False else t.strftime("%b %d %H:%M:%S")
def pid(): return random.randint(1000,32000)
def port(): return random.randint(30000,65000)

# brute force bursts
for _ in range(140):
    ip = random.choice(heavy) if random.random()<0.6 else random.choice(attackers)
    t0 = start + datetime.timedelta(seconds=random.random()*total)
    # attackers prefer night hours
    if random.random()<0.6: t0 = t0.replace(hour=random.choice([0,1,2,3,4,5,22,23]))
    n = random.randint(8,60)
    p = pid()
    for i in range(n):
        t = t0 + datetime.timedelta(seconds=i*random.randint(1,4))
        u = random.choice(bad_users)
        if u == "root" or random.random()<0.25:
            lines.append((t, f"{ts(t)} {host} sshd[{p}]: Failed password for {u} from {ip} port {port()} ssh2"))
        else:
            lines.append((t, f"{ts(t)} {host} sshd[{p}]: Invalid user {u} from {ip} port {port()}"))
            lines.append((t, f"{ts(t)} {host} sshd[{p}]: Failed password for invalid user {u} from {ip} port {port()} ssh2"))
    lines.append((t0, f"{ts(t0)} {host} sshd[{p}]: Connection closed by authenticating user root {ip} port {port()} [preauth]"))

# compromised: success after many failures
for ip,u in [(attackers[3],"test"),(attackers[11],"ubuntu"),(attackers[20],"deploy")]:
    t0 = start + datetime.timedelta(seconds=random.random()*total)
    p = pid()
    for i in range(25):
        t = t0 + datetime.timedelta(seconds=i*2)
        lines.append((t, f"{ts(t)} {host} sshd[{p}]: Failed password for {u} from {ip} port {port()} ssh2"))
    t = t0 + datetime.timedelta(seconds=55)
    lines.append((t, f"{ts(t)} {host} sshd[{p}]: Accepted password for {u} from {ip} port {port()} ssh2"))
    lines.append((t, f"{ts(t)} {host} sshd[{p}]: pam_unix(sshd:session): session opened for user {u} by (uid=0)"))

# legit logins during working hours
for _ in range(450):
    day = start + datetime.timedelta(days=random.randint(0,6))
    t = day.replace(hour=random.randint(9,18), minute=random.randint(0,59), second=random.randint(0,59))
    if t>end: continue
    u = random.choice(good_users); ip = random.choice(internal); p=pid()
    method = random.choice(["password","publickey"])
    if random.random()<0.08:
        lines.append((t, f"{ts(t)} {host} sshd[{p}]: Failed password for {u} from {ip} port {port()} ssh2"))
        t += datetime.timedelta(seconds=6)
    lines.append((t, f"{ts(t)} {host} sshd[{p}]: Accepted {method} for {u} from {ip} port {port()} ssh2"))
    lines.append((t, f"{ts(t)} {host} sshd[{p}]: pam_unix(sshd:session): session opened for user {u} by (uid=0)"))
    t2 = t + datetime.timedelta(minutes=random.randint(2,120))
    lines.append((t2, f"{ts(t2)} {host} sshd[{p}]: pam_unix(sshd:session): session closed for user {u}"))

# sudo noise
for _ in range(80):
    t = start + datetime.timedelta(seconds=random.random()*total)
    u = random.choice(good_users)
    lines.append((t, f"{ts(t)} {host} sudo:   {u} : TTY=pts/0 ; PWD=/home/{u} ; USER=root ; COMMAND=/usr/bin/apt update"))

lines = [l for l in lines if l[0] <= end]
lines.sort(key=lambda x:x[0])
with open("auth.log","w") as f:
    for _,l in lines: f.write(l+"\n")
print(len(lines))
