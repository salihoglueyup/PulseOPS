from collectors.ssh_collector import SSHCollector
from models.ports import PortExposure

MOCK_SECTIONS = {
    "HOST": "prod-ubuntu-01\n6.5.0-35-generic\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"",
    "UPTIME": "86400.50 172800.00",
    "LOAD": "4\n0.42 0.35 0.28 2/350 49201",
    "MEM": """              total        used        free      shared  buff/cache   available
Mem:    16777216000  8388608000  4194304000   100000000  4194304000  7900000000
Swap:    4294967296   100000000  4194967296""",
    "DISK": """Filesystem     1B-blocks        Used   Available Use% Mounted on
/dev/sda1    50000000000 20000000000 30000000000  40% /
/dev/sdb1   100000000000 60000000000 40000000000  60% /data""",
    "NET": """Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  eth0: 104857600   12000    0    0    0     0          0         0 52428800    8000    0    0    0     0       0          0""",
    "PORTS": """Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess
tcp   LISTEN 0      128          0.0.0.0:80         0.0.0.0:*    users:(("nginx",pid=1200,fd=6))
tcp   LISTEN 0      128          0.0.0.0:443        0.0.0.0:*    users:(("nginx",pid=1200,fd=7))
tcp   LISTEN 0      128        127.0.0.1:3000       0.0.0.0:*    users:(("node",pid=3450,fd=12))
tcp   LISTEN 0      128          0.0.0.0:3306       0.0.0.0:*    users:(("mysqld",pid=5600,fd=22))""",
    "NGINX": """server {
    listen 80;
    server_name example.com www.example.com;
    location / {
        proxy_pass http://127.0.0.1:3000;
    }
}""",
    "TIMERS": """NEXT                         LEFT          LAST                         PASSED       UNIT                         ACTIVATES
Thu 2026-10-01 02:00:00 UTC  12h left      Wed 2026-09-30 02:00:00 UTC  12h ago      db-backup.timer              db-backup.service""",
    "DOCKER": """{"ID":"c123456789ab","Names":"strapi-api","Image":"strapi:v4","Status":"Up 3 days","Ports":"0.0.0.0:1337->1337/tcp","RunningFor":"3 days"}""",
    "PROCS": """  PID USER     %CPU %MEM COMMAND
 1200 root      1.2  4.5 nginx
 3450 app       3.5 12.0 node
 5600 mysql     2.0 15.5 mysqld""",
    "UFW": "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing)",
    "LOGS": """192.168.1.1 - - [30/Sep/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 4520 "-" "curl/7.81.0"
192.168.1.2 - - [30/Sep/2026:12:01:00 +0000] "GET /api/v1/health HTTP/1.1" 200 120 "-" "Mozilla/5.0" """
}

def test_ssh_collector_parsing():
    collector = SSHCollector(host="192.168.1.50", username="root")
    
    # 1. System Snapshot
    snapshot = collector.parse_system_snapshot(MOCK_SECTIONS)
    assert snapshot.hostname == "prod-ubuntu-01"
    assert "Ubuntu 24.04" in snapshot.os_name
    assert snapshot.kernel == "6.5.0-35-generic"
    assert snapshot.cpu.cores == 4
    assert snapshot.cpu.load_avg[0] == 0.42
    assert snapshot.memory.percent == 50.0
    assert len(snapshot.disks) == 2
    assert snapshot.disks[0].mountpoint == "/"
    assert snapshot.firewall.is_active is True
    assert len(snapshot.top_processes) == 3
    assert snapshot.top_processes[0].name == "nginx"

    # 2. Ports
    ports = collector._port_collector.parse_ss_text(MOCK_SECTIONS["PORTS"])
    assert len(ports) == 4
    port_dict = {p.port: p for p in ports}
    assert port_dict[80].exposure == PortExposure.PUBLIC_WEB
    assert port_dict[3000].exposure == PortExposure.SAFE_INTERNAL
    assert port_dict[3306].exposure == PortExposure.EXPOSED_RISK  # 0.0.0.0:3306 mysql alert!

    # 3. Nginx
    routes = collector._nginx_parser.parse_config_text(MOCK_SECTIONS["NGINX"])
    assert len(routes) == 1
    assert routes[0].domain == "example.com"
    assert routes[0].target_url == "http://127.0.0.1:3000"

    # 4. Timers
    backups = collector._backup_collector.parse_timers_text(MOCK_SECTIONS["TIMERS"])
    assert len(backups) == 1
    assert backups[0].name == "db-backup.timer"

    # 5. Containers
    containers = collector.parse_containers(MOCK_SECTIONS["DOCKER"])
    assert len(containers) == 1
    assert containers[0].name == "strapi-api"

def test_netstat_fallback_parsing():
    collector = SSHCollector(host="192.168.1.50")
    netstat_text = """
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1054/sshd: /usr/sbi 
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      1120/postgres       
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      2050/nginx: master  
"""
    ports = collector._port_collector.parse_ss_text(netstat_text)
    assert len(ports) == 3
    p_map = {p.port: p for p in ports}
    assert p_map[22].process_name == "sshd"
    assert p_map[5432].process_name == "postgres"
    assert p_map[5432].exposure == PortExposure.SAFE_INTERNAL

def test_nginx_upstream_resolution():
    collector = SSHCollector(host="192.168.1.50")
    nginx_conf = """
upstream nextjs_frontend {
    server 127.0.0.1:3000;
}
server {
    listen 80;
    server_name myapp.com;
    location / {
        proxy_pass http://nextjs_frontend;
    }
}
"""
    routes = collector._nginx_parser.parse_config_text(nginx_conf)
    assert len(routes) == 1
    assert routes[0].domain == "myapp.com"
    assert routes[0].target_port == 3000
    assert "3000" in routes[0].target_url
