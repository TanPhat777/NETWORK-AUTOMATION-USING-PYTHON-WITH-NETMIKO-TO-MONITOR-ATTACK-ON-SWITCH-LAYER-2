import time
import re
from datetime import datetime, timedelta
from netmiko import ConnectHandler

switch = {
    "device_type": "cisco_ios",
    "host": "192.168.104.7",
    "username": "admin",
    "password": "cisco123",
    "secret": "cisco123",
}

log_file_path = "/var/log/syslog-remote/syslog.log"
pattern = r"%SPANTREE-2-BLOCK_BPDUGUARD:.* (\S+)"

last_violation_time = None
violation_timeout = 30  # so giay cho khong co log vi pham de bat lai cong
interface = "Ethernet0/3"
port_shutdown = False

def print_simulated_log():
    timestamp = datetime.now().strftime("%b %d %H:%M:%S")
    log_message = f"{timestamp} SW %SPANTREE-2-BLOCK_BPDUGUARD: Received BPDU on {interface}, port disabled."
    print(log_message)

def shutdown_interface(net_connect):
    global port_shutdown
    print(f"Dang shutdown {interface}...")
    net_connect.send_config_set([
        f"interface {interface}",
        "shutdown"
    ])
    port_shutdown = True

def enable_interface(net_connect):
    global port_shutdown
    print(f"Dang bat lai {interface}...")
    net_connect.send_config_set([
        f"interface {interface}",
        "no shutdown"
    ])
    port_shutdown = False

def monitor_logs():
    global last_violation_time, port_shutdown

    print(f"Theo doi log tai {log_file_path}...")
    with open(log_file_path, "r") as file:
        file.seek(0, 2)  # Di den cuoi file

        while True:
            line = file.readline()
            if not line:
                time.sleep(1)
            else:
                if re.search(pattern, line):
                    last_violation_time = datetime.now()
                    print_simulated_log()

                    if not port_shutdown:
                        try:
                            net_connect = ConnectHandler(**switch)
                            net_connect.enable()
                            shutdown_interface(net_connect)
                            net_connect.disconnect()
                        except Exception as e:
                            print(f"Loi khi shutdown {interface}: {e}")

            # Kiem tra timeout de bat lai cong
            if port_shutdown and last_violation_time:
                elapsed = datetime.now() - last_violation_time
                if elapsed.total_seconds() > violation_timeout:
                    try:
                        net_connect = ConnectHandler(**switch)
                        net_connect.enable()
                        enable_interface(net_connect)
                        net_connect.disconnect()
                        print(f"Da bat lai {interface} sau {violation_timeout} giay khong phat hien log vi pham.")
                        last_violation_time = None  # reset
                    except Exception as e:
                        print(f"Loi khi bat lai {interface}: {e}")

if __name__ == "__main__":
    monitor_logs()
