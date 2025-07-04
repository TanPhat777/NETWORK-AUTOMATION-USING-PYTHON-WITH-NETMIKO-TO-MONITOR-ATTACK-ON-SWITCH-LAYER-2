################### DHCP Snooping ##########################

Code: nano /opt/dhcp_snooping_protect.py

import time
import re
import logging
from datetime import datetime
from pathlib import Path
from netmiko import ConnectHandler
import pygame
import threading
from collections import defaultdict
import signal
import sys

class DHCPSpoofingMonitor:
    def __init__(self):
        # Cấu hình logging
        self.setup_logging()

        # Cau hinh mac dinh
        self.log_file_path = "/var/log/syslog-remote/syslog.log"
        # Pattern cho DHCP spoofing attack
        self.patterns = [
            r"%DHCP_SNOOPING-4-DHCP_SNOOPING_UNTRUSTED_PORT.*interface (\S+)",
            r"%DHCP_SNOOPING-4-DHCP_SNOOPING_FAKE_INTERFACE.*port (\S+)",
            r"%DHCP_SNOOPING-6-BINDING_COLLISION.*interface (\S+)",
            r"%DHCP_SNOOPING-4-DHCP_SNOOPING_RATE_LIMIT_EXCEEDED.*interface (\S+)",
            r"%DHCP_SNOOPING-4-DHCP_SNOOPING_INVALID_PACKET.*interface (\S+)",
            r"%DHCP_SNOOPING-4-AGENT_OPERATION_FAILED.*interface (\S+)"
        ]
        self.switch_config = {
            "device_type": "cisco_ios",
            "host": "192.168.104.7",
            "username": "admin",
            "password": "cisco123",
            "secret": "cisco123",
        }
        
        # Cau hinh monitor
        self.interface_state = defaultdict(lambda: {
            "counter": 0, 
            "last_log": "", 
            "first_detected": None, 
            "last_activity": None,
            "is_attacking": False,
            "attack_type": "",
            "dhcp_packets_dropped": 0,
            "violation_count": 0,
            "fake_offers": 0,
            "binding_collisions": 0
        })
        self.stable_threshold = 5
        self.timeout_threshold = 30  # 30 giay khong co log moi = dung tan cong
        self.alert_sound_path = "/opt/alert.mp3"

        # Flags dieu khien
        self.running = True
        self.sound_enabled = True

        # Khoi tao pygame mixer
        self.init_sound_system()

        # Thiet lap signal handler de dung gracefully
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def setup_logging(self):
        """Thiet lap logging system"""
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)

        log_filename = log_dir / f"dhcp_spoofing_monitor_{datetime.now().strftime('%Y%m%d')}.log"

        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_filename, encoding='utf-8'),
                logging.StreamHandler(sys.stdout)
            ]
        )

        self.logger = logging.getLogger(__name__)
        self.logger.info("Bat dau theo doi tan cong DHCP Spoofing")
    
    def init_sound_system(self):
        """Khoi tao he thong am thanh"""
        try:
            pygame.mixer.init()
            if not Path(self.alert_sound_path).exists():
                self.logger.warning(f"Khong tim thay file am thanh: {self.alert_sound_path}")
                self.sound_enabled = False
            else:
                self.logger.info("He thong am thanh da san sang")
        except Exception as e:
            self.logger.error(f"Loi khoi tao am thanh: {e}")
            self.sound_enabled = False
               
    def play_alert(self):
        """Phat am thanh canh bao"""
        if not self.sound_enabled:
            return

        try:
            pygame.mixer.music.load(self.alert_sound_path)
            pygame.mixer.music.play()
        except Exception as e:
            self.logger.error(f"Loi phat am thanh: {e}")
    
    def tail_log_file(self):
        """Doc log file theo thoi gian thuc"""
        try:
            with open(self.log_file_path, "r", encoding='utf-8') as f:
                # Di chuyen den cuoi file
                f.seek(0, 2)

                while self.running:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    yield line.strip()

        except FileNotFoundError:
            self.logger.error(f"Khong tim thay file log: {self.log_file_path}")
            return
        except Exception as e:
            self.logger.error(f"Loi doc file log: {e}")
            return
    
    def detect_attack_type(self, log_line):
        """Xac dinh loai tan cong DHCP spoofing"""
        if "UNTRUSTED_PORT" in log_line:
            return "Untrusted Port DHCP Response"
        elif "FAKE_INTERFACE" in log_line:
            return "Fake DHCP Server"
        elif "BINDING_COLLISION" in log_line:
            return "DHCP Binding Collision"
        elif "RATE_LIMIT_EXCEEDED" in log_line:
            return "DHCP Rate Limit Exceeded"
        elif "INVALID_PACKET" in log_line:
            return "Invalid DHCP Packet"
        elif "AGENT_OPERATION_FAILED" in log_line:
            return "DHCP Agent Operation Failed"
        else:
            return "Unknown DHCP Spoofing"
    
    def extract_dhcp_details(self, log_line):
        """Trich xuat thong tin chi tiet tu DHCP log"""
        details = {}
        
        # Tim IP address
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', log_line)
        if ip_match:
            details['ip'] = ip_match.group(1)
        
        # Tim MAC address
        mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', log_line)
        if mac_match:
            details['mac'] = mac_match.group(0)
        
        # Tim VLAN
        vlan_match = re.search(r'vlan (\d+)', log_line)
        if vlan_match:
            details['vlan'] = vlan_match.group(1)
            
        return details
    
    def get_dhcp_snooping_stats(self, interface):
        """Lay thong ke DHCP snooping"""
        try:
            with ConnectHandler(**self.switch_config) as connection:
                connection.enable()
                output = connection.send_command(f"show ip dhcp snooping statistics interface {interface}")
                return output
        except Exception as e:
            self.logger.error(f"Loi lay thong ke DHCP snooping: {e}")
            return None
    
    def get_dhcp_binding_table(self):
        """Lay bang DHCP binding"""
        try:
            with ConnectHandler(**self.switch_config) as connection:
                connection.enable()
                output = connection.send_command("show ip dhcp snooping binding")
                return output
        except Exception as e:
            self.logger.error(f"Loi lay bang DHCP binding: {e}")
            return None
    
    def process_dhcp_spoofing_attack(self, interface, log_line):
        """Xu ly khi phat hien tan cong DHCP Spoofing"""
        current_time = datetime.now()
        state = self.interface_state[interface]

        # Cap nhat thoi gian hoat dong cuoi cung
        state["last_activity"] = current_time

        # Trich xuat thong tin chi tiet
        dhcp_details = self.extract_dhcp_details(log_line)

        # Lan dau phat hien tan cong tren interface nay
        if not state["is_attacking"]:
            state["first_detected"] = current_time
            state["is_attacking"] = True
            state["counter"] = 0
            state["last_log"] = log_line
            state["attack_type"] = self.detect_attack_type(log_line)
            state["violation_count"] = 1

            # Dem cac loai tan cong cu the
            if "BINDING_COLLISION" in log_line:
                state["binding_collisions"] += 1
            elif "FAKE_INTERFACE" in log_line:
                state["fake_offers"] += 1
            else:
                state["dhcp_packets_dropped"] += 1

            self.logger.warning(f"PHAT HIEN TAN CONG DHCP SPOOFING tren cong {interface}")
            self.logger.info(f"Loai tan cong: {state['attack_type']}")
            
            if dhcp_details:
                for key, value in dhcp_details.items():
                    self.logger.info(f"{key.upper()}: {value}")
            
            self.logger.info(f"Log: {log_line}")

            # Lay thong ke DHCP snooping
            stats = self.get_dhcp_snooping_stats(interface)
            if stats:
                self.logger.info(f"DHCP Snooping Stats:\n{stats}")

            # Phat am thanh canh bao
            threading.Thread(target=self.play_alert, daemon=True).start()

        else:
            # Dang trong trang thai bi tan cong
            state["violation_count"] += 1
            
            # Dem cac loai tan cong cu the
            if "BINDING_COLLISION" in log_line:
                state["binding_collisions"] += 1
            elif "FAKE_INTERFACE" in log_line:
                state["fake_offers"] += 1
            else:
                state["dhcp_packets_dropped"] += 1
            
            if log_line == state["last_log"]:
                state["counter"] += 1
                self.logger.info(
                    f"{interface} - So lan log lap lai: {state['counter']}/{self.stable_threshold} "
                    f"(Tong violations: {state['violation_count']}, "
                    f"Packets dropped: {state['dhcp_packets_dropped']}, "
                    f"Fake offers: {state['fake_offers']}, "
                    f"Binding collisions: {state['binding_collisions']})"
                )
            else:
                # Log moi xuat hien -> van dang bi tan cong
                state["counter"] = 0
                state["last_log"] = log_line
                
                self.logger.info(f"Log moi: {log_line}")
                
                # Hien thi thong tin chi tiet neu co
                if dhcp_details:
                    for key, value in dhcp_details.items():
                        self.logger.info(f"{key.upper()}: {value}")

        # Kiem tra xem co on dinh khong (co the da dung)
        if state["counter"] >= self.stable_threshold:
            attack_duration = current_time - state["first_detected"]
            self.logger.info(
                f"{interface} - Tan cong DHCP Spoofing co ve da dung. "
                f"Thoi gian tan cong: {attack_duration}, "
                f"Tong violations: {state['violation_count']}, "
                f"Packets dropped: {state['dhcp_packets_dropped']}, "
                f"Fake offers: {state['fake_offers']}, "
                f"Binding collisions: {state['binding_collisions']}"
            )
            
            # Hien thi bang DHCP binding hien tai
            binding_table = self.get_dhcp_binding_table()
            if binding_table:
                self.logger.info(f"DHCP Binding Table:\n{binding_table}")
            
            # Danh dau da dung tan cong
            state["is_attacking"] = False
            state["counter"] = 0
            state["first_detected"] = None
    
    def check_timeout_attacks(self):
        """Kiem tra cac interface co the da dung tan cong do timeout"""
        current_time = datetime.now()
        
        for interface, state in self.interface_state.items():
            if not state["is_attacking"] or state["last_activity"] is None:
                continue

            # Tinh thoi gian khong co hoat dong
            time_since_last_activity = current_time - state["last_activity"]

            # Neu khong co log moi trong timeout_threshold giay
            if time_since_last_activity.total_seconds() >= self.timeout_threshold:
                attack_duration = current_time - state["first_detected"]
                self.logger.info(
                    f"{interface} - Tan cong DHCP Spoofing da dung (phat hien timeout). "
                    f"Thoi gian tan cong: {attack_duration}, "
                    f"Tong violations: {state['violation_count']}, "
                    f"Packets dropped: {state['dhcp_packets_dropped']}, "
                    f"Fake offers: {state['fake_offers']}, "
                    f"Binding collisions: {state['binding_collisions']}, "
                    f"Lan cuoi hoat dong: {time_since_last_activity.total_seconds():.1f}s truoc"
                )
                
                # Danh dau da dung tan cong
                state["is_attacking"] = False
                state["first_detected"] = None
                state["counter"] = 0
    
    def get_interface_status(self, interface):
        """Lay trang thai interface tu switch"""
        try:
            with ConnectHandler(**self.switch_config) as connection:
                connection.enable()
                output = connection.send_command(f"show interface {interface} status")
                return output
        except Exception as e:
            self.logger.error(f"Loi lay trang thai interface: {e}")
            return None
    
    def generate_summary_report(self):
        """Tao bao cao tong ket"""
        active_attacks = [interface for interface, state in self.interface_state.items() 
                         if state["is_attacking"]]
        
        if not self.interface_state:
            self.logger.info("Khong phat hien tan cong DHCP Spoofing nao trong phien nay")
            return
            
        self.logger.info("BAO CAO TONG KET TAN CONG DHCP SPOOFING:")
        self.logger.info("=" * 60)

        total_violations = 0
        total_packets_dropped = 0
        total_fake_offers = 0
        total_binding_collisions = 0

        for interface, state in self.interface_state.items():
            if state["first_detected"] or state["is_attacking"]:
                status = "Dang tan cong" if state["is_attacking"] else "Da dung"
                total_violations += state["violation_count"]
                total_packets_dropped += state["dhcp_packets_dropped"]
                total_fake_offers += state["fake_offers"]
                total_binding_collisions += state["binding_collisions"]
                
                self.logger.info(
                    f"Cong: {interface}\n"
                    f"  Trang thai: {status}\n"
                    f"  Loai tan cong: {state['attack_type']}\n"
                    f"  Lan dau phat hien: {state['first_detected']}\n"
                    f"  Tong violations: {state['violation_count']}\n"
                    f"  Packets dropped: {state['dhcp_packets_dropped']}\n"
                    f"  Fake offers: {state['fake_offers']}\n"
                    f"  Binding collisions: {state['binding_collisions']}"
                )

        # Tong ket chung
        self.logger.info("TONG KET CHUNG:")
        self.logger.info(f"  Tong violations: {total_violations}")
        self.logger.info(f"  Tong packets dropped: {total_packets_dropped}")
        self.logger.info(f"  Tong fake offers: {total_fake_offers}")
        self.logger.info(f"  Tong binding collisions: {total_binding_collisions}")
        self.logger.info("=" * 60)
    
    def monitor_logs(self):
        """Ham chinh de monitor logs"""
        self.logger.info("Bat dau theo doi tan cong DHCP Spoofing...")
        self.logger.info(f"Dang theo doi file log: {self.log_file_path}")
        self.logger.info(f"Nguong on dinh: {self.stable_threshold}")
        self.logger.info(f"Nguong timeout: {self.timeout_threshold}s")

        last_timeout_check = datetime.now()

        try:
            for log_line in self.tail_log_file():
                if not self.running:
                    break

                # Tim kiem pattern DHCP spoofing attack
                for pattern in self.patterns:
                    match = re.search(pattern, log_line)
                    if match:
                        interface = match.group(1)
                        self.process_dhcp_spoofing_attack(interface, log_line)
                        break

                # Kiem tra timeout moi 10 giay
                current_time = datetime.now()
                if (current_time - last_timeout_check).total_seconds() >= 10:
                    self.check_timeout_attacks()
                    last_timeout_check = current_time

        except KeyboardInterrupt:
            self.logger.info("Da dung theo doi theo yeu cau nguoi dung")
        except Exception as e:
            self.logger.error(f"Loi trong qua trinh theo doi: {e}")
        finally:
            self.cleanup()
    
    def signal_handler(self, signum, frame):
        """Xu ly signal de dung chuong trinh gracefully"""
        self.logger.info(f"Nhan signal {signum}, dang tat chuong trinh...")
        self.running = False
    
    def cleanup(self):
        """Don dep tai nguyen"""
        self.logger.info("Dang don dep tai nguyen...")

        # Tao bao cao tong ket
        self.generate_summary_report()

        # Dung pygame mixer
        if self.sound_enabled:
            try:
                pygame.mixer.quit()
            except:
                pass

        self.logger.info("Da dung DHCP Spoofing Monitor")

def main():
    """Ham main"""
    monitor = DHCPSpoofingMonitor()
    monitor.monitor_logs()

if __name__ == "__main__":
    main()
