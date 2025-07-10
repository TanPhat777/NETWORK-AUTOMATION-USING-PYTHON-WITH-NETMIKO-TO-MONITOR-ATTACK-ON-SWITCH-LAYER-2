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

class MACFloodingMonitor:
    def __init__(self):
        # Cấu hình logging
        self.setup_logging()

        # Cau hinh mac dinh
        self.log_file_path = "/var/log/syslog-remote/syslog.log"
        # Pattern cho MAC flooding - chỉ lấy pattern chính từ log thực tế
        self.pattern = r"XPM-4-ERR_DISABLE.*psecure-violation.*detected on (\S+)"
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
            "mac_count": 0,
            "violation_count": 0
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

        log_filename = log_dir / f"mac_flooding_monitor_{datetime.now().strftime('%Y%m%d')}.log"

        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_filename, encoding='utf-8'),
                logging.StreamHandler(sys.stdout)
            ]
        )

        self.logger = logging.getLogger(__name__)
        self.logger.info("Bat dau theo doi tan cong MAC Flooding")
    
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
    
    def get_mac_table_count(self, interface):
        """Lay so luong MAC address tren interface"""
        try:
            with ConnectHandler(**self.switch_config) as connection:
                connection.enable()
                output = connection.send_command(f"show mac address-table interface {interface}")
                # Đếm số dòng MAC address (bỏ qua header)
                mac_lines = [line for line in output.split('\n') 
                           if re.match(r'^\s*\d+\s+[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}', line)]
                return len(mac_lines)
        except Exception as e:
            self.logger.error(f"Loi lay so luong MAC: {e}")
            return 0
    
    def process_mac_flooding_attack(self, interface, log_line):
        """Xu ly khi phat hien tan cong MAC Flooding"""
        current_time = datetime.now()
        state = self.interface_state[interface]

        # Cap nhat thoi gian hoat dong cuoi cung
        state["last_activity"] = current_time

        # Lan dau phat hien tan cong tren interface nay
        if not state["is_attacking"]:
            state["first_detected"] = current_time
            state["is_attacking"] = True
            state["counter"] = 0
            state["last_log"] = log_line
            state["violation_count"] = 1

            # Lay so luong MAC hien tai
            state["mac_count"] = self.get_mac_table_count(interface)

            self.logger.warning(f"PHAT HIEN TAN CONG MAC FLOODING tren cong {interface}")
            self.logger.info(f"So luong MAC hien tai: {state['mac_count']}")
            self.logger.info(f"Log: {log_line}")

            # Phat am thanh canh bao
            threading.Thread(target=self.play_alert, daemon=True).start()

        else:
            # Dang trong trang thai bi tan cong
            state["violation_count"] += 1
            
            if log_line == state["last_log"]:
                state["counter"] += 1
                self.logger.info(
                    f"{interface} - So lan log lap lai: {state['counter']}/{self.stable_threshold} "
                    f"(Tong violations: {state['violation_count']})"
                )
            else:
                # Log moi xuat hien -> van dang bi tan cong
                state["counter"] = 0
                state["last_log"] = log_line
                # Cap nhat so luong MAC
                state["mac_count"] = self.get_mac_table_count(interface)
                self.logger.info(f"Log moi: {log_line}")
                self.logger.info(f"So luong MAC cap nhat: {state['mac_count']}")

        # Kiem tra xem co on dinh khong (co the da dung)
        if state["counter"] >= self.stable_threshold:
            attack_duration = current_time - state["first_detected"]
            self.logger.info(
                f"{interface} - Tan cong MAC Flooding co ve da dung. "
                f"Thoi gian tan cong: {attack_duration}, "
                f"Tong violations: {state['violation_count']}, "
                f"So MAC cuoi cung: {state['mac_count']}"
            )
            
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
                    f"{interface} - Tan cong MAC Flooding da dung (phat hien timeout). "
                    f"Thoi gian tan cong: {attack_duration}, "
                    f"Tong violations: {state['violation_count']}, "
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
            self.logger.info("Khong phat hien tan cong MAC Flooding nao trong phien nay")
            return
            
        self.logger.info("BAO CAO TONG KET TAN CONG MAC FLOODING:")
        self.logger.info("=" * 50)

        for interface, state in self.interface_state.items():
            if state["first_detected"] or state["is_attacking"]:
                status = "Dang tan cong" if state["is_attacking"] else "Da dung"
                self.logger.info(
                    f"Cong: {interface}\n"
                    f"  Trang thai: {status}\n"
                    f"  Lan dau phat hien: {state['first_detected']}\n"
                    f"  Tong violations: {state['violation_count']}\n"
                    f"  So MAC cuoi cung: {state['mac_count']}"
                )

        self.logger.info("=" * 50)
    
    def monitor_logs(self):
        """Ham chinh de monitor logs"""
        self.logger.info("Bat dau theo doi tan cong MAC Flooding...")
        self.logger.info(f"Dang theo doi file log: {self.log_file_path}")
        self.logger.info(f"Nguong on dinh: {self.stable_threshold}")
        self.logger.info(f"Nguong timeout: {self.timeout_threshold}s")

        last_timeout_check = datetime.now()

        try:
            for log_line in self.tail_log_file():
                if not self.running:
                    break

                # Tim kiem pattern MAC flooding attack
                match = re.search(self.pattern, log_line)
                if match:
                    interface = match.group(1)
                    self.process_mac_flooding_attack(interface, log_line)

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

        self.logger.info("Da dung MAC Flooding Monitor")

def main():
    """Ham main"""
    monitor = MACFloodingMonitor()
    monitor.monitor_logs()

if __name__ == "__main__":
    main()
