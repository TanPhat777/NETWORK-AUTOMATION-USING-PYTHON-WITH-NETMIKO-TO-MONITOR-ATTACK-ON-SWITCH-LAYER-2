import time
import re
from datetime import datetime
from netmiko import ConnectHandler
import pygame
import threading

log_file_path = "/var/log/syslog-remote/syslog.log"
pattern = r"%SPANTREE-2-BLOCK_BPDUGUARD.*port (\S+)"

switch = {
    "device_type": "cisco_ios",
    "host": "192.168.104.7",
    "username": "admin",
    "password": "cisco123",
    "secret": "cisco123",
}

interface_state = {}
poll_interval = 5
stable_threshold = 5

# Hàm phát âm thanh
def play_alert():
    pygame.mixer.init()
    pygame.mixer.music.load("/opt/alert.mp3")  # Đảm bảo file alert.mp3 nằm ở /opt/
    pygame.mixer.music.play()

def tail_log():
    with open(log_file_path, "r") as f:
        f.seek(0, 2)
        while True:
            dong = f.readline()
            if not dong:
                time.sleep(0.1)
                continue
            yield dong.strip()

def monitor_log():
    for dong_log in tail_log():
        match = re.search(pattern, dong_log)
        if match:
            interface = match.group(1)
            print(f"[{datetime.now()}] Phat hien tan cong BPDU tren {interface}: {dong_log}")
            
            # Phát âm thanh cảnh báo
            threading.Thread(target=play_alert, daemon=True).start()

            if interface not in interface_state:
                interface_state[interface] = {
                    "counter": 0,
                    "last_log": dong_log
                }
            else:
                if dong_log == interface_state[interface]["last_log"]:
                    interface_state[interface]["counter"] += 1
                    print(f"[{datetime.now()}] {interface} log khong thay doi ({interface_state[interface]['counter']}/{stable_threshold})")
                else:
                    interface_state[interface]["counter"] = 0
                    interface_state[interface]["last_log"] = dong_log
                    print(f"[{datetime.now()}] {interface} phat hien log moi -> dang con bi tan cong")

            if interface_state[interface]["counter"] >= stable_threshold:
                print(f"[{datetime.now()}] {interface} da on dinh -> co the hacker da ngung tan cong")
                interface_state[interface]["counter"] = 0

if __name__ == "__main__":
    monitor_log()




################################# Code Claud.ai ####################################33
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

class BPDUMonitor:
    def __init__(self, config_file=None):
        # Cấu hình logging
        self.setup_logging()
        
        # Cấu hình mặc định
        self.log_file_path = "/var/log/syslog-remote/syslog.log"
        self.pattern = r"%SPANTREE-2-BLOCK_BPDUGUARD.*port (\S+)"
        self.switch_config = {
            "device_type": "cisco_ios",
            "host": "192.168.104.7",
            "username": "admin",
            "password": "cisco123",
            "secret": "cisco123",
        }
        
        # Cấu hình monitor
        self.interface_state = defaultdict(lambda: {"counter": 0, "last_log": "", "first_detected": None})
        self.poll_interval = 5
        self.stable_threshold = 5
        self.alert_sound_path = "/opt/alert.mp3"
        
        # Flags điều khiển
        self.running = True
        self.sound_enabled = True
        
        # Khởi tạo pygame mixer
        self.init_sound_system()
        
        # Thiết lập signal handler để dừng gracefully
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def setup_logging(self):
        """Thiết lập logging system"""
        # Tạo thư mục logs nếu chưa tồn tại
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        # Cấu hình logging
        log_filename = log_dir / f"bpdu_monitor_{datetime.now().strftime('%Y%m%d')}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_filename, encoding='utf-8'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        self.logger = logging.getLogger(__name__)
        self.logger.info("BPDU Monitor started")
    
    def init_sound_system(self):
        """Khởi tạo hệ thống âm thanh"""
        try:
            pygame.mixer.init()
            # Kiểm tra file âm thanh có tồn tại không
            if not Path(self.alert_sound_path).exists():
                self.logger.warning(f"Alert sound file not found: {self.alert_sound_path}")
                self.sound_enabled = False
            else:
                self.logger.info("Sound system initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize sound system: {e}")
            self.sound_enabled = False
    
    def play_alert(self):
        """Phát âm thanh cảnh báo"""
        if not self.sound_enabled:
            return
            
        try:
            pygame.mixer.music.load(self.alert_sound_path)
            pygame.mixer.music.play()
            self.logger.debug("Alert sound played")
        except Exception as e:
            self.logger.error(f"Failed to play alert sound: {e}")
    
    def tail_log_file(self):
        """Đọc log file theo thời gian thực"""
        try:
            with open(self.log_file_path, "r", encoding='utf-8') as f:
                # Di chuyển đến cuối file
                f.seek(0, 2)
                
                while self.running:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    yield line.strip()
                    
        except FileNotFoundError:
            self.logger.error(f"Log file not found: {self.log_file_path}")
            return
        except Exception as e:
            self.logger.error(f"Error reading log file: {e}")
            return
    
    def process_bpdu_attack(self, interface, log_line):
        """Xử lý khi phát hiện tấn công BPDU"""
        current_time = datetime.now()
        
        # Lần đầu phát hiện interface này
        if interface not in self.interface_state:
            self.interface_state[interface]["first_detected"] = current_time
            self.interface_state[interface]["counter"] = 1
            self.interface_state[interface]["last_log"] = log_line
            
            self.logger.warning(f"BPDU Attack detected on {interface}")
            self.logger.info(f"Log: {log_line}")
            
            # Phát âm thanh cảnh báo trong thread riêng
            threading.Thread(target=self.play_alert, daemon=True).start()
            
        else:
            # Kiểm tra xem log có thay đổi không
            if log_line == self.interface_state[interface]["last_log"]:
                self.interface_state[interface]["counter"] += 1
                self.logger.info(
                    f"{interface} - Stable log count: "
                    f"{self.interface_state[interface]['counter']}/{self.stable_threshold}"
                )
            else:
                # Log mới xuất hiện -> vẫn đang bị tấn công
                self.interface_state[interface]["counter"] = 0
                self.interface_state[interface]["last_log"] = log_line
                self.logger.warning(f"{interface} - New attack pattern detected")
                
                # Phát âm thanh cảnh báo
                threading.Thread(target=self.play_alert, daemon=True).start()
        
        # Kiểm tra xem có ổn định không
        if self.interface_state[interface]["counter"] >= self.stable_threshold:
            attack_duration = current_time - self.interface_state[interface]["first_detected"]
            self.logger.info(
                f"{interface} - Attack appears to have stopped. "
                f"Duration: {attack_duration}"
            )
            
            # Reset counter nhưng giữ lại thông tin để theo dõi
            self.interface_state[interface]["counter"] = 0
    
    def get_interface_status(self, interface):
        """Lấy trạng thái interface từ switch (tùy chọn)"""
        try:
            with ConnectHandler(**self.switch_config) as connection:
                connection.enable()
                output = connection.send_command(f"show interface {interface} status")
                return output
        except Exception as e:
            self.logger.error(f"Failed to get interface status: {e}")
            return None
    
    def generate_summary_report(self):
        """Tạo báo cáo tổng kết"""
        if not self.interface_state:
            self.logger.info("No BPDU attacks detected during this session")
            return
        
        self.logger.info("BPDU Attack Summary Report:")
        self.logger.info("=" * 50)
        
        for interface, state in self.interface_state.items():
            if state["first_detected"]:
                self.logger.info(
                    f"Interface: {interface}\n"
                    f"  First Detected: {state['first_detected']}\n"
                    f"  Current Status: {'Stable' if state['counter'] >= self.stable_threshold else 'Active'}\n"
                    f"  Stability Counter: {state['counter']}"
                )
        
        self.logger.info("=" * 50)
    
    def monitor_logs(self):
        """Hàm chính để monitor logs"""
        self.logger.info("Starting BPDU attack monitoring...")
        self.logger.info(f"Monitoring log file: {self.log_file_path}")
        self.logger.info(f"Stable threshold: {self.stable_threshold}")
        
        try:
            for log_line in self.tail_log_file():
                if not self.running:
                    break
                
                # Tìm kiếm pattern BPDU attack
                match = re.search(self.pattern, log_line)
                if match:
                    interface = match.group(1)
                    self.process_bpdu_attack(interface, log_line)
                    
        except KeyboardInterrupt:
            self.logger.info("Monitoring stopped by user")
        except Exception as e:
            self.logger.error(f"Error during monitoring: {e}")
        finally:
            self.cleanup()
    
    def signal_handler(self, signum, frame):
        """Xử lý signal để dừng chương trình gracefully"""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
    
    def cleanup(self):
        """Dọn dẹp tài nguyên"""
        self.logger.info("Cleaning up resources...")
        
        # Tạo báo cáo tổng kết
        self.generate_summary_report()
        
        # Dừng pygame mixer
        if self.sound_enabled:
            try:
                pygame.mixer.quit()
            except:
                pass
        
        self.logger.info("BPDU Monitor stopped")

def main():
    """Hàm main"""
    monitor = BPDUMonitor()
    monitor.monitor_logs()

if __name__ == "__main__":
    main()






























