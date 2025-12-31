#!/usr/bin/env python3
"""
IP Geolocation Lookup Tool
Advanced utility for IP address information retrieval with multiple APIs
"""

import requests
import json
import re
import sys
import time
import logging
import socket
from dataclasses import dataclass
from typing import Optional, Dict, Any, Tuple
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
import argparse


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ip_lookup.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class IPInfo:
    
    ip: str
    country: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    asn: Optional[str] = None
    timezone: Optional[str] = None
    zip_code: Optional[str] = None
    country_code: Optional[str] = None
    reverse_dns: Optional[str] = None
    is_private: bool = False
    is_reserved: bool = False
    api_source: Optional[str] = None
    timestamp: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
  
        return {
            'ip': self.ip,
            'country': self.country,
            'region': self.region,
            'city': self.city,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'isp': self.isp,
            'organization': self.org,
            'asn': self.asn,
            'timezone': self.timezone,
            'zip_code': self.zip_code,
            'country_code': self.country_code,
            'reverse_dns': self.reverse_dns,
            'is_private': self.is_private,
            'is_reserved': self.is_reserved,
            'api_source': self.api_source,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }
    
    def __str__(self) -> str:
        lines = [
            "╔══════════════════════════════════════════════════════╗",
            f"║                IP INFORMATION REPORT                 ║",
            f"║                By migu                               ║",
            "╠══════════════════════════════════════════════════════╣",
            f"║  IP Address:        {self.ip:<35} ║",
        ]
        
        if self.is_private:
            lines.append("║  Type:              PRIVATE IP ADDRESS                ║")
        elif self.is_reserved:
            lines.append("║  Type:              RESERVED IP ADDRESS              ║")
        
        if self.country:
            lines.append(f"║  Country:           {self.country:<35} ║")
        if self.city:
            lines.append(f"║  City:              {self.city:<35} ║")
        if self.region:
            lines.append(f"║  Region:            {self.region:<35} ║")
        if self.latitude and self.longitude:
            lines.append(f"║  Coordinates:       {self.latitude:.6f}, {self.longitude:.6f}        ║")
        if self.isp:
            lines.append(f"║  ISP:               {self.isp:<35} ║")
        if self.org:
            lines.append(f"║  Organization:      {self.org:<35} ║")
        if self.asn:
            lines.append(f"║  ASN:               {self.asn:<35} ║")
        if self.reverse_dns:
            lines.append(f"║  Reverse DNS:       {self.reverse_dns:<35} ║")
        if self.timezone:
            lines.append(f"║  Timezone:          {self.timezone:<35} ║")
        if self.api_source:
            lines.append(f"║  Data Source:       {self.api_source:<35} ║")
        if self.timestamp:
            lines.append(f"║  Retrieved:         {self.timestamp.strftime('%Y-%m-%d %H:%M:%S'):<35} ║")
        
        lines.append("╚══════════════════════════════════════════════════════╝")
        return "\n".join(lines)


class IPValidator:

    
    PRIVATE_RANGES = [
        ('10.0.0.0', '10.255.255.255'),
        ('172.16.0.0', '172.31.255.255'),
        ('192.168.0.0', '192.168.255.255'),
        ('127.0.0.0', '127.255.255.255'),
        ('169.254.0.0', '169.254.255.255'),  # Link-local
    ]
    
    RESERVED_RANGES = [
        ('0.0.0.0', '0.255.255.255'),
        ('100.64.0.0', '100.127.255.255'),
        ('192.0.0.0', '192.0.0.255'),
        ('224.0.0.0', '239.255.255.255'),  # Multicast
        ('240.0.0.0', '255.255.255.254'),
        ('255.255.255.255', '255.255.255.255'),  # Broadcast
    ]
    
    @staticmethod
    def ip_to_int(ip: str) -> int:

        octets = ip.split('.')
        return (int(octets[0]) << 24) + (int(octets[1]) << 16) + (int(octets[2]) << 8) + int(octets[3])
    
    @classmethod
    def is_valid_ipv4(cls, ip: str) -> bool:
        pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
        match = re.match(pattern, ip)
        
        if not match:
            return False
        
        for octet in match.groups():
            if not 0 <= int(octet) <= 255:
                return False
        return True
    
    @classmethod
    def get_ip_type(cls, ip: str) -> Tuple[bool, bool]:
        if not cls.is_valid_ipv4(ip):
            return False, False
        
        ip_int = cls.ip_to_int(ip)
        
        # Проверка приватных диапазонов
        for start, end in cls.PRIVATE_RANGES:
            if cls.ip_to_int(start) <= ip_int <= cls.ip_to_int(end):
                return True, False
        
        # Проверка зарезервированных диапазонов
        for start, end in cls.RESERVED_RANGES:
            if cls.ip_to_int(start) <= ip_int <= cls.ip_to_int(end):
                return False, True
        
        return False, False
    
    @staticmethod
    def get_own_ip() -> str:
        
        try:
            response = requests.get('https://api.ipify.org?format=json', timeout=5)
            response.raise_for_status()
            return response.json()['ip']
        except Exception as e:
            logger.warning(f"Could not retrieve own IP: {e}")
            return "127.0.0.1"


class GeolocationAPI:
    
    
    # Список API с их конфигурацией
    APIS = {
        'ip-api': {
            'url': 'http://ip-api.com/json/{ip}',
            'fields': 'status,message,country,countryCode,region,regionName,'
                     'city,zip,lat,lon,timezone,isp,org,as,reverse,query',
            'params': {'fields': None},
            'mapping': {
                'country': 'country',
                'region': 'regionName',
                'city': 'city',
                'latitude': 'lat',
                'longitude': 'lon',
                'isp': 'isp',
                'org': 'org',
                'asn': 'as',
                'timezone': 'timezone',
                'zip_code': 'zip',
                'country_code': 'countryCode',
                'reverse_dns': 'reverse'
            }
        },
        'ipapi': {
            'url': 'https://ipapi.co/{ip}/json/',
            'mapping': {
                'country': 'country_name',
                'region': 'region',
                'city': 'city',
                'latitude': 'latitude',
                'longitude': 'longitude',
                'isp': 'org',
                'org': 'org',
                'asn': 'asn',
                'timezone': 'timezone',
                'zip_code': 'postal',
                'country_code': 'country_code',
            }
        },
        'ipwhois': {
            'url': 'http://free.ipwhois.io/json/{ip}',
            'mapping': {
                'country': 'country',
                'region': 'region',
                'city': 'city',
                'latitude': 'latitude',
                'longitude': 'longitude',
                'isp': 'isp',
                'org': 'org',
                'asn': 'asn',
                'timezone': 'timezone',
            }
        }
    }
    
    def __init__(self, timeout: int = 10, retries: int = 2):
        self.timeout = timeout
        self.retries = retries
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (IP-Lookup-Tool/1.0)',
            'Accept': 'application/json',
            'Accept-Language': 'en-US,en;q=0.9',
        })
    
    def get_info_from_api(self, ip: str, api_name: str) -> Optional[Dict[str, Any]]:
     
        api_config = self.APIS.get(api_name)
        if not api_config:
            logger.error(f"Unknown API: {api_name}")
            return None
        
        url = api_config['url'].format(ip=ip)
        params = {}
        
        if 'params' in api_config and api_config['params']:
            for key, value in api_config['params'].items():
                if value:
                    params[key] = value
                elif key == 'fields' and 'fields' in api_config:
                    params[key] = api_config['fields']
        
        for attempt in range(self.retries + 1):
            try:
                logger.debug(f"Requesting {api_name} for IP {ip} (attempt {attempt + 1})")
                
                response = self.session.get(
                    url,
                    params=params if params else None,
                    timeout=self.timeout
                )
                response.raise_for_status()
                
                data = response.json()
                
                # Проверка статуса для ip-api
                if api_name == 'ip-api' and data.get('status') == 'fail':
                    logger.warning(f"{api_name} API failed: {data.get('message')}")
                    return None
                
                return {
                    'data': data,
                    'mapping': api_config['mapping'],
                    'source': api_name
                }
                
            except requests.exceptions.Timeout:
                logger.warning(f"{api_name} timeout for IP {ip}")
                if attempt < self.retries:
                    time.sleep(1 * (attempt + 1))
                continue
            except requests.exceptions.HTTPError as e:
                logger.error(f"{api_name} HTTP error for IP {ip}: {e}")
                return None
            except requests.exceptions.RequestException as e:
                logger.error(f"{api_name} request error for IP {ip}: {e}")
                if attempt < self.retries:
                    time.sleep(1 * (attempt + 1))
                continue
            except json.JSONDecodeError as e:
                logger.error(f"{api_name} JSON decode error for IP {ip}: {e}")
                return None
        
        return None
    
    def get_info(self, ip: str, fallback: bool = True) -> Optional[IPInfo]:
        
        logger.info(f"Looking up information for IP: {ip}")
        
        # Проверяем валидность IP
        if not IPValidator.is_valid_ipv4(ip):
            logger.error(f"Invalid IP address: {ip}")
            return None
        
        # Определяем тип IP
        is_private, is_reserved = IPValidator.get_ip_type(ip)
        
        # Создаем объект IPInfo с базовой информацией
        ip_info = IPInfo(
            ip=ip,
            is_private=is_private,
            is_reserved=is_reserved,
            timestamp=datetime.now()
        )
        
        # Для приватных IP возвращаем базовую информацию
        if is_private or is_reserved:
            logger.info(f"IP {ip} is {'private' if is_private else 'reserved'}")
            return ip_info
        
        # Получаем reverse DNS
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            ip_info.reverse_dns = hostname
        except (socket.herror, socket.gaierror):
            pass
        
        # Пробуем получить информацию из разных API
        if fallback:
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = {
                    executor.submit(self.get_info_from_api, ip, api_name): api_name
                    for api_name in self.APIS.keys()
                }
                
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        self._map_data_to_ipinfo(ip_info, result)
                        if self._has_sufficient_data(ip_info):
                            logger.info(f"Successfully retrieved data from {result['source']}")
                            return ip_info
        
        # Если fallback=False или многопоточный запрос не дал результатов
        for api_name in self.APIS.keys():
            result = self.get_info_from_api(ip, api_name)
            if result:
                self._map_data_to_ipinfo(ip_info, result)
                logger.info(f"Successfully retrieved data from {result['source']}")
                return ip_info
        
        logger.warning(f"Could not retrieve information for IP {ip} from any API")
        return ip_info
    
    def _map_data_to_ipinfo(self, ip_info: IPInfo, api_result: Dict[str, Any]) -> None:
        """Маппинг данных из API в объект IPInfo"""
        data = api_result['data']
        mapping = api_result['mapping']
        source = api_result['source']
        
        ip_info.api_source = source
        
        for attr, key in mapping.items():
            if key in data and data[key]:
                value = data[key]
                # Преобразование числовых значений
                if attr in ['latitude', 'longitude']:
                    try:
                        value = float(value)
                    except (ValueError, TypeError):
                        continue
                setattr(ip_info, attr, value)
    
    def _has_sufficient_data(self, ip_info: IPInfo) -> bool:
        
        return any([
            ip_info.country,
            ip_info.city,
            ip_info.isp,
            ip_info.latitude
        ])


class IPLookupTool:
    
    
    def __init__(self, output_format: str = 'pretty', save_to_file: bool = False):
        self.geo_api = GeolocationAPI()
        self.output_format = output_format
        self.save_to_file = save_to_file
    
    @lru_cache(maxsize=100)
    def lookup(self, ip: str) -> Optional[IPInfo]:
        
        return self.geo_api.get_info(ip)
    
    def lookup_multiple(self, ips: list) -> Dict[str, Optional[IPInfo]]:
    
        results = {}
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(self.lookup, ip): ip for ip in ips}
            
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    results[ip] = future.result()
                except Exception as e:
                    logger.error(f"Error looking up IP {ip}: {e}")
                    results[ip] = None
        
        return results
    
    def display_result(self, ip_info: IPInfo) -> None:
        
        if not ip_info:
            print("No information available for this IP address.")
            return
        
        if self.output_format == 'json':
            print(json.dumps(ip_info.to_dict(), indent=2, ensure_ascii=False))
        elif self.output_format == 'csv':
            data = ip_info.to_dict()
            print(','.join(data.keys()))
            print(','.join([str(v) if v else '' for v in data.values()]))
        else:  # pretty
            print(ip_info)
        
        # Сохранение в файл
        if self.save_to_file:
            self.save_result(ip_info)
    
    def save_result(self, ip_info: IPInfo) -> None:
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"ip_report_{ip_info.ip}_{timestamp}.json"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(ip_info.to_dict(), f, indent=2, ensure_ascii=False)
            logger.info(f"Report saved to {filename}")
        except IOError as e:
            logger.error(f"Could not save report: {e}")
    
    def interactive_mode(self) -> None:
        
        print("\n" + "="*60)
        print("IP GEOLOCATION LOOKUP TOOL By migu")
        print("="*60)
        print("Commands:")
        print("  me       - Look up your own IP")
        print("  batch    - Enter multiple IPs for batch lookup")
        print("  file     - Read IPs from file (one per line)")
        print("  format   - Change output format (pretty/json/csv)")
        print("  save     - Toggle auto-save to file")
        print("  clear    - Clear screen")
        print("  help     - Show this help")
        print("  exit     - Exit program")
        print("="*60)
        
        while True:
            try:
                command = input("\n>>> ").strip()
                
                if not command:
                    continue
                
                if command.lower() == 'exit':
                    print("Goodbye!")
                    break
                elif command.lower() == 'help':
                    self.interactive_mode()
                    continue
                elif command.lower() == 'clear':
                    print("\n" * 100)
                    continue
                elif command.lower() == 'format':
                    self.output_format = input("Enter format (pretty/json/csv): ").strip().lower()
                    print(f"Output format set to: {self.output_format}")
                    continue
                elif command.lower() == 'save':
                    self.save_to_file = not self.save_to_file
                    status = "ENABLED" if self.save_to_file else "DISABLED"
                    print(f"Auto-save to file: {status}")
                    continue
                elif command.lower() == 'me':
                    ip = IPValidator.get_own_ip()
                    print(f"Your IP address: {ip}")
                    command = ip
                elif command.lower() == 'batch':
                    ips = []
                    print("Enter IP addresses (one per line, empty line to finish):")
                    while True:
                        line = input().strip()
                        if not line:
                            break
                        if IPValidator.is_valid_ipv4(line):
                            ips.append(line)
                        else:
                            print(f"Invalid IP: {line}")
                    
                    if ips:
                        print(f"\nLooking up {len(ips)} IP addresses...")
                        results = self.lookup_multiple(ips)
                        
                        for ip, info in results.items():
                            print(f"\nResults for {ip}:")
                            print("-" * 40)
                            if info:
                                self.display_result(info)
                            else:
                                print("No information available")
                    continue
                elif command.lower() == 'file':
                    filename = input("Enter filename: ").strip()
                    try:
                        with open(filename, 'r') as f:
                            ips = [line.strip() for line in f if line.strip()]
                        
                        # Валидация IP
                        valid_ips = []
                        for ip in ips:
                            if IPValidator.is_valid_ipv4(ip):
                                valid_ips.append(ip)
                            else:
                                print(f"Invalid IP in file: {ip}")
                        
                        if valid_ips:
                            print(f"\nLooking up {len(valid_ips)} IP addresses...")
                            results = self.lookup_multiple(valid_ips)
                            
                            for ip, info in results.items():
                                print(f"\nResults for {ip}:")
                                print("-" * 40)
                                if info:
                                    self.display_result(info)
                                else:
                                    print("No information available")
                    except FileNotFoundError:
                        print(f"File not found: {filename}")
                    except IOError as e:
                        print(f"Error reading file: {e}")
                    continue
                
                # Обычный поиск IP
                if IPValidator.is_valid_ipv4(command):
                    print(f"\nLooking up information for: {command}")
                    result = self.lookup(command)
                    self.display_result(result)
                else:
                    print(f"Invalid IP address: {command}")
                    print("Please enter a valid IPv4 address or command")
                    
            except KeyboardInterrupt:
                print("\n\nInterrupted by user. Use 'exit' to quit.")
            except EOFError:
                print("\n\nGoodbye!")
                break
            except Exception as e:
                logger.error(f"Unexpected error: {e}")
                print(f"Error: {e}")


def main():
    """Точка входа программы"""
    parser = argparse.ArgumentParser(
        description='Advanced IP Geolocation Lookup Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 8.8.8.8                 # Look up specific IP
  %(prog)s -i                       # Interactive mode
  %(prog)s 8.8.8.8 1.1.1.1         # Look up multiple IPs
  %(prog)s -f ips.txt              # Read IPs from file
  %(prog)s -o json 8.8.8.8         # Output in JSON format
  %(prog)s --me                     # Look up your own IP
        """
    )
    
    parser.add_argument(
        'ips',
        nargs='*',
        help='IP addresses to look up'
    )
    
    parser.add_argument(
        '-i', '--interactive',
        action='store_true',
        help='Run in interactive mode'
    )
    
    parser.add_argument(
        '-f', '--file',
        help='Read IP addresses from file (one per line)'
    )
    
    parser.add_argument(
        '-o', '--output',
        choices=['pretty', 'json', 'csv'],
        default='pretty',
        help='Output format (default: pretty)'
    )
    
    parser.add_argument(
        '-s', '--save',
        action='store_true',
        help='Save results to files'
    )
    
    parser.add_argument(
        '--me',
        action='store_true',
        help='Look up your own IP address'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=10,
        help='Request timeout in seconds (default: 10)'
    )
    
    args = parser.parse_args()
    
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    
    tool = IPLookupTool(
        output_format=args.output,
        save_to_file=args.save
    )
    
    
    ips_to_lookup = []
    
    if args.me:
        own_ip = IPValidator.get_own_ip()
        print(f"Your IP address: {own_ip}")
        ips_to_lookup.append(own_ip)
    
    if args.file:
        try:
            with open(args.file, 'r') as f:
                file_ips = [line.strip() for line in f if line.strip()]
                valid_ips = [ip for ip in file_ips if IPValidator.is_valid_ipv4(ip)]
                ips_to_lookup.extend(valid_ips)
                invalid_count = len(file_ips) - len(valid_ips)
                if invalid_count:
                    logger.warning(f"Skipped {invalid_count} invalid IPs from file")
        except FileNotFoundError:
            print(f"Error: File '{args.file}' not found")
            sys.exit(1)
        except IOError as e:
            print(f"Error reading file: {e}")
            sys.exit(1)
    
    ips_to_lookup.extend(args.ips)
    
    
    if args.interactive or (not ips_to_lookup and not args.me):
        tool.interactive_mode()
    elif ips_to_lookup:
        if len(ips_to_lookup) == 1:
            result = tool.lookup(ips_to_lookup[0])
            tool.display_result(result)
        else:
            print(f"Looking up {len(ips_to_lookup)} IP addresses...\n")
            results = tool.lookup_multiple(ips_to_lookup)
            
            for ip, info in results.items():
                print(f"\nResults for {ip}:")
                print("-" * 40)
                if info:
                    tool.display_result(info)
                else:
                    print("No information available")
                print()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nProgram interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)