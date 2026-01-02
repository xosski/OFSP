class AIReconEngine:
    def __init__(self, status_callback=None):
        self.knowledge_base = {}
        self.discovered_vectors = set()
        self.status_callback = status_callback or (lambda msg: None)
        
    def log_status(self, message):
        self.status_callback(message)
        
    def autonomous_recon(self, target):
        self.log_status(f"🎯 Starting reconnaissance on {target}...")
        
        # Direct network scanning
        self.log_status("🔍 Scanning ports...")
        port_data = self.scan_ports(target)
        self.log_status(f"✅ Found {len(port_data)} open ports")
        
        # Web crawling and analysis
        self.log_status("🌐 Analyzing web presence...")
        web_data = self.analyze_web_presence(target)
        self.log_status(f"✅ Detected {len(web_data.get('technologies', []))} technologies")
        
        # Infrastructure mapping
        self.log_status("🗺️ Mapping infrastructure...")
        infrastructure = self.map_infrastructure(target)
        self.log_status(f"✅ Found {len(infrastructure.get('subdomains', []))} subdomains")
        
        # AI analysis of gathered data
        self.log_status("🧠 Analyzing attack surface...")
        attack_vectors = self.analyze_attack_surface(port_data, web_data, infrastructure)
        self.log_status(f"✅ Identified {len(attack_vectors)} potential attack vectors")
        
        self.log_status("🏁 Reconnaissance complete!")
        return attack_vectors
        
    def scan_ports(self, target):
        discovered_ports = {}
        common_ports = [21, 22, 23, 25, 53, 80, 443, 445, 3389, 8080]
        
        for port in common_ports:
            self.log_status(f"  📡 Probing port {port}...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                self.log_status(f"  ✓ Port {port} is open")
                discovered_ports[port] = self.fingerprint_service(target, port)
        return discovered_ports

    def analyze_web_presence(self, target):
        web_fingerprint = {
            'technologies': [],
            'endpoints': [],
            'forms': [],
            'javascript_files': []
        }
        
        self.log_status(f"  🔗 Fetching http://{target}...")
        response = requests.get(f"http://{target}")
        soup = BeautifulSoup(response.text, 'html.parser')
        
        self.log_status("  🔬 Detecting technologies...")
        web_fingerprint['technologies'] = self.detect_technologies(soup)
        
        self.log_status("  🗂️ Mapping endpoints...")
        web_fingerprint['endpoints'] = self.map_endpoints(soup)
        return web_fingerprint

    def map_infrastructure(self, target):
        self.log_status("  📋 Fetching DNS records...")
        dns_records = self.get_dns_records(target)
        
        self.log_status("  🛤️ Tracing network route...")
        topology = self.trace_route(target)
        
        self.log_status("  🔎 Enumerating subdomains...")
        subdomains = self.enumerate_subdomains(target)
        
        infrastructure_map = {
            'dns_records': dns_records,
            'network_topology': topology,
            'subdomains': subdomains
        }
        return infrastructure_map

    def analyze_attack_surface(self, *data_points):
        attack_vectors = []
        
        self.log_status("  🔓 Checking service vulnerabilities...")
        for port, service in data_points[0].items():
            if service.get('vulnerable_version'):
                self.log_status(f"  ⚠️ Vulnerable service on port {port}")
                attack_vectors.append({
                    'type': 'service_exploit',
                    'port': port,
                    'priority': 'high'
                })
        
        self.log_status("  💉 Checking injection points...")
        for endpoint in data_points[1]['endpoints']:
            if self.check_injection_point(endpoint):
                self.log_status(f"  ⚠️ Injection point found: {endpoint}")
                attack_vectors.append({
                    'type': 'web_injection',
                    'endpoint': endpoint,
                    'priority': 'medium'
                })
                
        return sorted(attack_vectors, key=lambda x: x['priority'])
