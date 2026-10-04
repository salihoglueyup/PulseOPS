import re
from pathlib import Path
from typing import Optional
from pulseops.models.proxy import ProxyRoute
from pulseops.models.ports import ListeningPort

class NginxParser:
    """Parses Nginx site configs to correlate public domains with internal backend ports."""

    def _extract_blocks(self, text: str, block_name: str = "server") -> list[str]:
        """Extracts top-level block_name { ... } content using brace matching."""
        blocks: list[str] = []
        pos = 0
        pattern = re.compile(rf'\b{block_name}\b[^{{]*\{{')
        
        while True:
            match = pattern.search(text, pos)
            if not match:
                break
            
            brace_start = match.end() - 1
            brace_count = 1
            idx = brace_start + 1
            
            while idx < len(text) and brace_count > 0:
                char = text[idx]
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                idx += 1
                
            if brace_count == 0:
                blocks.append(text[match.start():idx])
                pos = idx
            else:
                break
                
        return blocks

    def parse_config_text(self, content: str) -> list[ProxyRoute]:
        """Parses raw Nginx configuration text into ProxyRoute instances."""
        routes: list[ProxyRoute] = []
        
        # Extract upstream definitions (e.g. upstream backend { server 127.0.0.1:3000; })
        upstream_blocks = self._extract_blocks(content, "upstream")
        upstreams: dict[str, int] = {}
        for ub in upstream_blocks:
            m_name = re.search(r'upstream\s+([^\s{]+)', ub)
            if m_name:
                u_name = m_name.group(1).strip()
                m_srv = re.search(r'server\s+[^:;\s]+:(\d+)', ub)
                if m_srv:
                    try:
                        upstreams[u_name] = int(m_srv.group(1))
                    except ValueError:
                        pass

        server_blocks = self._extract_blocks(content, "server")
        
        server_name_re = re.compile(r'server_name\s+([^;]+);')
        listen_re = re.compile(r'listen\s+([^;]+);')
        ssl_cert_re = re.compile(r'ssl_certificate\s+([^;]+);')
        proxy_pass_re = re.compile(r'proxy_pass\s+([^;]+);')
        port_re = re.compile(r':(\d+)')
        
        for block in server_blocks:
            # Check for proxy_pass
            proxy_match = proxy_pass_re.search(block)
            if not proxy_match:
                # Not a reverse proxy block (e.g. static file server or pure 301 redirect)
                continue
            
            target_url = proxy_match.group(1).strip()
            target_port: Optional[int] = None
            port_match = port_re.search(target_url)
            if port_match:
                try:
                    target_port = int(port_match.group(1))
                except ValueError:
                    target_port = None
            else:
                # Check if target_url references an upstream
                clean_target = target_url.replace("http://", "").replace("https://", "").strip("/")
                if clean_target in upstreams:
                    target_port = upstreams[clean_target]
                    target_url = f"{target_url} (:{target_port})"
                    
            # Extract server_names
            domains: list[str] = []
            sname_match = server_name_re.search(block)
            if sname_match:
                raw_names = sname_match.group(1).strip().split()
                # filter out '_' or default keywords
                domains = [d for d in raw_names if d not in ("_", "default_server")]
            
            if not domains:
                domains = ["localhost"]
                
            # Extract listen port and SSL
            listen_port = 80
            is_ssl = False
            
            if ssl_cert_re.search(block):
                is_ssl = True
                listen_port = 443
                
            for lmatch in listen_re.finditer(block):
                lval = lmatch.group(1).lower()
                if "ssl" in lval or "443" in lval:
                    is_ssl = True
                    listen_port = 443
                elif "80" in lval and not is_ssl:
                    listen_port = 80
                else:
                    # check if explicit custom port is specified
                    custom_port_match = port_re.search(lval)
                    if custom_port_match:
                        try:
                            listen_port = int(custom_port_match.group(1))
                        except ValueError:
                            pass
                            
            # Use the primary domain
            primary_domain = domains[0]
            routes.append(ProxyRoute(
                domain=primary_domain,
                listen_port=listen_port,
                is_ssl=is_ssl,
                target_url=target_url,
                target_port=target_port,
                status="UP"
            ))
            
        return routes

    def enrich_routes_with_ports(
        self, routes: list[ProxyRoute], listening_ports: list[ListeningPort]
    ) -> list[ProxyRoute]:
        """Correlates target_port in each ProxyRoute with the actual process from listening_ports."""
        port_to_proc: dict[int, str] = {}
        for lp in listening_ports:
            if lp.process_name:
                desc = f"{lp.process_name} [PID {lp.pid}]" if lp.pid else lp.process_name
                port_to_proc[lp.port] = desc
                
        enriched: list[ProxyRoute] = []
        for r in routes:
            r_copy = r.model_copy()
            if r.target_port and r.target_port in port_to_proc:
                r_copy.target_process = port_to_proc[r.target_port]
            enriched.append(r_copy)
            
        return enriched

    def collect_from_filesystem(self, nginx_dir: str = "/etc/nginx") -> list[ProxyRoute]:
        """Scans sites-enabled/ and conf.d/ on local filesystem."""
        path = Path(nginx_dir)
        if not path.exists():
            return []
        
        all_routes: list[ProxyRoute] = []
        subdirs = [path / "sites-enabled", path / "conf.d"]
        for sdir in subdirs:
            if sdir.exists():
                for conf_file in sdir.glob("*"):
                    if conf_file.is_file():
                        try:
                            text = conf_file.read_text(encoding="utf-8", errors="ignore")
                            all_routes.extend(self.parse_config_text(text))
                        except Exception:
                            continue
        return all_routes
