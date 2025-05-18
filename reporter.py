#!/usr/bin/env python3
"""
RapidRecon - Reporter Module

This module provides functionality for generating scan reports in CLI and HTML formats.
"""

import os
import time
from datetime import datetime
import json
import socket

class BaseReporter:
    """Base class for report generation."""
    
    def __init__(self, scan_results, subnet, scan_duration):
        """
        Initialize the reporter.
        
        Args:
            scan_results (dict): Results from the network scan
            subnet (str): Scanned subnet
            scan_duration (float): Duration of the scan in seconds
        """
        self.scan_results = scan_results
        self.subnet = subnet
        self.scan_duration = scan_duration
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Calculate scan statistics
        self.stats = self._calculate_statistics()
    
    def _calculate_statistics(self):
        """
        Calculate statistics from scan results.
        
        Returns:
            dict: Various statistics about the scan
        """
        stats = {
            "total_hosts": len(self.scan_results),
            "total_ports": 0,
            "risk_levels": {
                "High": 0,
                "Medium": 0,
                "Low": 0,
                "Unknown": 0
            }
        }
        
        # Calculate port statistics
        for host, data in self.scan_results.items():
            for port_info in data.get("ports", []):
                stats["total_ports"] += 1
                
                # Count risk levels
                risk = port_info.get("risk", "Unknown")
                if risk in stats["risk_levels"]:
                    stats["risk_levels"][risk] += 1
        
        return stats
    
    def generate_report(self):
        """Generate the report (to be implemented by subclasses)."""
        raise NotImplementedError("Subclasses must implement this method")


class CLIReporter(BaseReporter):
    """CLI report generator."""
    
    def generate_report(self):
        """Generate and display CLI report."""
        # Print summary
        print("\n" + "=" * 60)
        print(f"SCAN SUMMARY")
        print("=" * 60)
        print(f"Scan target:      {self.subnet}")
        print(f"Scan completed:   {self.timestamp}")
        print(f"Scan duration:    {self.scan_duration:.2f} seconds")
        print(f"Hosts discovered: {self.stats['total_hosts']}")
        print(f"Open ports found: {self.stats['total_ports']}")
        print("-" * 60)
        print("Risk assessment:")
        print(f"  High risk:      {self.stats['risk_levels']['High']}")
        print(f"  Medium risk:    {self.stats['risk_levels']['Medium']}")
        print(f"  Low risk:       {self.stats['risk_levels']['Low']}")
        print(f"  Unknown risk:   {self.stats['risk_levels']['Unknown']}")
        print("=" * 60)
        
        # Sort hosts by IP address
        sorted_hosts = sorted(self.scan_results.keys(), 
                              key=lambda ip: [int(octet) for octet in ip.split('.')])
        
        # Print detailed results for each host
        if sorted_hosts:
            print("\nDETAILED RESULTS:")
            print("-" * 60)
            
            for host in sorted_hosts:
                host_data = self.scan_results[host]
                ports = host_data.get("ports", [])
                
                # Skip hosts with no open ports
                if not ports:
                    continue
                
                # Print host information
                print(f"\nHost: {host}")
                print("-" * 40)
                
                # Sort ports numerically
                sorted_ports = sorted(ports, key=lambda x: x["port"])
                
                # Format and print port information
                for port_info in sorted_ports:
                    port = port_info["port"]
                    service = port_info["service"]
                    version = port_info.get("version", "")
                    risk = port_info["risk"]
                    
                    # Format the output
                    service_str = service
                    if version:
                        service_str += f" ({version})"
                    
                    # Add risk level highlight
                    risk_highlight = ""
                    if risk == "High":
                        risk_highlight = " - HIGH RISK"
                    elif risk == "Medium":
                        risk_highlight = " - Medium Risk"
                    
                    print(f"  Port {port}: {service_str}{risk_highlight}")
            
            print("\n" + "=" * 60)
        else:
            print("\nNo hosts with open ports were found.")


class HTMLReporter(BaseReporter):
    """HTML report generator."""
    
    def generate_report(self, filename="rapidrecon_report.html"):
        """
        Generate HTML report.
        
        Args:
            filename (str): Output filename for the HTML report
            
        Returns:
            str: Path to the generated HTML file
        """
        # Create templates directory if it doesn't exist
        templates_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
        os.makedirs(templates_dir, exist_ok=True)
        
        # Get template path
        template_path = os.path.join(templates_dir, "report_template.html")
        
        # Check if template exists, if not create a basic one
        if not os.path.exists(template_path):
            self._create_default_template(template_path)
        
        # Read the template
        try:
            with open(template_path, "r") as f:
                template = f.read()
        except Exception as e:
            print(f"Error reading template: {str(e)}")
            template = self._get_default_template()
        
        # Generate content for the template
        content = self._generate_content()
        
        # Replace placeholders in template
        report_html = template.replace("{{DETAILED_RESULTS}}", content)
        report_html = report_html.replace("{{TIMESTAMP}}", self.timestamp)
        report_html = report_html.replace("{{SUBNET}}", self.subnet)
        report_html = report_html.replace("{{DURATION}}", f"{self.scan_duration:.2f}")
        report_html = report_html.replace("{{HOST_COUNT}}", str(self.stats["total_hosts"]))
        report_html = report_html.replace("{{PORT_COUNT}}", str(self.stats["total_ports"]))
        report_html = report_html.replace("{{HIGH_RISK}}", str(self.stats["risk_levels"]["High"]))
        report_html = report_html.replace("{{MEDIUM_RISK}}", str(self.stats["risk_levels"]["Medium"]))
        report_html = report_html.replace("{{LOW_RISK}}", str(self.stats["risk_levels"]["Low"]))
        report_html = report_html.replace("{{UNKNOWN_RISK}}", str(self.stats["risk_levels"]["Unknown"]))
        
        # Write the report to file
        with open(filename, "w", encoding="utf-8") as f:
            f.write(report_html)
        
        return filename
    
    def _generate_content(self):
        """
        Generate the HTML content for the report.
        
        Returns:
            str: HTML content representing scan results
        """
        content = ""
        
        # Sort hosts by IP address
        sorted_hosts = sorted(self.scan_results.keys(), 
                              key=lambda ip: [int(octet) for octet in ip.split('.')])
        
        # Generate table for each host
        if sorted_hosts:
            for host in sorted_hosts:
                host_data = self.scan_results[host]
                ports = host_data.get("ports", [])
                
                # Skip hosts with no open ports
                if not ports:
                    continue
                
                # Create host table
                content += f'<div class="host-section">\n'
                content += f'  <div class="host-header" onclick="toggleHostSection(this)">\n'
                content += f'    <h3>Host: {host}</h3>\n'
                content += f'    <span>▼</span>\n'
                content += f'  </div>\n'
                content += f'  <div class="host-content">\n'
                content += f'    <table class="results-table">\n'
                content += f'      <thead>\n'
                content += f'        <tr><th>Port</th><th>Service</th><th>Version</th><th>Risk Level</th></tr>\n'
                content += f'      </thead>\n'
                content += f'      <tbody>\n'
                
                # Sort ports numerically
                sorted_ports = sorted(ports, key=lambda x: x["port"])
                
                # Add rows for each port
                for port_info in sorted_ports:
                    port = port_info["port"]
                    service = port_info["service"]
                    version = port_info.get("version", "")
                    risk = port_info["risk"]
                    
                    # Determine badge class based on risk
                    badge_class = f"badge-{risk.lower()}"
                    
                    content += f'        <tr>\n'
                    content += f'          <td>{port}</td>\n'
                    content += f'          <td>{service}</td>\n'
                    content += f'          <td>{version}</td>\n'
                    content += f'          <td><span class="badge {badge_class}">{risk}</span></td>\n'
                    content += f'        </tr>\n'
                
                content += f'      </tbody>\n'
                content += f'    </table>\n'
                content += f'  </div>\n'
                content += f'</div>\n'
        else:
            content = "<p>No hosts with open ports were found.</p>"
        
        return content
    
    def _create_default_template(self, template_path):
        """
        Create default HTML template file.
        
        Args:
            template_path (str): Path to save the template
        """
        template = self._get_default_template()
        
        try:
            with open(template_path, "w", encoding="utf-8") as f:
                f.write(template)
        except Exception as e:
            print(f"Error creating template: {str(e)}")
    
    def _get_default_template(self):
        """
        Get default HTML template content.
        
        Returns:
            str: HTML template content
        """
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RapidRecon Network Scan Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        .header {
            background-color: #2c3e50;
            color: white;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .summary {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            border: 1px solid #ddd;
        }
        .risk-summary {
            display: flex;
            justify-content: space-around;
            text-align: center;
            margin: 20px 0;
        }
        .risk-item {
            padding: 10px;
            border-radius: 5px;
            min-width: 100px;
        }
        .high {
            background-color: #ffdddd;
            color: #a94442;
        }
        .medium {
            background-color: #fff3cd;
            color: #856404;
        }
        .low {
            background-color: #d4edda;
            color: #155724;
        }
        .unknown {
            background-color: #e2e3e5;
            color: #383d41;
        }
        .host-section {
            margin-bottom: 30px;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
        }
        .host-header {
            background-color: #f2f2f2;
            padding: 10px;
            border-bottom: 1px solid #ddd;
            cursor: pointer;
        }
        .host-header span {
            float: right;
        }
        .host-content {
            padding: 10px;
            display: none;
        }
        .results-table {
            width: 100%;
            border-collapse: collapse;
        }
        .results-table th, .results-table td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        .results-table th {
            background-color: #f2f2f2;
        }
        .badge {
            padding: 5px 10px;
            border-radius: 5px;
            font-size: 0.9em;
        }
        .badge-high {
            background-color: #ffdddd;
            color: #a94442;
        }
        .badge-medium {
            background-color: #fff3cd;
            color: #856404;
        }
        .badge-low {
            background-color: #d4edda;
            color: #155724;
        }
        .badge-unknown {
            background-color: #e2e3e5;
            color: #383d41;
        }
        .footer {
            text-align: center;
            margin-top: 30px;
            font-size: 0.9em;
            color: #777;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>RapidRecon</h1>
        <p>Generated on {{TIMESTAMP}}</p>
    </div>
    
    <div class="summary">
        <h2>Scan Summary</h2>
        <p><strong>Subnet:</strong> {{SUBNET}}</p>
        <p><strong>Scan Duration:</strong> {{DURATION}} seconds</p>
        <p><strong>Hosts Discovered:</strong> {{HOST_COUNT}}</p>
        <p><strong>Open Ports Found:</strong> {{PORT_COUNT}}</p>
        
        <h3>Risk Assessment</h3>
        <div class="risk-summary">
            <div class="risk-item high">
                <h4>High Risk</h4>
                <p>{{HIGH_RISK}}</p>
            </div>
            <div class="risk-item medium">
                <h4>Medium Risk</h4>
                <p>{{MEDIUM_RISK}}</p>
            </div>
            <div class="risk-item low">
                <h4>Low Risk</h4>
                <p>{{LOW_RISK}}</p>
            </div>
            <div class="risk-item unknown">
                <h4>Unknown</h4>
                <p>{{UNKNOWN_RISK}}</p>
            </div>
        </div>
    </div>
    
    <h2>Detailed Results</h2>
    {{DETAILED_RESULTS}}
    
    <div class="footer">
        <p>Network and operation course</p>
    </div>
    
    <script>
        function toggleHostSection(element) {
            var hostContent = element.parentNode.nextElementSibling;
            if (hostContent.style.display === "block") {
                hostContent.style.display = "none";
                element.children[1].textContent = "▼";
            } else {
                hostContent.style.display = "block";
                element.children[1].textContent = "▲";
            }
        }
    </script>
</body>
</html>"""
