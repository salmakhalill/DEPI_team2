import os
import json
from jinja2 import Environment, FileSystemLoader
from playwright.sync_api import sync_playwright
import matplotlib
matplotlib.use('Agg') 

from reporter.charts.donut_chart import generate_donut_chart
from reporter.charts.bar_chart import generate_bar_chart

def generate_pdf(dynamic_data, output_pdf_path, **kwargs):
    """Generates a premium PDF report using runtime dynamic scan data."""
    REPORTER_DIR = os.path.dirname(os.path.abspath(__file__))
    TEMPLATE_DIR = os.path.join(REPORTER_DIR, 'templates')
    
    static_json_path = os.path.join(REPORTER_DIR, 'static_content.json')
    with open(static_json_path, 'r', encoding='utf-8') as f:
        static_data = json.load(f)
        
    donut_chart = generate_donut_chart(dynamic_data['executive_summary']['aggregated_threat_distribution'])
    bar_chart = generate_bar_chart(dynamic_data['detailed_findings'])
    
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template('report.html') 
    
    html_out = template.render(
        dynamic=dynamic_data, 
        static=static_data, 
        donut_chart=donut_chart, 
        bar_chart=bar_chart
    )
    
    os.makedirs(os.path.dirname(output_pdf_path), exist_ok=True)
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.set_default_timeout(120000)
        page.set_content(html_out, wait_until="networkidle")
        
        page.pdf(
            path=output_pdf_path, 
            format="A4", 
            print_background=True, 
            display_header_footer=True,
            header_template="<div></div>",
            footer_template="""
            <div style="width: 100%; text-align: right; font-size: 10px; font-family: 'Segoe UI', Arial, sans-serif; color: #7f8c8d; padding-right: 20px; padding-bottom: 5px;">
                Page <span class="pageNumber"></span> of <span class="totalPages"></span>
            </div>
            """,
            margin={"top": "20px", "bottom": "50px", "left": "20px", "right": "20px"}
        )
        browser.close()