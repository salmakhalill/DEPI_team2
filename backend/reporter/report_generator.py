import os
import json
import base64
from io import BytesIO
import matplotlib.pyplot as plt
from jinja2 import Environment, FileSystemLoader
from playwright.sync_api import sync_playwright

def generate_donut_chart(distribution):
    labels = [k.capitalize() for k in distribution.keys() if distribution[k] > 0]
    sizes = [v for v in distribution.values() if v > 0]
    colors_map = {'critical': '#8b0000', 'high': '#dc3545', 'medium': '#ffc107', 'low': '#28a745'}
    colors = [colors_map[k.lower()] for k in distribution.keys() if distribution[k] > 0]
    
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90, wedgeprops=dict(width=0.4, edgecolor='w'))
    ax.axis('equal')  
    
    buffer = BytesIO()
    plt.savefig(buffer, format='png', bbox_inches='tight', transparent=True)
    buffer.seek(0)
    image_base64 = base64.b64encode(buffer.read()).decode('utf-8')
    plt.close()
    return f"data:image/png;base64,{image_base64}"

def generate_bar_chart(findings):
    if not findings: return ""
    ids = [f['id'] for f in findings]
    scores = []
    colors = []
    for f in findings:
        try: score = float(f['cvss_score'].split()[0])
        except: score = 0
        scores.append(score)
        lvl = f['threat_level'].lower()
        colors.append({'critical':'#8b0000', 'high':'#dc3545', 'medium':'#ffc107', 'low':'#28a745'}.get(lvl, '#28a745'))

    fig, ax = plt.subplots(figsize=(8, 4))
    ax.bar(ids, scores, color=colors, width=0.5)
    ax.set_ylim(0, 10)
    plt.ylabel('CVSS Score')
    plt.title('Individual Threat Distribution')

    buffer = BytesIO()
    plt.savefig(buffer, format='png', bbox_inches='tight', transparent=True)
    buffer.seek(0)
    image_base64 = base64.b64encode(buffer.read()).decode('utf-8')
    plt.close()
    return f"data:image/png;base64,{image_base64}"

def generate_pdf(dynamic_data_or_path, static_json_name, template_path, output_pdf_path):
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    
    # Flexible Input Management: Accepts dictionary from database layer or string path context for raw isolated CLI test execution
    if isinstance(dynamic_data_or_path, str):
        with open(os.path.join(BASE_DIR, dynamic_data_or_path), 'r', encoding='utf-8') as f:
            dynamic_data = json.load(f)
    else:
        dynamic_data = dynamic_data_or_path
        
    with open(os.path.join(BASE_DIR, static_json_name), 'r', encoding='utf-8') as f:
        static_data = json.load(f)
        
    donut_chart = generate_donut_chart(dynamic_data['executive_summary']['aggregated_threat_distribution'])
    bar_chart = generate_bar_chart(dynamic_data['detailed_findings'])
    
    env = Environment(loader=FileSystemLoader(BASE_DIR))
    template = env.get_template(template_path)
    html_out = template.render(dynamic=dynamic_data, static=static_data, donut_chart=donut_chart, bar_chart=bar_chart)
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.set_content(html_out, wait_until="networkidle")
        page.pdf(path=output_pdf_path, format="A4", print_background=True, margin={"top":"20px","bottom":"20px","left":"20px","right":"20px"})
        browser.close()