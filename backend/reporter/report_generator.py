import os
import json
import base64
from io import BytesIO
import matplotlib
matplotlib.use('Agg') 
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches # Imported to handle dynamic legend patches
from jinja2 import Environment, FileSystemLoader
from playwright.sync_api import sync_playwright

def generate_donut_chart(distribution):
    labels = [k.capitalize() for k in distribution.keys() if distribution[k] > 0]
    sizes = [v for v in distribution.values() if v > 0]
    colors_map = {'critical': '#8b0000', 'high': '#dc3545', 'medium': '#ffc107', 'low': '#28a745'}
    colors = [colors_map[k.lower()] for k in distribution.keys() if distribution[k] > 0]
    
    # Increased the figure width to comfortably accommodate the external legend
    fig, ax = plt.subplots(figsize=(8, 4))
    
    # Capture wedges to bind them to the legend
    wedges, texts, autotexts = ax.pie(
        sizes, colors=colors, autopct='%1.1f%%', startangle=90, 
        pctdistance=0.80, 
        textprops={'color': "white", 'weight': 'bold'}, 
        wedgeprops=dict(width=0.4, edgecolor='w')
    )
    ax.axis('equal')  
    
    # Add an elegant external legend to the right of the donut chart
    ax.legend(wedges, labels,
              title="Risk Level",
              loc="center left",
              bbox_to_anchor=(1, 0, 0.5, 1),
              frameon=False)
    
    buffer = BytesIO()
    plt.savefig(buffer, format='png', bbox_inches='tight', transparent=True)
    buffer.seek(0)
    image_base64 = base64.b64encode(buffer.read()).decode('utf-8')
    plt.close(fig) # Explicitly close the figure reference to free memory
    return f"data:image/png;base64,{image_base64}"

def generate_bar_chart(findings):
    if not findings: return ""
    ids = [f['id'] for f in findings]
    scores = []
    colors = []
    present_levels = set() # Track which risk levels actually exist in the findings
    
    for f in findings:
        try: score = float(f['cvss_score'].split()[0])
        except: score = 0
        scores.append(score)
        
        # Capitalize for the legend display
        lvl = f['threat_level'].capitalize()
        present_levels.add(lvl)
        colors.append({'Critical':'#8b0000', 'High':'#dc3545', 'Medium':'#ffc107', 'Low':'#28a745'}.get(lvl, '#28a745'))

    # Increased figure width to prevent the legend from cropping out
    fig, ax = plt.subplots(figsize=(9, 4))
    ax.bar(ids, scores, color=colors, width=0.5)
    ax.set_ylim(0, 10)
    plt.ylabel('CVSS Score')

    # Dynamically generate legend elements based strictly on the present threat levels
    colors_map = {'Critical': '#8b0000', 'High': '#dc3545', 'Medium': '#ffc107', 'Low': '#28a745'}
    legend_elements = [mpatches.Patch(color=colors_map[lvl], label=lvl) for lvl in ['Critical', 'High', 'Medium', 'Low'] if lvl in present_levels]
    
    # Place the legend outside the plot area on the top right
    ax.legend(handles=legend_elements, title="Risk Level", loc="upper left", bbox_to_anchor=(1.02, 1), frameon=False)

    buffer = BytesIO()
    plt.savefig(buffer, format='png', bbox_inches='tight', transparent=True)
    buffer.seek(0)
    image_base64 = base64.b64encode(buffer.read()).decode('utf-8')
    plt.close(fig) # Explicitly close the figure reference
    return f"data:image/png;base64,{image_base64}"

def generate_pdf(dynamic_data, output_pdf_path, **kwargs):
    """Generates a premium PDF report using runtime dynamic scan data."""
    REPORTER_DIR = os.path.dirname(os.path.abspath(__file__))
    TEMPLATE_DIR = os.path.join(REPORTER_DIR, 'templates')
    
    # Safely load the static content JSON
    static_json_path = os.path.join(REPORTER_DIR, 'static_content.json')
    with open(static_json_path, 'r', encoding='utf-8') as f:
        static_data = json.load(f)
        
    # Generate the charts with the newly attached legends
    donut_chart = generate_donut_chart(dynamic_data['executive_summary']['aggregated_threat_distribution'])
    bar_chart = generate_bar_chart(dynamic_data['detailed_findings'])
    
    # Initialize the Jinja2 rendering environment
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template('report.html') 
    
    html_out = template.render(
        dynamic=dynamic_data, 
        static=static_data, 
        donut_chart=donut_chart, 
        bar_chart=bar_chart
    )
    
    # Ensure the destination directory exists
    os.makedirs(os.path.dirname(output_pdf_path), exist_ok=True)
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        
        # Extended timeout to 120 seconds to easily accommodate massive loops and Base64 payloads
        page.set_default_timeout(120000)
        
        page.set_content(html_out, wait_until="networkidle")
        
        # Configure PDF generation with automatic pagination (Page X of Y)
        page.pdf(
            path=output_pdf_path, 
            format="A4", 
            print_background=True, 
            display_header_footer=True,
            header_template="<div></div>", # Empty header
            footer_template="""
            <div style="width: 100%; text-align: right; font-size: 10px; font-family: 'Segoe UI', Arial, sans-serif; color: #7f8c8d; padding-right: 20px; padding-bottom: 5px;">
                Page <span class="pageNumber"></span> of <span class="totalPages"></span>
            </div>
            """,
            margin={"top": "20px", "bottom": "50px", "left": "20px", "right": "20px"} # Increased bottom margin for the footer
        )
        browser.close()