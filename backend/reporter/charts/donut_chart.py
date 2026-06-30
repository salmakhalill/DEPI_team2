import base64
from io import BytesIO
import matplotlib.pyplot as plt

def generate_donut_chart(distribution):
    total_vulns = sum(distribution.values())
    fig, ax = plt.subplots(figsize=(8, 4))
    
    if total_vulns == 0:
        sizes = [1]
        colors = ['#28a745']
        labels = ['Secure (0 Findings)']
        wedges, texts, autotexts = ax.pie(sizes, colors=colors, autopct='', startangle=90, wedgeprops=dict(width=0.4, edgecolor='w'))
        ax.text(0, 0, 'SECURE', ha='center', va='center', fontsize=12, weight='bold', color='#28a745')
        ax.legend(wedges, labels, title="System Status", loc="center left", bbox_to_anchor=(1, 0, 0.5, 1), frameon=False)
    else:
        labels = [k.capitalize() for k in distribution.keys() if distribution[k] > 0]
        sizes = [v for v in distribution.values() if v > 0]
        colors_map = {'critical': '#8b0000', 'high': '#dc3545', 'medium': '#ffc107', 'low': '#28a745'}
        colors = [colors_map[k.lower()] for k in distribution.keys() if distribution[k] > 0]
        
        wedges, texts, autotexts = ax.pie(sizes, colors=colors, autopct='%1.1f%%', startangle=90, pctdistance=0.80, textprops={'color': "white", 'weight': 'bold'}, wedgeprops=dict(width=0.4, edgecolor='w'))
        ax.legend(wedges, labels, title="Risk Level", loc="center left", bbox_to_anchor=(1, 0, 0.5, 1), frameon=False)

    ax.axis('equal')  
    buffer = BytesIO()
    plt.savefig(buffer, format='png', bbox_inches='tight', transparent=True)
    buffer.seek(0)
    image_base64 = base64.b64encode(buffer.read()).decode('utf-8')
    plt.close(fig)
    return f"data:image/png;base64,{image_base64}"