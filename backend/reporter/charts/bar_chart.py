import base64
from io import BytesIO
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

def generate_bar_chart(findings):
    if not findings: return ""
    ids = [f['id'] for f in findings]
    scores = []
    colors = []
    present_levels = set()
    
    for f in findings:
        try: score = float(f['cvss_score'].split()[0])
        except: score = 0
        scores.append(score)
        
        lvl = f['threat_level'].capitalize()
        present_levels.add(lvl)
        colors.append({'Critical':'#8b0000', 'High':'#dc3545', 'Medium':'#ffc107', 'Low':'#28a745'}.get(lvl, '#28a745'))

    fig, ax = plt.subplots(figsize=(9, 4))
    ax.bar(ids, scores, color=colors, width=0.5)
    ax.set_ylim(0, 10)
    plt.ylabel('CVSS Score')
    plt.xticks(rotation=90, ha='center', fontsize=8)
    colors_map = {'Critical': '#8b0000', 'High': '#dc3545', 'Medium': '#ffc107', 'Low': '#28a745'}
    legend_elements = [mpatches.Patch(color=colors_map[lvl], label=lvl) for lvl in ['Critical', 'High', 'Medium', 'Low'] if lvl in present_levels]
    ax.legend(handles=legend_elements, title="Risk Level", loc="upper left", bbox_to_anchor=(1.02, 1), frameon=False)

    buffer = BytesIO()
    plt.savefig(buffer, format='png', bbox_inches='tight', transparent=True)
    buffer.seek(0)
    image_base64 = base64.b64encode(buffer.read()).decode('utf-8')
    plt.close(fig)
    return f"data:image/png;base64,{image_base64}"