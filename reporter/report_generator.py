import os
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML
from datetime import date



def generate_report(data):
    
    template_dir = os.path.join(os.path.dirname(__file__), "templates")
    env = Environment(loader=FileSystemLoader(template_dir))

    template = env.get_template("report.html")

   # الاسمااء لو حاجة اتغيرت ننغير 
    html_content = template.render(
        target_url=data["target_url"],
        scan_date=date.today().isoformat(),
        vulnerabilities=data["vulnerabilities"]
    )

    print("START2")
    output_file = "scan_report.pdf"
    HTML(string=html_content).write_pdf(output_file)        

    print(f"✅ Report generated: {output_file}")
    

##################ex 

if __name__ == "__main__":
    data = {
        "target_url": "http://example.com",
        "vulnerabilities": []
    }

    generate_report(data)