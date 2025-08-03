import os
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

app = FastAPI()

# Set up paths
templates_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")

# Mount static files
app.mount("/static", StaticFiles(directory=static_dir), name="static")
templates = Jinja2Templates(directory=templates_dir)

# Import agent functions
from agents.log_parser import extract_iocs
from agents.threat_lookup import ThreatLookupAgent
from agents.geo_lookup import get_geo_info
from agents.risk_scorer import score_risk
from agents.action_recommender import recommend_action
from agents.summary_generator import generate_summary
from agents.export_agent import export_csv, export_stix
from agents.report_history import ReportHistoryAgent
from agents.yara_engine import scan_with_yara
from agents.sigma_engine import scan_with_sigma
from agents.mitre_attack import map_to_mitre

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/analyze", response_class=HTMLResponse)
async def analyze(
    request: Request,
    raw_input: str = Form(...),
    enable_geo: bool = Form(False),
    export_csv_flag: bool = Form(False),
    export_stix_flag: bool = Form(False)
):
    # Run analysis
    results = run_analysis(raw_input, enable_geo, export_csv_flag, export_stix_flag)

    # Generate summary
    summary_table = generate_summary(results)

    return templates.TemplateResponse("results.html", {
        "request": request,
        "summary_table": summary_table,
        "export_csv_flag": export_csv_flag,
        "export_stix_flag": export_stix_flag,
        "enable_geo": enable_geo,
        "results": results
    })

def run_analysis(raw_input, enable_geo=True, export_csv_flag=False, export_stix_flag=False):
    print("[+] Parsing IOCs...")
    iocs = extract_iocs(raw_input)

    print("[+] Initializing agents...")
    lookup_agent = ThreatLookupAgent()
    history_agent = ReportHistoryAgent()

    results = []

    for ioc_type, values in iocs.items():
        if ioc_type == "hashes":
            for value, htype in values:
                if history_agent.is_seen(value): continue
                print(f"[+] Analyzing {value} ({htype})")
                threat_data = lookup_agent.lookup_ioc(value, htype.lower())
                risk = score_risk(threat_data)
                action = recommend_action(risk["level"])
                yara_matches = scan_with_yara(value)
                sigma_match = scan_with_sigma(value)
                mitre_tactic = map_to_mitre(htype)
                geo = get_geo_info(value) if enable_geo and ioc_type == "ips" else {}
                results.append({
                    "ioc": value,
                    "type": htype,
                    "risk": risk,
                    "action": action,
                    "yara": yara_matches,
                    "sigma": sigma_match,
                    "mitre": mitre_tactic,
                    "geo": geo
                })
                history_agent.add_seen(value)
        elif ioc_type in ["ips", "domains", "urls", "emails"]:
            for value in values:
                if history_agent.is_seen(value): continue
                print(f"[+] Analyzing {value}")
                threat_data = lookup_agent.lookup_ioc(value, ioc_type.rstrip('s'))
                risk = score_risk(threat_data)
                action = recommend_action(risk["level"])
                yara_matches = scan_with_yara(value)
                sigma_match = scan_with_sigma(value)
                mitre_tactic = map_to_mitre(ioc_type.rstrip('s'))
                geo = get_geo_info(value) if enable_geo and ioc_type == "ips" else {}
                results.append({
                    "ioc": value,
                    "type": ioc_type.rstrip('s'),
                    "risk": risk,
                    "action": action,
                    "yara": yara_matches,
                    "sigma": sigma_match,
                    "mitre": mitre_tactic,
                    "geo": geo
                })
                history_agent.add_seen(value)

    if export_csv_flag:
        export_csv(results)
    if export_stix_flag:
        export_stix(results)

    return results