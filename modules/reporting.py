import json
import os
from datetime import datetime

class ReportGenerator:
    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def generate_json(self, system_info, findings):
        report = {
            "scan_date": datetime.now().isoformat(),
            "tool_name": "OMNISCIENT",
            "system_info": system_info,
            "findings": findings,
            "summary": {
                "total_findings": len(findings),
                "critical": len([f for f in findings if f.get('severity') == "Critical"]),
                "high": len([f for f in findings if f.get('severity') == "High"]),
                "medium": len([f for f in findings if f.get('severity') == "Medium"]),
                "low": len([f for f in findings if f.get('severity') == "Low"]),
            }
        }
        
        filename = f"{self.output_dir}/Omniscient_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=4)
            return filename
        except Exception as e:
            return f"Error: {e}"

    def generate_html(self, system_info, findings, report_name="Report"):
        # Sanitize report name for filename
        safe_name = "".join([c for c in report_name if c.isalnum() or c in (' ', '_', '-')]).strip().replace(" ", "_")
        filename = f"{self.output_dir}/Omniscient_{safe_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        crit_count = len([f for f in findings if f.get('severity') == "Critical"])
        high_count = len([f for f in findings if f.get('severity') == "High"])
        total_count = len(findings)
        
        categories = sorted(list(set(f.get('category', 'General') for f in findings)))
        
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>OMNISCIENT Report</title>
            <!-- Fonts & DataTables -->
            <link href="https://fonts.googleapis.com/css2?family=Syncopate:wght@400;700&family=Space+Mono&display=swap" rel="stylesheet">
            <link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.13.4/css/jquery.dataTables.min.css">
            
            <style>
                :root {{
                    --primary: #ffffff;
                    --secondary: #000000;
                    --bg: #000000;
                    --text: #e0e0e0;
                    --highlight: #333333;
                }}
                
                body {{ 
                    font-family: 'Space Mono', monospace; 
                    background-color: var(--bg); 
                    color: var(--text); 
                    margin: 0; 
                    padding: 40px; 
                }}
                
                .container {{ max-width: 1400px; margin: auto; }}
                
                header {{
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 60px;
                    border-bottom: 1px solid var(--text);
                    padding-bottom: 20px;
                }}
                
                h1 {{ 
                    font-family: 'Syncopate', sans-serif;
                    font-size: 3.5em; 
                    margin: 0; 
                    text-transform: uppercase;
                    letter-spacing: 12px;
                    color: white;
                    font-weight: 700;
                }}
                
                .meta {{ font-size: 0.8em; letter-spacing: 2px; text-align: right; }}
                
                .stats-grid {{ 
                    display: grid; 
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
                    gap: 0; 
                    margin-bottom: 60px; 
                    border: 1px solid var(--text);
                }}
                
                .stat-card {{ 
                    background: var(--bg); 
                    padding: 30px; 
                    border-right: 1px solid var(--text);
                    text-align: left;
                }}
                
                .stat-card:last-child {{ border-right: none; }}
                
                .stat-value {{ 
                    font-size: 3em; 
                    font-weight: 400; 
                    display: block; 
                    font-family: 'Syncopate', sans-serif; 
                }}
                .stat-label {{ color: #888; text-transform: uppercase; font-size: 0.7em; letter-spacing: 3px; display: block; margin-top: 10px; }}
                
                .text-crit {{ color: #ff3333; }}
                
                /* Filters */
                .filters {{ margin-bottom: 20px; display: flex; gap: 0; flex-wrap: wrap; }}
                .filter-btn {{
                    background: transparent;
                    border: 1px solid var(--text);
                    color: var(--text);
                    padding: 10px 20px;
                    cursor: pointer;
                    font-family: 'Space Mono', monospace;
                    text-transform: uppercase;
                    margin-right: -1px;
                    margin-bottom: -1px;
                    transition: all 0.2s;
                }}
                .filter-btn:hover, .filter-btn.active {{
                    background: var(--text);
                    color: var(--bg);
                }}
                .filter-btn.clear-btn {{
                    border-color: #ff3333;
                    color: #ff3333;
                    margin-left: 20px; /* Separation from filter group */
                }}
                .filter-btn.clear-btn:hover {{
                    background: #ff3333;
                    color: white;
                }}

                /* Table Fixed Layout */
                table.dataTable {{ 
                    width: 100% !important;
                    table-layout: fixed;
                    background: transparent; 
                    border: 1px solid var(--text) !important;
                    color: var(--text);
                }}
                
                table.dataTable thead th {{ 
                    background-color: #111; 
                    color: white; 
                    border-bottom: 1px solid var(--text) !important;
                    padding: 15px !important;
                    font-family: 'Syncopate', sans-serif;
                    letter-spacing: 2px;
                    font-size: 0.8em;
                    overflow: hidden;
                }}
                
                table.dataTable tbody td {{ 
                    background-color: transparent !important; 
                    color: var(--text) !important;
                    border-bottom: 1px solid #222;
                    padding: 15px !important;
                    font-size: 0.85em;
                    word-wrap: break-word; /* Wrap long text */
                    white-space: normal;
                }}

                /* DataTables Controls Override */
                .dataTables_wrapper .dataTables_length, 
                .dataTables_wrapper .dataTables_filter, 
                .dataTables_wrapper .dataTables_info, 
                .dataTables_wrapper .dataTables_processing, 
                .dataTables_wrapper .dataTables_paginate {{
                    color: var(--text) !important;
                    margin-top: 20px;
                    margin-bottom: 20px; /* Added spacing */
                }}
                
                .dataTables_wrapper .dataTables_filter input {{
                    background-color: #000;
                    color: white;
                    border: 1px solid #444;
                    padding: 8px; /* Increased padding */
                    margin-left: 10px;
                }}
                /* ... rest of CSS ... */

                /* Pagination Buttons */
                .dataTables_wrapper .dataTables_paginate .paginate_button {{
                    color: white !important;
                    border: 1px solid #333 !important;
                    background: transparent !important;
                }}
                
                .dataTables_wrapper .dataTables_paginate .paginate_button:hover {{
                    color: white !important;
                    border: 1px solid white !important;
                    background: #222 !important;
                }}
                
                .dataTables_wrapper .dataTables_paginate .paginate_button.current,
                .dataTables_wrapper .dataTables_paginate .paginate_button.current:hover {{
                    color: white !important;
                    border: 1px solid var(--text) !important;
                    background: #333 !important; /* Faded grey highlight */
                }}
                
                .dataTables_wrapper .dataTables_paginate .paginate_button.disabled,
                .dataTables_wrapper .dataTables_paginate .paginate_button.disabled:hover {{
                     color: #444 !important;
                     border: 1px solid transparent !important;
                     background: transparent !important;
                }}

                .badge {{ padding: 2px 6px; border: 1px solid; text-transform: uppercase; font-size: 0.8em; display: inline-block; }}
                .badge-Critical {{ color: #ff3333; border-color: #ff3333; }}
                .badge-High {{ color: #ffaa00; border-color: #ffaa00; }}
                .badge-Medium {{ color: #ffff00; border-color: #ffff00; }}
                .badge-Low {{ color: #00ccff; border-color: #00ccff; }}
                .badge-Info {{ color: #888; border-color: #888; }}

                .sys-info {{
                    border: 1px solid var(--text);
                    padding: 20px;
                    margin-bottom: 40px;
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
                    gap: 20px;
                    letter-spacing: 1px;
                }}
                .sys-item {{ display: flex; flex-direction: column; }}
                .sys-label {{ color: #888; font-size: 0.7em; letter-spacing: 2px; margin-bottom: 5px; }}
                .sys-value {{ color: white; font-size: 0.9em; }}
            </style>
        </head>
        <body>
            <div class="container">
                <header>
                    <div>
                        <h1>OMNISCIENT</h1>
                        <div style="font-size: 1rem; letter-spacing: 5px; color: #888; margin-top: -10px; padding-left: 5px;">by codeinecasket</div>
                    </div>
                    <div class="meta">
                        // ARTIFACT V1.0 //<br>
                        {datetime.now().strftime('%Y.%m.%d')}
                    </div>
                </header>

                <div class="sys-info">
                   <div class="sys-item"><span class="sys-label">HOST NODE</span><span class="sys-value">{system_info.get('Hostname', 'UNK')}</span></div>
                   <div class="sys-item"><span class="sys-label">OS BUILD</span><span class="sys-value">{system_info.get('OS Name', system_info.get('OS', 'UNK'))} ({system_info.get('OS Version', '')})</span></div>
                   <div class="sys-item"><span class="sys-label">ARCHITECTURE</span><span class="sys-value">{system_info.get('Architecture', 'UNK')}</span></div>
                   <div class="sys-item"><span class="sys-label">PROCESSOR</span><span class="sys-value">{system_info.get('Processor', 'UNK')}</span></div>
                   <div class="sys-item"><span class="sys-label">MEMORY</span><span class="sys-value">{system_info.get('Total RAM', 'UNK')}</span></div>
                   <div class="sys-item"><span class="sys-label">IP ADDRESS</span><span class="sys-value">{system_info.get('IP Address', 'UNK')}</span></div>
                   <div class="sys-item"><span class="sys-label">LAST BOOT</span><span class="sys-value">{system_info.get('Last Boot', 'UNK')}</span></div>
                   <div class="sys-item"><span class="sys-label">DOMAIN</span><span class="sys-value">{system_info.get('Domain', 'WORKGROUP')}</span></div>
                </div>

                <div class="stats-grid">
                    <div class="stat-card">
                        <span class="stat-value text-crit">{crit_count}</span>
                        <span class="stat-label">Critical</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-value">{high_count}</span>
                        <span class="stat-label">High Risk</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-value">{total_count}</span>
                        <span class="stat-label">Total Signals</span>
                    </div>
                </div>
                
                <div class="filters">
                    <button class="filter-btn active" onclick="filterTable('all')">ALL</button>
                    {''.join(f'<button class="filter-btn" onclick="filterTable(\'{c}\')">{c}</button>' for c in categories)}
                    <button class="filter-btn clear-btn" onclick="filterTable('all'); $('.dataTables_filter input').val('').keyup();">RESET VIEW</button>
                </div>

                <table id="findingsTable" class="display" style="width:100%">
                    <thead>
                        <tr>
                            <th style="width: 10%">Level</th>
                            <th style="width: 15%">Scope</th>
                            <th style="width: 25%">Signal</th>
                            <th style="width: 50%">Data</th>
                        </tr>
                    </thead>
                    <tbody>
                    {''.join(f'''
                    <tr data-category="{f.get('category', 'General')}">
                        <td><span class="badge badge-{f['severity']}">{f['severity']}</span></td>
                        <td>{f.get('category', 'General')}</td>
                        <td>{f['check']}</td>
                        <td>{f['details']}</td>
                    </tr>
                    ''' for f in findings)}
                    </tbody>
                </table>
                
                <footer style="margin-top: 80px; text-align: center; color: #444; font-size: 0.7em; letter-spacing: 4px;">
                    OMNISCIENT // BY CODEINECASKET
                </footer>
            </div>

            <script type="text/javascript" src="https://code.jquery.com/jquery-3.5.1.js"></script>
            <script type="text/javascript" src="https://cdn.datatables.net/1.13.4/js/jquery.dataTables.min.js"></script>
            <script>
                var table;
                $(document).ready(function() {{
                    table = $('#findingsTable').DataTable({{
                        "pageLength": 50,
                        "order": [],
                        "language": {{ "search": "FILTER SIGNALS:" }}
                    }});
                }});

                function filterTable(category) {{
                    $('.filter-btn').removeClass('active');
                    if(category !== 'all') event.target.classList.add('active');
                    else $('.filter-btn').first().addClass('active');

                    if (category === 'all') {{
                        table.column(1).search('').draw();
                    }} else {{
                        table.column(1).search(category).draw();
                    }}
                }}
            </script>
        </body>
        </html>
        """
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            return filename
        except Exception as e:
            return f"Error: {e}"
