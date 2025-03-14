import os
from datetime import datetime
import json
import csv
from typing import Optional, Dict, Any
from pathlib import Path
import jinja2
from utils import setup_logger, console, SecurityValidator, SecurityError

class LogReportError(SecurityError):
    pass

class ReportFormatError(LogReportError):
    pass

class DataValidationError(LogReportError):
    pass

class OutputPathError(LogReportError):
    pass

logger = setup_logger('LogReportPro', 'LogReportPro.log')

class ReportGenerator:
    SUPPORTED_FORMATS = ['json', 'html', 'csv', 'pdf']
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.config = config or {}
        self.data: Dict[str, Any] = {}
        self.validator = SecurityValidator()
        logger.info("Report generation started")

    def collect_data(self) -> Dict[str, Any]:
        self.data = {
            "timestamp": self.timestamp,
            "system_info": self._get_system_info(),
            "activity_data": self._get_activity_data(),
        }
        
        if not self._validate_data(self.data):
            raise DataValidationError("Collected data failed validation")
            
        logger.debug(f"Data collected: {self.data}")
        return self.data

    def _get_system_info(self) -> Dict[str, Any]:
        try:
            uname = os.uname()
            info = {
                "platform": uname.sysname,
                "node": uname.nodename,
                "release": uname.release,
                "version": uname.version,
                "machine": uname.machine,
            }
            logger.debug(f"System info: {info}")
            return info
        except Exception as e:
            logger.error(f"Error collecting system info: {e}")
            return {}

    def _get_activity_data(self) -> Dict[str, Any]:
        try:
            data = {
                "activities": [
                    {"action": "login", "status": "success", "timestamp": "2025-01-25 10:00:00"},
                    {"action": "upload", "status": "failed", "timestamp": "2025-01-25 10:05:00"},
                ],
                "metrics": {
                    "total_operations": 100,
                    "successful_operations": 90,
                    "failed_operations": 10
                }
            }
            logger.debug(f"Activity data: {data}")
            return data
        except Exception as e:
            logger.error(f"Error collecting activity data: {e}")
            return {}

    def _validate_data(self, data: Dict[str, Any]) -> bool:
        try:
            required_keys = ["timestamp", "system_info", "activity_data"]
            if not all(key in data for key in required_keys):
                logger.error(f"Missing required keys in data: {required_keys}")
                return False
                
            self.validator.validate_data_structure(data)
            return True
        except Exception as e:
            logger.error(f"Data validation error: {e}")
            return False

    def generate_report(self, format: str = 'pdf', output: Optional[str] = None) -> Optional[str]:
        try:
            format = format.lower()
            if format not in self.SUPPORTED_FORMATS:
                raise ReportFormatError(f"Unsupported format: {format}. Supported formats: {self.SUPPORTED_FORMATS}")

            data = self.collect_data()
            if not output:
                output_dir = self.config.get('output_dir', '.')
                Path(output_dir).mkdir(parents=True, exist_ok=True)
                output = str(Path(output_dir) / f"report_{self.timestamp}.{format}")
            
            generators = {
                'json': self._generate_json,
                'html': self._generate_html,
                'csv': self._generate_csv,
                'pdf': self._generate_pdf
            }

            result = generators[format](data, output)
            if result:
                console.print(f"[green]Report generated successfully: {result}[/green]")
            return result

        except (LogReportError, Exception) as e:
            logger.error(f"{'Report generation' if isinstance(e, LogReportError) else 'Unexpected'} error: {e}", 
                        exc_info=not isinstance(e, LogReportError))
            console.print(f"[red]{'Report generation' if isinstance(e, LogReportError) else 'Unexpected'} error: {str(e)}[/red]")
            return None

    def _generate_json(self, data: Dict[str, Any], output_path: str) -> Optional[str]:
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            logger.debug(f"JSON report saved at {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Error generating JSON report: {e}")
            return None

    def _generate_html(self, data: Dict[str, Any], output_path: str) -> Optional[str]:
        try:
            template = """
            <html>
                <head>
                    <meta charset="UTF-8">
                    <title>Report {{ timestamp }}</title>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 20px; }
                        table { border-collapse: collapse; width: 100%; }
                        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                        th { background-color: #f2f2f2; }
                    </style>
                </head>
                <body>
                    <h1>Activity Report</h1>
                    <h2>System Information</h2>
                    <table>
                        {% for key, value in system_info.items() %}
                        <tr>
                            <th>{{ key }}</th>
                            <td>{{ value }}</td>
                        </tr>
                        {% endfor %}
                    </table>
                    <h2>Activity Data</h2>
                    <h3>Metrics</h3>
                    <table>
                        {% for key, value in activity_data.metrics.items() %}
                        <tr>
                            <th>{{ key }}</th>
                            <td>{{ value }}</td>
                        </tr>
                        {% endfor %}
                    </table>
                    <h3>Activities</h3>
                    <table>
                        <tr>
                            <th>Action</th>
                            <th>Status</th>
                            <th>Time</th>
                        </tr>
                        {% for activity in activity_data.activities %}
                        <tr>
                            <td>{{ activity.action }}</td>
                            <td>{{ activity.status }}</td>
                            <td>{{ activity.timestamp }}</td>
                        </tr>
                        {% endfor %}
                    </table>
                </body>
            </html>
            """

            env = jinja2.Environment(autoescape=True)
            tmpl = env.from_string(template)
            html_content = tmpl.render(
                timestamp=data['timestamp'],
                system_info=data['system_info'],
                activity_data=data['activity_data']
            )

            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            logger.debug(f"HTML report saved at {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Error generating HTML report: {e}")
            return None
        
    def _generate_csv(self, data: Dict[str, Any], output_path: str) -> Optional[str]:
        try:
            activities = data['activity_data'].get('activities', [])
            
            if not activities:
                logger.warning("No activity data available for CSV export")
                
            with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
                if activities:
                    fieldnames = list(activities[0].keys())
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(activities)
                
                csvfile.write("\n\nSystem Information\n")
                system_writer = csv.writer(csvfile)
                for key, value in data['system_info'].items():
                    system_writer.writerow([key, value])
                
                csvfile.write("\n\nMetrics\n")
                metrics = data['activity_data'].get('metrics', {})
                metrics_writer = csv.writer(csvfile)
                for key, value in metrics.items():
                    metrics_writer.writerow([key, value])
                    
            logger.debug(f"CSV report saved at {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Error generating CSV report: {e}")
            return None
            
    def _generate_pdf(self, data: Dict[str, Any], output_path: str) -> Optional[str]:
        try:
            html_path = output_path.replace('.pdf', '.html')
            self._generate_html(data, html_path)
            
            try:
                import weasyprint
                html = weasyprint.HTML(filename=html_path)
                html.write_pdf(output_path)
            except ImportError:
                from reportlab.lib.pagesizes import letter
                from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
                from reportlab.lib.styles import getSampleStyleSheet
                
                doc = SimpleDocTemplate(output_path, pagesize=letter)
                elements = []
                
                styles = getSampleStyleSheet()
                title_style = styles['Heading1']
                subtitle_style = styles['Heading2']
                
                elements.append(Paragraph("Activity Report", title_style))
                
                elements.append(Paragraph("System Information", subtitle_style))
                system_data = [[key, str(value)] for key, value in data['system_info'].items()]
                system_table = Table(system_data)
                system_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), '#f2f2f2'),
                    ('TEXTCOLOR', (0, 0), (-1, 0), (0, 0, 0)),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('INNERGRID', (0, 0), (-1, -1), 0.25, (0, 0, 0)),
                    ('BOX', (0, 0), (-1, -1), 0.25, (0, 0, 0)),
                ]))
                elements.append(system_table)
                
                elements.append(Paragraph("Activities", subtitle_style))
                activities = data['activity_data']['activities']
                if activities:
                    headers = list(activities[0].keys())
                    activity_data = [headers]
                    for activity in activities:
                        activity_data.append([str(activity.get(h, '')) for h in headers])
                    
                    activity_table = Table(activity_data)
                    activity_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), '#f2f2f2'),
                        ('TEXTCOLOR', (0, 0), (-1, 0), (0, 0, 0)),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('INNERGRID', (0, 0), (-1, -1), 0.25, (0, 0, 0)),
                        ('BOX', (0, 0), (-1, -1), 0.25, (0, 0, 0)),
                    ]))
                    elements.append(activity_table)
                
                doc.build(elements)
                
            os.remove(html_path)
            
            logger.debug(f"PDF report saved at {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Error generating PDF report: {e}", exc_info=True)
            return None

    def generate_summary(self) -> str:
        summary = f"Report Summary:\n"
        summary += f"Timestamp: {self.data.get('timestamp')}\n"
        summary += f"System Info: {self.data.get('system_info')}\n"
        summary += f"Activity Data: {self.data.get('activity_data')}\n"
        return summary
