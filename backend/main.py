from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import asyncio
import json
from datetime import datetime
from typing import Dict, List, Optional
import os
from dotenv import load_dotenv
import aiosqlite
import logging

from scanner import GitHubScanner
from database import init_db, save_scan, update_scan_status, get_scan_history, get_scan_by_id
from waysecrets_scanner import WaySecretsScanner
from waysecrets_db import (
    init_waysecrets_db, save_waysecrets_scan, update_waysecrets_scan,
    get_waysecrets_scan_history, get_waysecrets_scan_by_id,
    delete_waysecrets_scan, delete_all_waysecrets_scans, get_waysecrets_stats
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

app = FastAPI(
    title="GitHub Security Scanner + WaySecrets",
    description="Multi-scanner security tool: GitHub secrets and Wayback Machine sensitive info",
    version="2.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize scanners
scanner = GitHubScanner()
waysecrets_scanner = WaySecretsScanner()

# Store active WebSocket connections
active_connections: Dict[int, WebSocket] = {}
waysecrets_connections: Dict[int, WebSocket] = {}

# Store scan tasks
scan_tasks: Dict[int, Dict] = {}
waysecrets_tasks: Dict[int, Dict] = {}

DATABASE_NAME = "scans.db"

@app.on_event("startup")
async def startup():
    await init_db()
    await init_waysecrets_db()
    print("=" * 60)
    print("Multi-Scanner Security Tool Started")
    print("=" * 60)
    print(f"GitHub Token: {'✅ Configured' if os.getenv('GITHUB_TOKEN') else '⚠️ Not configured (rate limited)'}")
    print(f"WaySecrets: ✅ Initialized")
    print(f"Server URL: http://localhost:{os.getenv('PORT', '8000')}")
    print("=" * 60)

# ==================== GitHub Scanner Endpoints ====================

@app.websocket("/ws/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: int):
    """WebSocket for GitHub scanner"""
    await websocket.accept()
    active_connections[scan_id] = websocket
    
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong", "timestamp": datetime.now().isoformat()})
    except WebSocketDisconnect:
        if scan_id in active_connections:
            del active_connections[scan_id]

async def send_progress(scan_id: int, phase: str, message: str, progress: float = None, data: Dict = None):
    """Send progress update to WebSocket client for GitHub scanner"""
    if scan_id in active_connections:
        message_data = {
            "type": "progress",
            "phase": phase,
            "message": message,
            "timestamp": datetime.now().isoformat()
        }
        
        if progress is not None:
            message_data["progress"] = progress
        
        if data:
            message_data["data"] = data
        
        try:
            await active_connections[scan_id].send_json(message_data)
        except:
            pass

@app.post("/api/scan")
async def start_scan(
    org_name: str = Query(..., description="GitHub organization or username"),
    scan_type: str = Query("public", description="Type of repos to scan: all, public, private, forked, archived, source"),
    include_buckets: bool = Query(False, description="Include cloud bucket vulnerability checks"),
    background_tasks: BackgroundTasks = None
):
    """Start a new GitHub scan"""
    try:
        # Validate scan type
        valid_scan_types = ["all", "public", "private", "forked", "archived", "source"]
        if scan_type not in valid_scan_types:
            raise HTTPException(
                status_code=400, 
                detail=f"Invalid scan_type. Must be one of: {', '.join(valid_scan_types)}"
            )
        
        # Validate org name
        if not org_name or len(org_name.strip()) == 0:
            raise HTTPException(status_code=400, detail="Organization/User name is required")
        
        # Save scan to database
        scan_id = await save_scan(org_name, scan_type, include_buckets)
        
        # Start scanning in background
        task = asyncio.create_task(run_scan_phases(scan_id, org_name, scan_type, include_buckets))
        scan_tasks[scan_id] = {
            "task": task,
            "phase": "starting",
            "org_name": org_name,
            "started_at": datetime.now().isoformat()
        }
        
        # Clean up task when done
        task.add_done_callback(lambda t: scan_tasks.pop(scan_id, None) if scan_id in scan_tasks else None)
        
        return JSONResponse(
            status_code=202,
            content={
                "scan_id": scan_id,
                "message": f"Scan started for {org_name}",
                "websocket_url": f"/ws/{scan_id}",
                "status_endpoint": f"/api/scan/{scan_id}",
                "phases": ["secret_scan", "bucket_validation"] if include_buckets else ["secret_scan"]
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start scan: {str(e)}")

async def run_scan_phases(scan_id: int, org_name: str, scan_type: str, include_buckets: bool):
    """Run GitHub scan in two phases: secrets first, then bucket validation"""
    try:
        # Phase 1: Secret Scanning
        await send_progress(scan_id, "starting", "Initializing scan...", 0)
        await update_scan_status(scan_id, "initializing")
        
        if scan_id in scan_tasks:
            scan_tasks[scan_id]["phase"] = "secret_scan"
        
        await send_progress(scan_id, "secret_scan", f"Detecting account type for '{org_name}'...", 5)
        
        # Get account type
        account_type, _ = await scanner.detect_account_type(org_name)
        await send_progress(scan_id, "secret_scan", f"Detected as {account_type}. Fetching repositories...", 10)
        
        # Get repositories
        repos = await scanner.get_github_repos(org_name, scan_type)
        
        if not repos:
            await send_progress(scan_id, "secret_scan", f"No {scan_type} repositories found for {org_name}", 100)
            await update_scan_status(scan_id, "completed", {
                "secrets": [], 
                "buckets": [], 
                "bucket_urls": [],
                "stats": {
                    "total_repos": 0,
                    "scanned_repos": 0,
                    "secrets_found": 0,
                    "bucket_urls_found": 0,
                    "vulnerable_buckets": 0
                }
            })
            return
        
        await send_progress(scan_id, "secret_scan", f"Found {len(repos)} repositories. Starting secret scan...", 15)
        
        # Run secret scan (Phase 1)
        findings = await scanner.scan_secrets_only(org_name, scan_type)
        
        # Prepare Phase 1 results
        phase1_results = {
            "phase": "secret_scan_complete",
            "secrets": findings["secrets"],
            "bucket_urls": findings["bucket_urls"],
            "stats": findings["stats"],
            "summary": {
                "total_secrets": findings["stats"]["secrets_found"],
                "total_bucket_urls": findings["stats"]["bucket_urls_found"],
                "repos_scanned": findings["stats"]["scanned_repos"],
                "repos_total": findings["stats"]["total_repos"]
            }
        }
        
        # Send Phase 1 completion
        await send_progress(
            scan_id, 
            "secret_scan", 
            f"✅ Secret scan complete! Found {findings['stats']['secrets_found']} secrets and {findings['stats']['bucket_urls_found']} bucket URLs.", 
            100,
            phase1_results
        )
        
        # Update database with Phase 1 results
        await update_scan_status(
            scan_id, 
            "secret_scan_complete", 
            {
                "secrets": findings["secrets"],
                "bucket_urls": findings["bucket_urls"],
                "buckets": [],  # Empty for now
                "stats": findings["stats"]
            },
            findings["stats"]["total_repos"],
            findings["stats"]["scanned_repos"]
        )
        
        # Phase 2: Bucket Validation (only if requested and bucket URLs found)
        if include_buckets and findings["bucket_urls"]:
            if scan_id in scan_tasks:
                scan_tasks[scan_id]["phase"] = "bucket_validation"
            
            await send_progress(
                scan_id, 
                "bucket_validation", 
                f"Starting bucket validation for {len(findings['bucket_urls'])} bucket URLs...", 
                0
            )
            
            bucket_results = []
            vulnerable_count = 0
            
            for i, bucket_info in enumerate(findings["bucket_urls"]):
                # Check for cancellation
                if scan_id not in scan_tasks:
                    break
                
                progress = (i / len(findings["bucket_urls"])) * 100
                await send_progress(
                    scan_id,
                    "bucket_validation",
                    f"Checking bucket {i+1}/{len(findings['bucket_urls'])}: {bucket_info['url'][:50]}...",
                    progress
                )
                
                # Validate bucket
                result = await scanner.check_bucket_vulnerability(bucket_info["url"], bucket_info["type"])
                bucket_results.append(result)
                
                if result["vulnerable"]:
                    vulnerable_count += 1
                    await send_progress(
                        scan_id,
                        "bucket_validation",
                        f"🚨 VULNERABLE BUCKET FOUND: {result['url']}",
                        progress,
                        {"vulnerable_bucket": result}
                    )
            
            # Update Phase 2 results
            findings["buckets"] = bucket_results
            findings["stats"]["vulnerable_buckets"] = vulnerable_count
            
            # Send final completion
            await send_progress(
                scan_id,
                "bucket_validation",
                f"✅ Bucket validation complete! Found {vulnerable_count} vulnerable buckets out of {len(bucket_results)} checked.",
                100,
                {
                    "phase": "bucket_validation_complete",
                    "buckets": bucket_results,
                    "vulnerable_count": vulnerable_count,
                    "total_checked": len(bucket_results)
                }
            )
            
            # Update database with complete results
            await update_scan_status(
                scan_id,
                "completed",
                findings,
                findings["stats"]["total_repos"],
                findings["stats"]["scanned_repos"]
            )
            
        else:
            # No bucket validation needed or no bucket URLs found
            if include_buckets and not findings["bucket_urls"]:
                await send_progress(
                    scan_id,
                    "bucket_validation",
                    "No bucket URLs found to validate.",
                    100
                )
            
            # Mark as completed
            await update_scan_status(scan_id, "completed")
            await send_progress(
                scan_id,
                "completed",
                "✅ Scan completed successfully!",
                100,
                {"phase": "scan_complete"}
            )
        
    except asyncio.CancelledError:
        # Scan was cancelled
        await send_progress(scan_id, "cancelled", "Scan cancelled by user", 0)
        await update_scan_status(scan_id, "cancelled")
        print(f"Scan {scan_id} was cancelled")
        
    except Exception as e:
        error_msg = f"Scan failed: {str(e)}"
        print(f"Scan {scan_id} failed: {error_msg}")
        import traceback
        traceback.print_exc()
        
        await send_progress(scan_id, "failed", error_msg, 0)
        await update_scan_status(scan_id, "failed")

# ==================== WaySecrets Scanner Endpoints ====================

async def send_waysecrets_progress(scan_id: int, message: str, progress: float = None, data: Dict = None):
    """Send progress update for WaySecrets scan"""
    if scan_id in waysecrets_connections:
        try:
            message_data = {
                "type": "progress",
                "message": message,
                "timestamp": datetime.now().isoformat()
            }
            
            if progress is not None:
                message_data["progress"] = progress
            
            if data:
                message_data["data"] = data
            
            await waysecrets_connections[scan_id].send_json(message_data)
            logger.debug(f"Sent progress to scan {scan_id}: {message}")
            
        except Exception as e:
            logger.warning(f"Failed to send progress to scan {scan_id}: {e}")
            if scan_id in waysecrets_connections:
                del waysecrets_connections[scan_id]

@app.websocket("/ws/waysecrets/{scan_id}")
async def waysecrets_websocket_endpoint(websocket: WebSocket, scan_id: int):
    """WebSocket endpoint for WaySecrets real-time updates"""
    await websocket.accept()
    waysecrets_connections[scan_id] = websocket
    
    try:
        # Send initial connection confirmation
        await websocket.send_json({
            "type": "connected",
            "message": f"Connected to scan {scan_id}",
            "scan_id": scan_id
        })
        
        # Simple keep-alive
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                if data == "ping":
                    await websocket.send_json({
                        "type": "pong", 
                        "timestamp": datetime.now().isoformat()
                    })
            except asyncio.TimeoutError:
                # Send keep-alive ping
                try:
                    await websocket.send_json({
                        "type": "ping",
                        "timestamp": datetime.now().isoformat()
                    })
                except:
                    break
            except WebSocketDisconnect:
                break
                
    except Exception as e:
        logger.error(f"WebSocket error for scan {scan_id}: {e}")
    finally:
        if scan_id in waysecrets_connections:
            del waysecrets_connections[scan_id]
        logger.info(f"WebSocket closed for scan {scan_id}")

async def run_waysecrets_scan(scan_id: int, domain: str):
    """Run WaySecrets scan with proper WebSocket communication"""
    start_time = datetime.now()
    
    try:
        # Send initial progress IMMEDIATELY
        await send_waysecrets_progress(scan_id, "🚀 Starting WaySecrets scan...", 5)
        await update_waysecrets_scan(scan_id, "initializing")
        
        if scan_id in waysecrets_tasks:
            waysecrets_tasks[scan_id]["status"] = "initializing"
        
        # Phase 1: Fetch URLs
        await send_waysecrets_progress(
            scan_id, 
            f"🌐 Fetching URLs from Wayback Machine for {domain}...", 
            20
        )
        
        # Run the actual scan with timeout
        try:
            result = await asyncio.wait_for(
                waysecrets_scanner.scan_domain(domain),
                timeout=60.0  # 60 second timeout
            )
        except asyncio.TimeoutError:
            raise Exception("Scan timeout after 60 seconds")
        
        # Send progress updates
        await send_waysecrets_progress(
            scan_id,
            f"🔍 Analyzing {result.stats.get('urls_scanned', 0)} URLs for sensitive data...",
            50
        )
        
        # Prepare results in the expected format
        results_dict = {
            "sensitive_tokens": result.sensitive_tokens,
            "sensitive_endpoints": result.sensitive_endpoints,
            "idor_params": result.idor_params,
            "open_redirect_params": result.open_redirect_params,
            "sample_urls": result.all_urls[:100]  # Limit to 100 sample URLs
        }
        
        # Create summary
        summary_parts = []
        if len(result.sensitive_tokens) > 0:
            summary_parts.append(f"{len(result.sensitive_tokens)} tokens")
        if len(result.sensitive_endpoints) > 0:
            summary_parts.append(f"{len(result.sensitive_endpoints)} endpoints")
        if len(result.idor_params) > 0:
            summary_parts.append(f"{len(result.idor_params)} IDOR params")
        if len(result.open_redirect_params) > 0:
            summary_parts.append(f"{len(result.open_redirect_params)} redirect params")
        
        summary = ", ".join(summary_parts) if summary_parts else "No sensitive findings"
        
        # Send completion with full results
        await send_waysecrets_progress(
            scan_id,
            f"✅ Scan complete! Found: {summary}",
            100,
            {
                "phase": "completed",
                "results": results_dict,
                "stats": result.stats,
                "summary": summary
            }
        )
        
        # Update database
        await update_waysecrets_scan(
            scan_id,
            "completed",
            results_dict,
            result.stats
        )
        
    except asyncio.CancelledError:
        await send_waysecrets_progress(scan_id, "❌ Scan cancelled", 0)
        await update_waysecrets_scan(scan_id, "cancelled")
        logger.info(f"WaySecrets scan {scan_id} was cancelled")
        
    except Exception as e:
        error_msg = f"❌ Scan failed: {str(e)}"
        logger.error(f"WaySecrets scan {scan_id} failed: {e}", exc_info=True)
        
        # Try to send error message via WebSocket
        try:
            await send_waysecrets_progress(scan_id, error_msg, 0)
        except:
            pass
            
        await update_waysecrets_scan(scan_id, "failed")

@app.post("/api/waysecrets/scan")
async def start_waysecrets_scan(
    domain: str = Query(..., description="Domain to scan via Wayback Machine"),
    background_tasks: BackgroundTasks = None
):
    """Start a new WaySecrets scan"""
    try:
        # Validate domain
        if not domain or len(domain.strip()) < 3:
            raise HTTPException(status_code=400, detail="Valid domain name is required")
        
        # Clean domain (remove protocol, paths)
        domain = domain.lower().strip()
        if domain.startswith(('http://', 'https://')):
            from urllib.parse import urlparse
            domain = urlparse(domain).netloc
        
        # Remove www prefix
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Save scan to database
        scan_id = await save_waysecrets_scan(domain)
        
        # Start scanning in background
        task = asyncio.create_task(run_waysecrets_scan(scan_id, domain))
        waysecrets_tasks[scan_id] = {
            "task": task,
            "status": "starting",
            "domain": domain,
            "started_at": datetime.now().isoformat()
        }
        
        # Clean up task when done
        task.add_done_callback(lambda t: waysecrets_tasks.pop(scan_id, None) if scan_id in waysecrets_tasks else None)
        
        return JSONResponse(
            status_code=202,
            content={
                "scan_id": scan_id,
                "message": f"WaySecrets scan started for {domain}",
                "websocket_url": f"/ws/waysecrets/{scan_id}",
                "status_endpoint": f"/api/waysecrets/scan/{scan_id}"
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to start WaySecrets scan: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to start scan: {str(e)[:100]}")

@app.get("/api/waysecrets/scan/{scan_id}")
async def get_waysecrets_scan_results(scan_id: int):
    """Get WaySecrets scan results"""
    try:
        scan = await get_waysecrets_scan_by_id(scan_id)
        
        if not scan:
            raise HTTPException(status_code=404, detail="WaySecrets scan not found")
        
        # Add task info if still running
        current_status = scan["status"]
        
        if scan_id in waysecrets_tasks:
            current_status = "running"
            scan["task_info"] = {
                "status": waysecrets_tasks[scan_id].get("status"),
                "started_at": waysecrets_tasks[scan_id].get("started_at"),
                "domain": waysecrets_tasks[scan_id].get("domain")
            }
        
        scan["current_status"] = current_status
        
        return scan
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch WaySecrets scan: {str(e)}")

@app.delete("/api/waysecrets/scan/{scan_id}")
async def cancel_waysecrets_scan(scan_id: int):
    """Cancel a running WaySecrets scan"""
    try:
        if scan_id in waysecrets_tasks:
            waysecrets_tasks[scan_id]["task"].cancel()
            
            # Update status
            await update_waysecrets_scan(scan_id, "cancelled")
            
            # Send cancellation message
            await send_waysecrets_progress(scan_id, "Scan cancelled by user", 0)
            
            return {"message": f"WaySecrets scan {scan_id} cancelled", "success": True}
        else:
            # Check if scan exists
            scan = await get_waysecrets_scan_by_id(scan_id)
            if not scan:
                raise HTTPException(status_code=404, detail="WaySecrets scan not found")
            
            if scan["status"] in ["completed", "failed", "cancelled"]:
                return {"message": f"Scan {scan_id} is already {scan['status']}", "success": False}
            else:
                # Mark as cancelled
                await update_waysecrets_scan(scan_id, "cancelled")
                return {"message": f"WaySecrets scan {scan_id} marked as cancelled", "success": True}
                
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to cancel WaySecrets scan: {str(e)}")

@app.get("/api/waysecrets/history")
async def get_waysecrets_history(limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0)):
    """Get WaySecrets scan history"""
    try:
        # Get total count
        async with aiosqlite.connect("waysecrets.db") as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT COUNT(*) as count FROM waysecrets_scans") as cursor:
                total_row = await cursor.fetchone()
                total_count = total_row["count"] if total_row else 0
        
        # Get paginated history
        history = await get_waysecrets_scan_history(limit)
        
        return {
            "scans": history,
            "pagination": {
                "total": total_count,
                "limit": limit,
                "offset": offset,
                "has_more": (offset + len(history)) < total_count
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch WaySecrets history: {str(e)}")

@app.delete("/api/waysecrets/history")
async def delete_waysecrets_history(
    scan_id: Optional[int] = Query(None, description="Delete specific WaySecrets scan by ID"),
    delete_all: bool = Query(False, description="Delete all WaySecrets scan history")
):
    """Delete WaySecrets scan history"""
    try:
        if scan_id:
            # Delete specific scan
            success = await delete_waysecrets_scan(scan_id)
            
            # Cancel if running
            if scan_id in waysecrets_tasks:
                waysecrets_tasks[scan_id]["task"].cancel()
                if scan_id in waysecrets_connections:
                    del waysecrets_connections[scan_id]
                waysecrets_tasks.pop(scan_id, None)
            
            return {
                "message": f"WaySecrets scan {scan_id} deleted successfully",
                "success": success
            }
        elif delete_all:
            # Delete all scans
            success = await delete_all_waysecrets_scans()
            
            # Cancel all running scans
            for sid in list(waysecrets_tasks.keys()):
                if sid in waysecrets_tasks:
                    waysecrets_tasks[sid]["task"].cancel()
                if sid in waysecrets_connections:
                    del waysecrets_connections[sid]
            
            waysecrets_tasks.clear()
            
            return {
                "message": "All WaySecrets scan history deleted",
                "success": success
            }
        else:
            raise HTTPException(
                status_code=400, 
                detail="Either provide scan_id or set delete_all=true"
            )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete WaySecrets history: {str(e)}")

@app.get("/api/waysecrets/stats")
async def get_waysecrets_system_stats():
    """Get WaySecrets system statistics"""
    running_scans = []
    for scan_id, task_info in waysecrets_tasks.items():
        running_scans.append({
            "scan_id": scan_id,
            "domain": task_info.get("domain"),
            "status": task_info.get("status"),
            "started_at": task_info.get("started_at")
        })
    
    # Get WaySecrets database stats
    ws_stats = await get_waysecrets_stats()
    
    return {
        "active_scans": len(waysecrets_tasks),
        "running_scans": running_scans,
        "active_connections": len(waysecrets_connections),
        "database_stats": ws_stats,
        "scanner_config": {
            "max_urls": waysecrets_scanner.max_urls,
            "max_concurrent": waysecrets_scanner.max_concurrent,
            "timeout": waysecrets_scanner.timeout
        },
        "timestamp": datetime.now().isoformat()
    }

@app.get("/api/waysecrets/patterns")
async def get_waysecrets_patterns():
    """Get the patterns used by WaySecrets scanner"""
    patterns_info = {
        "token_patterns": list(waysecrets_scanner.token_patterns.keys()),
        "endpoint_patterns": [label for _, label in waysecrets_scanner.endpoint_patterns],
        "idor_params": waysecrets_scanner.idor_params,
        "redirect_params": waysecrets_scanner.redirect_params,
        "ignore_patterns": waysecrets_scanner.ignore_patterns
    }
    
    return patterns_info

@app.get("/api/waysecrets/test")
async def test_waysecrets():
    """Test the WaySecrets scanner"""
    try:
        # Test with a simple, reliable domain
        test_domain = "example.com"
        urls = await waysecrets_scanner.fetch_wayback_urls_simple(test_domain)
        
        return {
            "status": "ok",
            "test_domain": test_domain,
            "urls_found": len(urls),
            "sample_url": urls[0] if urls else None,
            "backend": "working"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Test failed: {str(e)}")

# ==================== Common Endpoints ====================

@app.get("/api/history")
async def get_history(limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0)):
    """Get GitHub scan history with pagination"""
    try:
        # Get total count
        async with aiosqlite.connect(DATABASE_NAME) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT COUNT(*) as count FROM scans") as cursor:
                total_row = await cursor.fetchone()
                total_count = total_row["count"] if total_row else 0
        
        # Get paginated history
        history = await get_scan_history(limit)
        
        # Parse JSON findings
        for scan in history:
            if scan.get("findings"):
                try:
                    scan["findings"] = json.loads(scan["findings"])
                except:
                    scan["findings"] = {}
        
        return {
            "scans": history,
            "pagination": {
                "total": total_count,
                "limit": limit,
                "offset": offset,
                "has_more": (offset + len(history)) < total_count
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch history: {str(e)}")

@app.get("/api/scan/{scan_id}")
async def get_scan_results(scan_id: int):
    """Get specific GitHub scan results"""
    try:
        scan = await get_scan_by_id(scan_id)
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Get scan task status if still running
        current_status = scan["status"]
        current_phase = "completed"
        
        if scan_id in scan_tasks:
            current_phase = scan_tasks[scan_id].get("phase", "running")
            if current_phase not in ["completed", "failed", "cancelled"]:
                current_status = "running"
        
        if scan.get("findings"):
            try:
                scan["findings"] = json.loads(scan["findings"])
            except:
                scan["findings"] = {}
        
        # Add task info if running
        if scan_id in scan_tasks:
            scan["task_info"] = {
                "phase": scan_tasks[scan_id].get("phase"),
                "started_at": scan_tasks[scan_id].get("started_at"),
                "org_name": scan_tasks[scan_id].get("org_name")
            }
        
        scan["current_status"] = current_status
        scan["current_phase"] = current_phase
        
        return scan
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch scan: {str(e)}")

@app.delete("/api/scan/{scan_id}")
async def cancel_scan(scan_id: int):
    """Cancel a running GitHub scan"""
    try:
        if scan_id in scan_tasks:
            scan_tasks[scan_id]["task"].cancel()
            
            # Update status
            await update_scan_status(scan_id, "cancelled")
            
            # Send cancellation message
            await send_progress(scan_id, "cancelled", "Scan cancelled by user", 0)
            
            return {"message": f"Scan {scan_id} cancelled", "success": True}
        else:
            # Check if scan exists in database
            scan = await get_scan_by_id(scan_id)
            if not scan:
                raise HTTPException(status_code=404, detail="Scan not found")
            
            if scan["status"] in ["completed", "failed", "cancelled"]:
                return {"message": f"Scan {scan_id} is already {scan['status']}", "success": False}
            else:
                # Mark as cancelled in database
                await update_scan_status(scan_id, "cancelled")
                return {"message": f"Scan {scan_id} marked as cancelled", "success": True}
                
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to cancel scan: {str(e)}")

@app.delete("/api/history")
async def delete_history(
    scan_id: Optional[int] = Query(None, description="Delete specific scan by ID"),
    delete_all: bool = Query(False, description="Delete all scan history (requires confirmation)")
):
    """Delete GitHub scan history - either specific scan or all scans"""
    try:
        async with aiosqlite.connect(DATABASE_NAME) as db:
            if scan_id:
                # Delete specific scan
                await db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
                await db.commit()
                
                # Also cancel if running
                if scan_id in scan_tasks:
                    scan_tasks[scan_id]["task"].cancel()
                    if scan_id in active_connections:
                        del active_connections[scan_id]
                    scan_tasks.pop(scan_id, None)
                
                return {
                    "message": f"Scan {scan_id} deleted successfully",
                    "deleted_id": scan_id,
                    "success": True
                }
            elif delete_all:
                # Delete all scans
                await db.execute("DELETE FROM scans")
                await db.commit()
                
                # Cancel all running scans
                for sid in list(scan_tasks.keys()):
                    if sid in scan_tasks:
                        scan_tasks[sid]["task"].cancel()
                    if sid in active_connections:
                        del active_connections[sid]
                
                scan_tasks.clear()
                
                return {
                    "message": "All scan history deleted successfully",
                    "deleted_count": "all",
                    "success": True
                }
            else:
                raise HTTPException(
                    status_code=400, 
                    detail="Either provide scan_id or set delete_all=true"
                )
                
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete history: {str(e)}")

@app.get("/api/stats")
async def get_system_stats():
    """Get system statistics for both scanners"""
    # GitHub scanner stats
    github_running_scans = []
    for scan_id, task_info in scan_tasks.items():
        github_running_scans.append({
            "scan_id": scan_id,
            "org_name": task_info.get("org_name"),
            "phase": task_info.get("phase"),
            "started_at": task_info.get("started_at")
        })
    
    # Get database stats
    async with aiosqlite.connect(DATABASE_NAME) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT COUNT(*) as total, status FROM scans GROUP BY status") as cursor:
            status_counts = {}
            async for row in cursor:
                status_counts[row["status"]] = row["total"]
    
    # WaySecrets stats
    ws_stats = await get_waysecrets_stats()
    
    return {
        "github_scanner": {
            "active_scans": len(scan_tasks),
            "running_scans": github_running_scans,
            "active_connections": len(active_connections),
            "database_stats": status_counts
        },
        "waysecrets_scanner": {
            "active_scans": len(waysecrets_tasks),
            "running_scans": len([t for t in waysecrets_tasks.values() if t.get("status") == "running"]),
            "active_connections": len(waysecrets_connections),
            "database_stats": ws_stats
        },
        "github_token_configured": bool(os.getenv("GITHUB_TOKEN")),
        "timestamp": datetime.now().isoformat()
    }

@app.get("/")
async def root():
    """Root endpoint with API info"""
    return {
        "name": "GitHub Security Scanner + WaySecrets",
        "version": "2.0.0",
        "description": "Multi-scanner security tool",
        "scanners": {
            "github_scanner": {
                "name": "GitHub Security Scanner",
                "description": "Two-phase scanner: 1. Find secrets, 2. Validate bucket vulnerabilities",
                "endpoints": {
                    "start_scan": "POST /api/scan?org_name=<name>&scan_type=<type>&include_buckets=<bool>",
                    "scan_status": "GET /api/scan/{scan_id}",
                    "scan_history": "GET /api/history?limit=<int>&offset=<int>",
                    "cancel_scan": "DELETE /api/scan/{scan_id}",
                    "delete_history": "DELETE /api/history?scan_id=<id>&delete_all=<bool>",
                    "system_stats": "GET /api/stats",
                    "patterns": "GET /api/patterns",
                    "websocket": "WS /ws/{scan_id}"
                }
            },
            "waysecrets": {
                "name": "WaySecrets",
                "description": "Wayback Machine sensitive information scanner",
                "endpoints": {
                    "start_scan": "POST /api/waysecrets/scan?domain=<domain>",
                    "scan_status": "GET /api/waysecrets/scan/{scan_id}",
                    "scan_history": "GET /api/waysecrets/history?limit=<int>&offset=<int>",
                    "cancel_scan": "DELETE /api/waysecrets/scan/{scan_id}",
                    "delete_history": "DELETE /api/waysecrets/history?scan_id=<id>&delete_all=<bool>",
                    "system_stats": "GET /api/waysecrets/stats",
                    "patterns": "GET /api/waysecrets/patterns",
                    "test": "GET /api/waysecrets/test",
                    "websocket": "WS /ws/waysecrets/{scan_id}"
                }
            }
        },
        "features": [
            "GitHub secret detection",
            "Cloud bucket vulnerability checking",
            "Wayback Machine URL collection",
            "Sensitive token detection in URLs",
            "Sensitive endpoint discovery",
            "IDOR parameter detection",
            "Open redirect parameter detection",
            "Real-time WebSocket updates",
            "Separate databases for each scanner"
        ]
    }

@app.get("/api/health")
async def health_check():
    """Health check endpoint for both scanners"""
    try:
        # Check GitHub scanner database
        async with aiosqlite.connect(DATABASE_NAME) as db:
            await db.execute("SELECT 1")
        
        # Check WaySecrets database
        async with aiosqlite.connect("waysecrets.db") as db:
            await db.execute("SELECT 1")
        
        return {
            "status": "healthy", 
            "timestamp": datetime.now().isoformat(),
            "databases": {
                "github_scanner": "connected",
                "waysecrets": "connected"
            },
            "github_api": "ready" if os.getenv("GITHUB_TOKEN") else "rate_limited",
            "active_scans": {
                "github": len(scan_tasks),
                "waysecrets": len(waysecrets_tasks)
            }
        }
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Service unhealthy: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    
    # Get port from environment or default to 8000
    port = int(os.getenv("PORT", "8000"))
    
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=port,
        log_level="info",
        access_log=True
    )