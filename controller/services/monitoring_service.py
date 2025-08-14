"""
Monitoring service for DNS-Loki Controller
Handles system monitoring, metrics collection, and health checks
"""

import asyncio
import psutil
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from ..core.database import state_manager, cache_manager
from ..core.logging import get_logger


logger = get_logger(__name__)


class MonitoringService:
    """Service for system monitoring and metrics"""
    
    def __init__(self):
        self.initialized = False
        self._monitoring_task: Optional[asyncio.Task] = None
        self._metrics_history: List[Dict[str, Any]] = []
        self._max_history = 1000  # Keep last 1000 metrics entries
    
    async def start(self):
        """Start monitoring service"""
        try:
            logger.info("Starting monitoring service...")
            # Start monitoring task
            self._monitoring_task = asyncio.create_task(self._monitoring_loop())
            self.initialized = True
            logger.info("Monitoring service started successfully")
        except Exception as e:
            logger.error(f"Failed to start monitoring service: {e}")
            raise
    
    async def stop(self):
        """Stop monitoring service"""
        try:
            logger.info("Stopping monitoring service...")
            
            # Cancel monitoring task
            if self._monitoring_task and not self._monitoring_task.done():
                self._monitoring_task.cancel()
                try:
                    await self._monitoring_task
                except asyncio.CancelledError:
                    pass
            
            logger.info("Monitoring service stopped")
        except Exception as e:
            logger.error(f"Error stopping monitoring service: {e}")
    
    async def health_check(self) -> Dict[str, Any]:
        """Basic health check"""
        try:
            return {
                "status": "healthy",
                "timestamp": datetime.utcnow().isoformat(),
                "service": "dns-loki-controller",
                "version": "2.0.0",
                "monitoring_active": self.initialized and self._monitoring_task and not self._monitoring_task.done()
            }
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return {
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def get_system_status(self) -> Dict[str, Any]:
        """Get overall system status"""
        try:
            # Get database status
            db_stats = await state_manager.get("stats", {})
            
            # Get basic system info
            system_info = {
                "cpu_percent": psutil.cpu_percent(interval=1),
                "memory": dict(psutil.virtual_memory()._asdict()),
                "disk": dict(psutil.disk_usage('/')._asdict()) if psutil.disk_usage('/') else {},
                "uptime": datetime.utcnow().timestamp() - psutil.boot_time()
            }
            
            return {
                "database": {"status": "connected", "stats": db_stats},
                "cache": {"status": "active"},
                "system": system_info,
                "services": {
                    "controller": "running",
                    "monitoring": "running" if self.initialized else "stopped"
                }
            }
        except Exception as e:
            logger.error(f"Failed to get system status: {e}")
            return {"error": str(e)}
    
    async def get_system_metrics(self) -> Dict[str, Any]:
        """Get current system metrics"""
        try:
            metrics = {
                "timestamp": datetime.utcnow().isoformat(),
                "cpu": {
                    "percent": psutil.cpu_percent(interval=1),
                    "count": psutil.cpu_count()
                },
                "memory": {
                    "total": psutil.virtual_memory().total,
                    "available": psutil.virtual_memory().available,
                    "percent": psutil.virtual_memory().percent,
                    "used": psutil.virtual_memory().used
                },
                "disk": {
                    "total": psutil.disk_usage('/').total if psutil.disk_usage('/') else 0,
                    "used": psutil.disk_usage('/').used if psutil.disk_usage('/') else 0,
                    "free": psutil.disk_usage('/').free if psutil.disk_usage('/') else 0,
                    "percent": psutil.disk_usage('/').percent if psutil.disk_usage('/') else 0
                },
                "network": self._get_network_stats(),
                "processes": len(psutil.pids())
            }
            
            # Add to history
            self._metrics_history.append(metrics)
            if len(self._metrics_history) > self._max_history:
                self._metrics_history.pop(0)
            
            return metrics
        except Exception as e:
            logger.error(f"Failed to get system metrics: {e}")
            return {"error": str(e)}
    
    async def get_node_metrics(self, ip: str, period: str = "1h") -> Dict[str, Any]:
        """Get metrics for specific node"""
        try:
            # Get node data from state
            nodes = await state_manager.get("nodes", {})
            node = nodes.get(ip, {})
            
            if not node:
                return {"error": "Node not found"}
            
            # Get cached metrics for this node
            cache_key = f"node_metrics_{ip}_{period}"
            cached = await cache_manager.get(cache_key)
            if cached:
                return cached
            
            # Generate mock metrics (in real implementation, this would come from agents)
            metrics = {
                "node_ip": ip,
                "period": period,
                "timestamp": datetime.utcnow().isoformat(),
                "cpu_usage": node.get("status", {}).get("cpu_usage", 0),
                "memory_usage": node.get("status", {}).get("memory_usage", 0),
                "disk_usage": node.get("status", {}).get("disk_usage", 0),
                "uptime": node.get("status", {}).get("uptime", 0),
                "services": node.get("status", {}).get("services", {}),
                "last_heartbeat": node.get("status", {}).get("last_heartbeat")
            }
            
            # Cache for 5 minutes
            await cache_manager.set(cache_key, metrics, 300)
            return metrics
        except Exception as e:
            logger.error(f"Failed to get node metrics for {ip}: {e}")
            return {"error": str(e)}
    
    async def get_performance_metrics(self, period: str = "1h") -> Dict[str, Any]:
        """Get performance metrics"""
        try:
            # Calculate time range
            now = datetime.utcnow()
            if period == "1h":
                start_time = now - timedelta(hours=1)
            elif period == "6h":
                start_time = now - timedelta(hours=6)
            elif period == "24h":
                start_time = now - timedelta(days=1)
            elif period == "7d":
                start_time = now - timedelta(days=7)
            else:
                start_time = now - timedelta(hours=1)
            
            # Filter metrics history by time range
            filtered_metrics = [
                m for m in self._metrics_history
                if datetime.fromisoformat(m['timestamp'].replace('Z', '+00:00')) >= start_time
            ]
            
            if not filtered_metrics:
                return {"error": "No metrics data available for the specified period"}
            
            # Calculate averages
            avg_cpu = sum(m.get('cpu', {}).get('percent', 0) for m in filtered_metrics) / len(filtered_metrics)
            avg_memory = sum(m.get('memory', {}).get('percent', 0) for m in filtered_metrics) / len(filtered_metrics)
            
            return {
                "period": period,
                "data_points": len(filtered_metrics),
                "averages": {
                    "cpu_percent": round(avg_cpu, 2),
                    "memory_percent": round(avg_memory, 2)
                },
                "latest": filtered_metrics[-1] if filtered_metrics else None
            }
        except Exception as e:
            logger.error(f"Failed to get performance metrics: {e}")
            return {"error": str(e)}
    
    async def get_alerts(self, active_only: bool = True, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get system alerts"""
        try:
            # Mock alerts - in real implementation, this would come from alert system
            alerts = []
            
            # Check system health and generate alerts
            current_metrics = await self.get_system_metrics()
            if isinstance(current_metrics, dict) and 'error' not in current_metrics:
                # CPU alert
                cpu_percent = current_metrics.get('cpu', {}).get('percent', 0)
                if cpu_percent > 80:
                    alerts.append({
                        "id": "cpu_high",
                        "type": "system",
                        "severity": "warning" if cpu_percent < 90 else "critical",
                        "message": f"High CPU usage: {cpu_percent}%",
                        "timestamp": datetime.utcnow().isoformat(),
                        "active": True
                    })
                
                # Memory alert
                memory_percent = current_metrics.get('memory', {}).get('percent', 0)
                if memory_percent > 85:
                    alerts.append({
                        "id": "memory_high", 
                        "type": "system",
                        "severity": "warning" if memory_percent < 95 else "critical",
                        "message": f"High memory usage: {memory_percent}%",
                        "timestamp": datetime.utcnow().isoformat(),
                        "active": True
                    })
            
            # Filter by severity if specified
            if severity:
                alerts = [a for a in alerts if a.get('severity') == severity]
            
            # Filter by active status
            if active_only:
                alerts = [a for a in alerts if a.get('active', False)]
            
            return alerts
        except Exception as e:
            logger.error(f"Failed to get alerts: {e}")
            return []
    
    async def get_prometheus_metrics(self) -> str:
        """Get metrics in Prometheus format"""
        try:
            current_metrics = await self.get_system_metrics()
            if isinstance(current_metrics, dict) and 'error' not in current_metrics:
                metrics_text = f"""# HELP dns_loki_cpu_percent CPU usage percentage
# TYPE dns_loki_cpu_percent gauge
dns_loki_cpu_percent {current_metrics.get('cpu', {}).get('percent', 0)}

# HELP dns_loki_memory_percent Memory usage percentage  
# TYPE dns_loki_memory_percent gauge
dns_loki_memory_percent {current_metrics.get('memory', {}).get('percent', 0)}

# HELP dns_loki_disk_percent Disk usage percentage
# TYPE dns_loki_disk_percent gauge
dns_loki_disk_percent {current_metrics.get('disk', {}).get('percent', 0)}

# HELP dns_loki_processes_total Total number of processes
# TYPE dns_loki_processes_total gauge
dns_loki_processes_total {current_metrics.get('processes', 0)}
"""
                return metrics_text
            else:
                return "# Error getting metrics\n"
        except Exception as e:
            logger.error(f"Failed to get Prometheus metrics: {e}")
            return f"# Error: {str(e)}\n"
    
    def _get_network_stats(self) -> Dict[str, Any]:
        """Get network statistics"""
        try:
            net_io = psutil.net_io_counters()
            return {
                "bytes_sent": net_io.bytes_sent,
                "bytes_recv": net_io.bytes_recv,
                "packets_sent": net_io.packets_sent,
                "packets_recv": net_io.packets_recv
            }
        except Exception as e:
            logger.error(f"Failed to get network stats: {e}")
            return {}
    
    async def _monitoring_loop(self):
        """Background monitoring loop"""
        while True:
            try:
                await asyncio.sleep(60)  # Collect metrics every minute
                await self.get_system_metrics()
                logger.debug("Metrics collected")
            except asyncio.CancelledError:
                logger.info("Monitoring loop cancelled")
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(30)  # Wait 30 seconds before retry
