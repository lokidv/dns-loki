"""
SSH service for remote node management
"""

import asyncio
import io
from typing import Optional, Dict, Any
from pathlib import Path
import paramiko
from paramiko import SSHClient, AutoAddPolicy, RSAKey

from ..core.logging import get_logger
from ..core.exceptions import NodeConnectionError


logger = get_logger(__name__)


class SSHService:
    """Service for SSH operations"""
    
    def __init__(self):
        self.connection_timeout = 10
        self.command_timeout = 30
    
    async def test_connection(
        self,
        host: str,
        port: int = 22,
        username: str = "root",
        password: Optional[str] = None,
        key: Optional[str] = None
    ) -> Dict[str, Any]:
        """Test SSH connection to a host"""
        try:
            # Run in executor to avoid blocking
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                self._test_connection_sync,
                host, port, username, password, key
            )
            return result
        except Exception as e:
            logger.error(f"SSH connection test failed for {host}: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _test_connection_sync(
        self,
        host: str,
        port: int,
        username: str,
        password: Optional[str],
        key: Optional[str]
    ) -> Dict[str, Any]:
        """Synchronous SSH connection test"""
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())
        
        try:
            # Prepare authentication
            pkey = None
            if key:
                try:
                    key_file = io.StringIO(key)
                    pkey = RSAKey.from_private_key(key_file)
                except Exception as e:
                    logger.warning(f"Failed to parse SSH key: {e}")
            
            # Connect
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                pkey=pkey,
                timeout=self.connection_timeout,
                look_for_keys=False,
                allow_agent=False
            )
            
            # Test command
            stdin, stdout, stderr = client.exec_command("echo 'Connection successful'")
            output = stdout.read().decode().strip()
            
            client.close()
            
            return {
                'success': True,
                'message': output
            }
        
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
        finally:
            client.close()
    
    async def execute_command(
        self,
        host: str,
        command: str,
        port: int = 22,
        username: str = "root",
        password: Optional[str] = None,
        key: Optional[str] = None,
        timeout: int = 30,
        sudo: bool = False
    ) -> Dict[str, Any]:
        """Execute a command on remote host"""
        try:
            # Add sudo if required
            if sudo and not command.startswith('sudo'):
                command = f"sudo {command}"
            
            # Run in executor
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                self._execute_command_sync,
                host, port, username, password, key, command, timeout
            )
            return result
        except Exception as e:
            logger.error(f"Command execution failed on {host}: {e}")
            return {
                'success': False,
                'error': str(e),
                'output': '',
                'exit_code': -1
            }
    
    def _execute_command_sync(
        self,
        host: str,
        port: int,
        username: str,
        password: Optional[str],
        key: Optional[str],
        command: str,
        timeout: int
    ) -> Dict[str, Any]:
        """Synchronous command execution"""
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())
        
        try:
            # Prepare authentication
            pkey = None
            if key:
                try:
                    key_file = io.StringIO(key)
                    pkey = RSAKey.from_private_key(key_file)
                except Exception as e:
                    logger.warning(f"Failed to parse SSH key: {e}")
            
            # Connect
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                pkey=pkey,
                timeout=self.connection_timeout,
                look_for_keys=False,
                allow_agent=False
            )
            
            # Execute command
            stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            
            # Get output
            output = stdout.read().decode()
            error = stderr.read().decode()
            exit_code = stdout.channel.recv_exit_status()
            
            client.close()
            
            return {
                'success': exit_code == 0,
                'output': output,
                'error': error,
                'exit_code': exit_code
            }
        
        except Exception as e:
            return {
                'success': False,
                'output': '',
                'error': str(e),
                'exit_code': -1
            }
        finally:
            client.close()
    
    async def execute_script(
        self,
        host: str,
        script: str,
        port: int = 22,
        username: str = "root",
        password: Optional[str] = None,
        key: Optional[str] = None,
        timeout: int = 60
    ) -> Dict[str, Any]:
        """Execute a multi-line script on remote host"""
        # Create a temporary script file
        script_name = f"/tmp/dns_loki_script_{asyncio.get_event_loop().time()}.sh"
        
        # Upload script
        upload_cmd = f"cat > {script_name} << 'EOF'\n{script}\nEOF"
        upload_result = await self.execute_command(
            host, upload_cmd, port, username, password, key, timeout=10
        )
        
        if not upload_result['success']:
            return upload_result
        
        # Make executable and run
        run_cmd = f"chmod +x {script_name} && {script_name}"
        run_result = await self.execute_command(
            host, run_cmd, port, username, password, key, timeout
        )
        
        # Clean up
        cleanup_cmd = f"rm -f {script_name}"
        await self.execute_command(
            host, cleanup_cmd, port, username, password, key, timeout=5
        )
        
        return run_result
    
    async def upload_file(
        self,
        host: str,
        local_path: Path,
        remote_path: str,
        port: int = 22,
        username: str = "root",
        password: Optional[str] = None,
        key: Optional[str] = None
    ) -> Dict[str, Any]:
        """Upload a file to remote host"""
        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                self._upload_file_sync,
                host, port, username, password, key, local_path, remote_path
            )
            return result
        except Exception as e:
            logger.error(f"File upload failed to {host}: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _upload_file_sync(
        self,
        host: str,
        port: int,
        username: str,
        password: Optional[str],
        key: Optional[str],
        local_path: Path,
        remote_path: str
    ) -> Dict[str, Any]:
        """Synchronous file upload"""
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())
        
        try:
            # Prepare authentication
            pkey = None
            if key:
                try:
                    key_file = io.StringIO(key)
                    pkey = RSAKey.from_private_key(key_file)
                except Exception as e:
                    logger.warning(f"Failed to parse SSH key: {e}")
            
            # Connect
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                pkey=pkey,
                timeout=self.connection_timeout,
                look_for_keys=False,
                allow_agent=False
            )
            
            # Upload file
            sftp = client.open_sftp()
            sftp.put(str(local_path), remote_path)
            sftp.close()
            
            client.close()
            
            return {
                'success': True,
                'message': f"File uploaded to {remote_path}"
            }
        
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
        finally:
            client.close()
    
    async def download_file(
        self,
        host: str,
        remote_path: str,
        local_path: Path,
        port: int = 22,
        username: str = "root",
        password: Optional[str] = None,
        key: Optional[str] = None
    ) -> Dict[str, Any]:
        """Download a file from remote host"""
        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                self._download_file_sync,
                host, port, username, password, key, remote_path, local_path
            )
            return result
        except Exception as e:
            logger.error(f"File download failed from {host}: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _download_file_sync(
        self,
        host: str,
        port: int,
        username: str,
        password: Optional[str],
        key: Optional[str],
        remote_path: str,
        local_path: Path
    ) -> Dict[str, Any]:
        """Synchronous file download"""
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())
        
        try:
            # Prepare authentication
            pkey = None
            if key:
                try:
                    key_file = io.StringIO(key)
                    pkey = RSAKey.from_private_key(key_file)
                except Exception as e:
                    logger.warning(f"Failed to parse SSH key: {e}")
            
            # Connect
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                pkey=pkey,
                timeout=self.connection_timeout,
                look_for_keys=False,
                allow_agent=False
            )
            
            # Download file
            sftp = client.open_sftp()
            sftp.get(remote_path, str(local_path))
            sftp.close()
            
            client.close()
            
            return {
                'success': True,
                'message': f"File downloaded to {local_path}"
            }
        
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
        finally:
            client.close()
