import asyncio
import ssl
import sys

async def check_tls(ip, port, hostname):
    print(f"Checking TLS for {hostname} ({ip}:{port})...")
    result = {'valid': False, 'version': 'unknown', 'expired': False, 'expiry_date': None}
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_OPTIONAL 
        
        conn = asyncio.open_connection(ip, port, ssl=context)
        reader, writer = await asyncio.wait_for(conn, timeout=5.0)
        
        ssl_obj = writer.get_extra_info('ssl_object')
        cert = ssl_obj.getpeercert()
        print(f"Cert: {cert}")
        
        result['version'] = ssl_obj.version()
        result['cipher'] = ssl_obj.cipher()
        
        writer.close()
        await writer.wait_closed()
    except Exception as e:
        print(f"Error: {e}")
        result['error'] = str(e)
    
    print(f"Result: {result}")

if __name__ == "__main__":
    hostname = sys.argv[1] if len(sys.argv) > 1 else "mainstreaming.tv"
    # Resolve IP
    import socket
    ip = socket.gethostbyname(hostname)
    asyncio.run(check_tls(ip, 443, hostname))
