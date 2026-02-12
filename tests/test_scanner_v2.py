import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from nis2_checker.scanner_logic import ScannerLogic

@pytest.mark.asyncio
async def test_scanner_async_orchestration():
    config = {
        'timeout': 1,
        'checks': {'connectivity': True, 'ssl_tls': True, 'evidence': False},
        'nmap': {'enabled': False},
        'ssl': {}, 'headers': {}, 'dns': {}, 'whois': {}, 'content': {}, 'compliance': {}
    }
    
    with patch('nis2_checker.scanner_logic.NmapScanner'), \
         patch('nis2_checker.scanner_logic.DNSScanner'), \
         patch('nis2_checker.scanner_logic.WhoisScanner'), \
         patch('nis2_checker.scanner_logic.ContentScanner'), \
         patch('nis2_checker.scanner_logic.ComplianceScanner'), \
         patch('nis2_checker.scanner_logic.EvidenceCollector'), \
         patch('nis2_checker.scanner_logic.WebScannerPlugin') as MockWeb, \
         patch('nis2_checker.scanner_logic.CompliancePlugin') as MockComp, \
         patch('nis2_checker.scanner_logic.InfrastructurePlugin') as MockInfra:
        
        # Setup Mocks
        MockWeb.return_value.scan = AsyncMock(return_value=[])
        MockComp.return_value.scan = AsyncMock(return_value=[])
        MockInfra.return_value.scan = AsyncMock(return_value=[])
        
        scanner = ScannerLogic(config)
        target = {'url': 'https://example.com', 'name': 'Test'}
        
        results = await scanner.scan_target(target)
        
        assert len(results) == 1
        assert results[0].name == 'Test'
        assert MockWeb.return_value.scan.called
        assert MockComp.return_value.scan.called
