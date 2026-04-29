# Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
NIS2 MCP (Model Context Protocol) Server.

Exposes the NIS2 Compliance Platform as MCP tools for AI assistants:
- scan_target(url) → Run scan and return findings
- check_certificate(domain) → Deep cert analysis
- get_compliance_status(org_id) → Current compliance posture
- explain_finding(finding_id) → AI explanation
- generate_report(scan_id, format) → Generate report
- get_governance_score(org_id) → Governance checklist status
- search_playbooks(query) → Find remediation playbooks
"""
import asyncio
import json
import logging
import sys
import uuid
from typing import Any

from fastapi import APIRouter, Depends

from app.dependencies import get_current_user_org
from app.models.user import User

logger = logging.getLogger("nis2.mcp")

# MCP tool definitions (JSON-Schema format for MCP protocol)
MCP_TOOLS = [
    {
        "name": "check_certificate",
        "description": "Deep TLS/SSL certificate analysis for a domain. Returns chain validation, expiry, key strength, OCSP status, CT logs, and a 0-100 health score.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to analyze (e.g. example.com)"},
                "port": {"type": "integer", "description": "TLS port (default 443)", "default": 443},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "scan_target",
        "description": "Quick NIS2 compliance scan of a single domain. Returns open ports, TLS issues, DNS security, HTTP headers, and compliance score.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Domain or IP to scan"},
                "features": {
                    "type": "object",
                    "description": "Feature flags",
                    "properties": {
                        "dns_checks": {"type": "boolean", "default": True},
                        "web_checks": {"type": "boolean", "default": True},
                        "port_scan": {"type": "boolean", "default": True},
                    },
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "search_playbooks",
        "description": "Search NIS2 remediation playbooks by keyword. Returns step-by-step fix instructions with server-specific configs (Nginx, Apache, Caddy).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search term (e.g. 'TLS', 'SPF', 'SMB', 'HSTS')"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "get_playbook",
        "description": "Get a specific remediation playbook with full configs and commands.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "playbook_id": {"type": "string", "description": "Playbook ID (e.g. 'tls_obsolete_protocol', 'dns_no_spf')"},
            },
            "required": ["playbook_id"],
        },
    },
    {
        "name": "estimate_remediation",
        "description": "Estimate remediation effort and cost for a list of findings.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "findings": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "message": {"type": "string"},
                            "severity": {"type": "string"},
                            "category": {"type": "string"},
                        },
                    },
                    "description": "List of findings to estimate",
                },
            },
            "required": ["findings"],
        },
    },
    {
        "name": "list_governance_items",
        "description": "List the 30 NIS2 governance checklist items with their priorities and descriptions.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
]


async def handle_tool_call(name: str, arguments: dict) -> Any:
    """Execute an MCP tool call and return the result."""

    if name == "check_certificate":
        from nis2scan.certificate import CertificateAnalyzer
        analyzer = CertificateAnalyzer(timeout=10)
        info = await analyzer.analyze(
            arguments["domain"],
            arguments.get("port", 443),
        )
        return analyzer.to_dict(info)

    elif name == "scan_target":
        from nis2scan.config import Config, Targets
        from nis2scan.scanner import Scanner
        from nis2scan.compliance import ComplianceEngine

        target = arguments["target"]
        features = arguments.get("features", {
            "dns_checks": True, "web_checks": True, "port_scan": True,
        })
        config = Config(
            targets=Targets(domains=[target]),
            features=features,
            scan_timeout=10,
            concurrency=5,
            max_hosts=1,
        )
        scanner = Scanner(config)
        results = await scanner.run()
        engine = ComplianceEngine(config)
        report = engine.evaluate(results)

        return {
            "target": target,
            "score": report.total_score,
            "findings_count": len(report.findings),
            "findings": [
                {
                    "severity": f.severity,
                    "category": f.category,
                    "message": f.message,
                    "remediation": f.remediation,
                }
                for f in report.findings
            ],
            "hosts_scanned": report.stats.get("analyzed_hosts", 0),
            "hosts_alive": report.stats.get("active_hosts", 0),
        }

    elif name == "search_playbooks":
        from app.services.remediation import get_all_playbooks
        query = arguments["query"].lower()
        playbooks = get_all_playbooks()
        matches = {}
        for pid, pb in playbooks.items():
            searchable = f"{pb['title']} {pb['category']} {pid} {' '.join(pb['steps'])}".lower()
            if query in searchable:
                matches[pid] = {
                    "title": pb["title"],
                    "category": pb["category"],
                    "effort": pb["effort"],
                    "nis2_article": pb["nis2_article"],
                }
        return {"query": query, "total": len(matches), "playbooks": matches}

    elif name == "get_playbook":
        from app.services.remediation import get_all_playbooks
        playbooks = get_all_playbooks()
        pb = playbooks.get(arguments["playbook_id"])
        if not pb:
            return {"error": f"Playbook '{arguments['playbook_id']}' not found"}
        return {"id": arguments["playbook_id"], **pb}

    elif name == "estimate_remediation":
        from app.services.remediation import estimate_remediation
        return estimate_remediation(arguments["findings"])

    elif name == "list_governance_items":
        from app.routers.governance import CHECKLIST_TEMPLATE
        return {
            "total": len(CHECKLIST_TEMPLATE),
            "items": [
                {"id": item_id, "priority": priority, "title": title,
                 "description": desc, "nis2_reference": ref}
                for item_id, priority, title, desc, ref in CHECKLIST_TEMPLATE
            ],
        }

    else:
        return {"error": f"Unknown tool: {name}"}


def run_mcp_stdio():
    """Run the MCP server in stdio mode (for Claude Desktop, Cursor, etc.)."""

    async def _main():
        # Read JSON-RPC messages from stdin, write responses to stdout
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin)

        while True:
            try:
                line = await reader.readline()
                if not line:
                    break
                request = json.loads(line.decode())
                method = request.get("method", "")

                if method == "initialize":
                    response = {
                        "jsonrpc": "2.0",
                        "id": request.get("id"),
                        "result": {
                            "protocolVersion": "2024-11-05",
                            "capabilities": {"tools": {}},
                            "serverInfo": {
                                "name": "nis2-compliance",
                                "version": "2.4.26",
                            },
                        },
                    }
                elif method == "tools/list":
                    response = {
                        "jsonrpc": "2.0",
                        "id": request.get("id"),
                        "result": {"tools": MCP_TOOLS},
                    }
                elif method == "tools/call":
                    params = request.get("params", {})
                    tool_name = params.get("name", "")
                    tool_args = params.get("arguments", {})
                    try:
                        result = await handle_tool_call(tool_name, tool_args)
                        response = {
                            "jsonrpc": "2.0",
                            "id": request.get("id"),
                            "result": {
                                "content": [{"type": "text", "text": json.dumps(result, default=str, indent=2)}],
                            },
                        }
                    except Exception as e:
                        response = {
                            "jsonrpc": "2.0",
                            "id": request.get("id"),
                            "result": {
                                "content": [{"type": "text", "text": f"Error: {e}"}],
                                "isError": True,
                            },
                        }
                else:
                    response = {
                        "jsonrpc": "2.0",
                        "id": request.get("id"),
                        "result": {},
                    }

                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()

            except Exception as e:
                logger.error(f"MCP error: {e}")
                break

    asyncio.run(_main())


# FastAPI router for HTTP-based MCP (alternative to stdio).
# All HTTP MCP routes require authentication: the stdio entry point is local
# and trusted, but the HTTP entry point sits behind FastAPI and must be
# tenant-scoped.

router = APIRouter(prefix="/mcp", tags=["mcp"])


@router.get("/tools")
async def list_tools(
    auth: tuple[User, uuid.UUID] = Depends(get_current_user_org),
):
    """List available MCP tools."""
    return {"tools": MCP_TOOLS}


@router.post("/call")
async def call_tool(
    request: dict,
    auth: tuple[User, uuid.UUID] = Depends(get_current_user_org),
):
    """Execute an MCP tool call via HTTP."""
    name = request.get("name", "")
    arguments = request.get("arguments", {})
    if not name:
        return {"error": "Missing tool name"}
    try:
        result = await handle_tool_call(name, arguments)
        return {"result": result}
    except Exception as e:
        return {"error": str(e)}
