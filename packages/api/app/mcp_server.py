# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
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
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.dependencies import (
    ROLES_ANY,
    ROLES_AUDITOR_OR_ADMIN,
    get_current_org,
)
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.routers.auth import limiter
from app.models.membership import Membership
from app.models.user import User

logger = logging.getLogger("nis2.mcp")


def _mcp_version() -> str:
    """Return the installed package version, matching main.py's logic."""
    try:
        from importlib.metadata import version as _pkg_version

        return _pkg_version("nis2-api")
    except Exception:
        return "0.0.0-dev"


# MCP tool definitions (JSON-Schema format for MCP protocol)
MCP_TOOLS = [
    {
        "name": "check_certificate",
        "description": "Deep TLS/SSL certificate analysis for a domain. Returns chain validation, expiry, key strength, OCSP status, CT logs, and a 0-100 health score.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Domain to analyze (e.g. example.com)",
                },
                "port": {
                    "type": "integer",
                    "description": "TLS port (default 443)",
                    "default": 443,
                },
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
                "query": {
                    "type": "string",
                    "description": "Search term (e.g. 'TLS', 'SPF', 'SMB', 'HSTS')",
                },
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
                "playbook_id": {
                    "type": "string",
                    "description": "Playbook ID (e.g. 'tls_obsolete_protocol', 'dns_no_spf')",
                },
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



async def _require_owned_target(target: str, *, db: Any, org_id: Any) -> "str | None":
    """Return an error string when `target` is not a verified asset of `org_id`.

    Returns None when the scan may proceed.
    """
    if db is None or org_id is None:
        # The STDIO entry point has no session. Refusing is the only honest
        # answer: running the scan would mean scanning an arbitrary host with no
        # record of who authorised it.
        return (
            "scan_target requires an authenticated session so the target can be "
            "matched against a verified asset. Use the HTTP MCP endpoint."
        )

    from sqlalchemy import select

    from app.models.asset import Asset
    from app.utils import asset_verification

    result = await db.execute(
        select(Asset).where(
            Asset.organization_id == org_id,
            Asset.target_value == target,
            Asset.is_active.is_(True),
        )
    )
    asset = result.scalars().first()
    if asset is None:
        return (
            f"{target!r} is not an asset of this organisation. Add it and verify "
            f"ownership before scanning; this tool does not accept arbitrary hosts."
        )
    if not asset_verification.may_scan(asset.verification_status):
        return (
            f"Ownership is not established for {target!r} "
            f"(status: {asset.verification_status}). Verify the domain or attest "
            f"authority over the range first."
        )
    return None


async def handle_tool_call(
    name: str,
    arguments: dict,
    *,
    db: Any = None,
    org_id: Any = None,
) -> Any:
    """Execute an MCP tool call and return the result.

    `db` and `org_id` are threaded through so the outbound-scan tools can check
    that the caller's organisation has established authority over the target.
    They are optional because the STDIO entry point has no request context; that
    path refuses those tools outright rather than running them unchecked.
    """

    if name == "check_certificate":
        # P0-04 audit fix: validate domain against SSRF blocklist
        # before any outbound connection.
        from app.utils.target_validator import (
            validate_domain_pinned,
            TargetValidationError,
        )

        domain = arguments.get("domain", "")
        try:
            await validate_domain_pinned(domain)
        except TargetValidationError as exc:
            return {"error": f"Target blocked: {exc}"}

        from nis2scan.certificate import CertificateAnalyzer

        analyzer = CertificateAnalyzer(timeout=10)
        info = await analyzer.analyze(
            domain,
            arguments.get("port", 443),
        )
        return analyzer.to_dict(info)

    elif name == "scan_target":
        from nis2scan.config import Config, Targets
        from nis2scan.scanner import Scanner
        from nis2scan.compliance import ComplianceEngine

        target = arguments.get("target", "")

        # P0-04 audit fix: validate the scan target against the SSRF
        # blocklist BEFORE any outbound connection. Without this, an
        # authenticated user could scan localhost, cloud metadata
        # endpoints (169.254.169.254), or internal RFC-1918 ranges
        # via the HTTP MCP endpoint.
        from app.utils.target_validator import (
            validate_domain_pinned,
            validate_ip_pinned,
            TargetValidationError,
        )
        import ipaddress as _ipaddress

        try:
            # Heuristic: if it parses as an IP, validate as IP;
            # otherwise treat as domain.
            try:
                _ipaddress.ip_address(target)
                validate_ip_pinned(target)
            except ValueError:
                await validate_domain_pinned(target)
        except TargetValidationError as exc:
            return {"error": f"Target blocked: {exc}"}

        # Ownership. routers/scans.py and the scheduled-scan task both refuse
        # targets whose ownership was never established; without the same gate
        # here this tool is the way around them — and it is the most permissive
        # of the three, because it takes a free-form target rather than an
        # Asset row. A scan port-scans the host, attempts zone transfers against
        # its nameservers and requests /.env from it.
        ownership_error = await _require_owned_target(target, db=db, org_id=org_id)
        if ownership_error:
            return {"error": ownership_error}

        features = arguments.get(
            "features",
            {
                "dns_checks": True,
                "web_checks": True,
                "port_scan": True,
            },
        )
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
            searchable = (
                f"{pb['title']} {pb['category']} {pid} {' '.join(pb['steps'])}".lower()
            )
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
                {
                    "id": item_id,
                    "priority": priority,
                    "title": title,
                    "description": desc,
                    "nis2_reference": ref,
                }
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
        await asyncio.get_running_loop().connect_read_pipe(lambda: protocol, sys.stdin)

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
                                "version": _mcp_version(),
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
                                "content": [
                                    {
                                        "type": "text",
                                        "text": json.dumps(
                                            result, default=str, indent=2
                                        ),
                                    }
                                ],
                            },
                        }
                    except Exception as e:
                        logger.error(
                            "MCP tool %r failed in stdio: %s",
                            tool_name,
                            e,
                            exc_info=True,
                        )
                        response = {
                            "jsonrpc": "2.0",
                            "id": request.get("id"),
                            "result": {
                                "content": [
                                    {
                                        "type": "text",
                                        "text": "Error: Internal error processing MCP tool call",
                                    }
                                ],
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
#
# P1-07 audit fix: rate-limited. MCP tools like scan_target trigger
# full network scans which are expensive on both the platform and the
# target. Without limits a single client could saturate every Celery
# worker.

router = APIRouter(prefix="/mcp", tags=["mcp"])


# Per-tool role requirements.
#
# This endpoint was an RBAC bypass. Every tool ran behind
# `Depends(get_current_user_org)`, which proves membership of an organisation
# and nothing else — so a `viewer`, the read-only role, could POST
# /api/v1/mcp/call and reach the two tools that generate outbound traffic:
#
#   scan_target       -> full port scan, AXFR attempts, HTTP probing of an
#                        arbitrary internet host
#   check_certificate -> TLS/CT-log analysis of an arbitrary host
#
# Their REST equivalents are gated: POST /scans and the whole /certificates
# router require admin or auditor. The MCP surface simply skipped that, and
# because MCP scans are not persisted as Scan rows they also left no
# org-visible trace.
#
# Default is DENY: a tool absent from this map cannot be called at all, so
# adding a tool to MCP_TOOLS without deciding its authorisation fails closed
# instead of inheriting the weakest gate in the file.
MCP_TOOL_ROLES: dict[str, tuple[str, ...]] = {
    # Outbound network actions — mirror the REST gates.
    "check_certificate": ROLES_AUDITOR_OR_ADMIN,
    "scan_target": ROLES_AUDITOR_OR_ADMIN,
    # Read-only lookups against local data or static playbooks.
    "search_playbooks": ROLES_ANY,
    "get_playbook": ROLES_ANY,
    "estimate_remediation": ROLES_ANY,
    "list_governance_items": ROLES_ANY,
}


def _tool_is_allowed(tool_name: str, role: str) -> bool:
    return role in MCP_TOOL_ROLES.get(tool_name, ())


@router.get("/tools")
async def list_tools(
    current_org: tuple[User, Membership] = Depends(get_current_org),
):
    """List the MCP tools the caller is actually allowed to invoke.

    Filtered rather than complete: advertising a tool that would 403 on call
    invites an AI assistant to plan around a capability it does not have.
    """
    _, membership = current_org
    return {
        "tools": [t for t in MCP_TOOLS if _tool_is_allowed(t["name"], membership.role)]
    }


@router.post("/call")
@limiter.limit("20/minute")
async def call_tool(
    request: Request,
    payload: dict,
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
):
    """Execute an MCP tool call via HTTP.

    P0-05 audit fix: internal exceptions are logged server-side and the
    client receives a generic error string. Pre-fix, ``str(e)`` leaked
    filesystem paths, connection-string fragments, and table names.
    """
    user, membership = current_org
    name = payload.get("name", "")
    arguments = payload.get("arguments", {})
    if not name:
        return {"error": "Missing tool name"}

    # Authorise BEFORE dispatch. Unknown tools fall through to the empty tuple
    # in MCP_TOOL_ROLES and are refused.
    if not _tool_is_allowed(name, membership.role):
        allowed = MCP_TOOL_ROLES.get(name)
        logger.warning(
            "MCP tool %r denied for user=%s org=%s role=%s",
            name,
            user.id,
            membership.organization_id,
            membership.role,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"This tool requires one of: {', '.join(allowed)}"
                if allowed
                else "Unknown tool"
            ),
        )

    try:
        result = await handle_tool_call(
            name, arguments, db=db, org_id=membership.organization_id
        )
        return {"result": result}
    except Exception as e:
        # P0-05 audit fix: never leak internal exception text.
        logger.error("MCP tool %r failed: %s", name, e, exc_info=True)
        return {"error": "Internal error processing MCP tool call"}
