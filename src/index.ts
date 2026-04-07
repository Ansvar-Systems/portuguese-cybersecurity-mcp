#!/usr/bin/env node

/**
 * Portuguese Cybersecurity MCP — stdio entry point.
 *
 * Provides MCP tools for querying CNCS (Centro Nacional de Ciberseguranca —
 * National Cybersecurity Centre of Portugal) guidelines, technical reports,
 * security advisories, and cybersecurity frameworks.
 *
 * Tool prefix: pt_cyber_
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import {
  searchGuidance,
  getGuidance,
  searchAdvisories,
  getAdvisory,
  listFrameworks,
} from "./db.js";
import { buildCitation } from "./citation.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

let pkgVersion = "0.1.0";
try {
  const pkg = JSON.parse(
    readFileSync(join(__dirname, "..", "package.json"), "utf8"),
  ) as { version: string };
  pkgVersion = pkg.version;
} catch {
  // fallback to default
}

const SERVER_NAME = "portuguese-cybersecurity-mcp";

// --- Tool definitions ---------------------------------------------------------

const TOOLS = [
  {
    name: "pt_cyber_search_guidance",
    description:
      "Full-text search across CNCS (Centro Nacional de Ciberseguranca) guidelines and technical reports. Covers cybersecurity guides, NIS2 implementation guidance, RGPD technical measures, and sector-specific recommendations. Returns matching documents with reference, title, series, and summary.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: {
          type: "string",
          description: "Search query in Portuguese or English (e.g., 'ciberseguranca', 'NIS2 requisitos', 'gestao de vulnerabilidades', 'encryption')",
        },
        type: {
          type: "string",
          enum: ["technical_guideline", "sector_guide", "standard", "recommendation"],
          description: "Filter by document type. Optional.",
        },
        series: {
          type: "string",
          enum: ["CNCS", "NIS2", "RGPD"],
          description: "Filter by guidance series. Optional.",
        },
        status: {
          type: "string",
          enum: ["current", "superseded", "draft"],
          description: "Filter by document status. Defaults to returning all statuses.",
        },
        limit: {
          type: "number",
          description: "Maximum number of results to return. Defaults to 20.",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "pt_cyber_get_guidance",
    description:
      "Get a specific CNCS guidance document by reference (e.g., 'CNCS-2023-01', 'CNCS-Guia-001').",
    inputSchema: {
      type: "object" as const,
      properties: {
        reference: {
          type: "string",
          description: "CNCS document reference",
        },
      },
      required: ["reference"],
    },
  },
  {
    name: "pt_cyber_search_advisories",
    description:
      "Search CNCS security advisories and alerts. Returns advisories with severity, affected products, and CVE references where available.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: {
          type: "string",
          description: "Search query in Portuguese or English (e.g., 'vulnerabilidade critica', 'ransomware', 'phishing')",
        },
        severity: {
          type: "string",
          enum: ["critical", "high", "medium", "low"],
          description: "Filter by severity level. Optional.",
        },
        limit: {
          type: "number",
          description: "Maximum number of results to return. Defaults to 20.",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "pt_cyber_get_advisory",
    description:
      "Get a specific CNCS security advisory by reference (e.g., 'CNCS-2024-001').",
    inputSchema: {
      type: "object" as const,
      properties: {
        reference: {
          type: "string",
          description: "CNCS advisory reference",
        },
      },
      required: ["reference"],
    },
  },
  {
    name: "pt_cyber_list_frameworks",
    description:
      "List all CNCS frameworks and guidance series covered in this MCP, including the Portuguese national cybersecurity strategy and NIS2 implementation framework.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
  {
    name: "pt_cyber_about",
    description: "Return metadata about this MCP server: version, data source, coverage, and tool list.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
];

// --- Zod schemas for argument validation --------------------------------------

const SearchGuidanceArgs = z.object({
  query: z.string().min(1),
  type: z.enum(["technical_guideline", "sector_guide", "standard", "recommendation"]).optional(),
  series: z.enum(["CNCS", "NIS2", "RGPD"]).optional(),
  status: z.enum(["current", "superseded", "draft"]).optional(),
  limit: z.number().int().positive().max(100).optional(),
});

const GetGuidanceArgs = z.object({
  reference: z.string().min(1),
});

const SearchAdvisoriesArgs = z.object({
  query: z.string().min(1),
  severity: z.enum(["critical", "high", "medium", "low"]).optional(),
  limit: z.number().int().positive().max(100).optional(),
});

const GetAdvisoryArgs = z.object({
  reference: z.string().min(1),
});

// --- Helper ------------------------------------------------------------------

function textContent(data: unknown) {
  return {
    content: [
      { type: "text" as const, text: JSON.stringify(data, null, 2) },
    ],
  };
}

function errorContent(message: string) {
  return {
    content: [{ type: "text" as const, text: message }],
    isError: true as const,
  };
}

// --- Server setup ------------------------------------------------------------

const server = new Server(
  { name: SERVER_NAME, version: pkgVersion },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: TOOLS,
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;

  try {
    switch (name) {
      case "pt_cyber_search_guidance": {
        const parsed = SearchGuidanceArgs.parse(args);
        const results = searchGuidance({
          query: parsed.query,
          type: parsed.type,
          series: parsed.series,
          status: parsed.status,
          limit: parsed.limit,
        });
        return textContent({ results, count: results.length });
      }

      case "pt_cyber_get_guidance": {
        const parsed = GetGuidanceArgs.parse(args);
        const doc = getGuidance(parsed.reference);
        if (!doc) {
          return errorContent(`Guidance document not found: ${parsed.reference}`);
        }
        const d = doc as Record<string, unknown>;
        return textContent({
          ...d,
          _citation: buildCitation(
            String(d.reference ?? parsed.reference),
            String(d.title ?? d.reference ?? parsed.reference),
            "pt_cyber_get_guidance",
            { reference: parsed.reference },
          ),
        });
      }

      case "pt_cyber_search_advisories": {
        const parsed = SearchAdvisoriesArgs.parse(args);
        const results = searchAdvisories({
          query: parsed.query,
          severity: parsed.severity,
          limit: parsed.limit,
        });
        return textContent({ results, count: results.length });
      }

      case "pt_cyber_get_advisory": {
        const parsed = GetAdvisoryArgs.parse(args);
        const advisory = getAdvisory(parsed.reference);
        if (!advisory) {
          return errorContent(`Advisory not found: ${parsed.reference}`);
        }
        const a = advisory as Record<string, unknown>;
        return textContent({
          ...a,
          _citation: buildCitation(
            String(a.reference ?? parsed.reference),
            String(a.title ?? a.reference ?? parsed.reference),
            "pt_cyber_get_advisory",
            { reference: parsed.reference },
          ),
        });
      }

      case "pt_cyber_list_frameworks": {
        const frameworks = listFrameworks();
        return textContent({ frameworks, count: frameworks.length });
      }

      case "pt_cyber_about": {
        return textContent({
          name: SERVER_NAME,
          version: pkgVersion,
          description:
            "CNCS (Centro Nacional de Ciberseguranca — National Cybersecurity Centre of Portugal) MCP server. Provides access to Portuguese national cybersecurity guidelines, technical reports, NIS2 implementation materials, RGPD technical guidance, and security advisories.",
          data_source: "CNCS (https://www.cncs.gov.pt/)",
          coverage: {
            guidance: "National cybersecurity guidelines, NIS2 implementation guidance, RGPD technical measures, sector-specific recommendations",
            advisories: "CNCS security advisories and vulnerability alerts",
            frameworks: "Portuguese national cybersecurity framework, Quadro Nacional de Referencia para a Ciberseguranca (QNRCS)",
          },
          tools: TOOLS.map((t) => ({ name: t.name, description: t.description })),
        });
      }

      default:
        return errorContent(`Unknown tool: ${name}`);
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return errorContent(`Error executing ${name}: ${message}`);
  }
});

// --- Main --------------------------------------------------------------------

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write(`${SERVER_NAME} v${pkgVersion} running on stdio\n`);
}

main().catch((err) => {
  process.stderr.write(`Fatal error: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
