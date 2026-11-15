#!/usr/bin/env node
/**
 * Minimal stdio JSON-RPC 2.0 MCP Server for local Bifrost + TOOLSEAL integration testing.
 * Exposes safe utilities alongside intentionally sensitive/unregistered tools so Bifrost's
 * PreMCPHook and PostMCPHook can be verified end-to-end against real MCP responses and errors.
 */
import readline from 'node:readline';

const TOOLS = [
  {
    name: 'get_weather',
    description: 'Retrieves current meteorological forecast for a given city.',
    inputSchema: {
      type: 'object',
      properties: {
        city: { type: 'string', description: 'Target city name (e.g. Mumbai)' },
        units: { type: 'string', enum: ['metric', 'imperial'], description: 'Temperature unit system' },
      },
      required: ['city'],
      additionalProperties: false,
    },
  },
  {
    name: 'read_file',
    description: 'Reads workspace text files within authorized project directories.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Relative workspace file path' },
      },
      required: ['path'],
      additionalProperties: false,
    },
  },
  {
    name: 'unregistered_diagnostic_tool',
    description: 'Unregistered diagnostic probe used to test TOOLSEAL REVIEW short-circuiting.',
    inputSchema: {
      type: 'object',
      properties: {
        target: { type: 'string', description: 'Diagnostic target' },
      },
      required: ['target'],
    },
  },
  {
    name: 'failing_upstream_tool',
    description: 'Always returns an upstream MCP execution error to test PostMCPHook error telemetry.',
    inputSchema: {
      type: 'object',
      properties: {
        reason: { type: 'string' },
      },
    },
  },
];

function send(msg) {
  process.stdout.write(`${JSON.stringify(msg)}\n`);
}

function handleRequest(req) {
  const { id, method, params } = req;

  if (method === 'initialize') {
    send({
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: '2024-11-05',
        capabilities: { tools: {} },
        serverInfo: { name: 'toolseal-mock-mcp', version: '1.0.0' },
      },
    });
    return;
  }

  if (method === 'notifications/initialized') {
    return;
  }

  if (method === 'ping') {
    send({ jsonrpc: '2.0', id, result: {} });
    return;
  }

  if (method === 'tools/list') {
    send({ jsonrpc: '2.0', id, result: { tools: TOOLS } });
    return;
  }

  if (method === 'tools/call') {
    const toolName = params?.name || '';
    const args = params?.arguments || {};

    if (toolName === 'get_weather') {
      const city = String(args.city || 'Mumbai');
      const units = args.units === 'imperial' ? 'F' : 'C';
      send({
        jsonrpc: '2.0',
        id,
        result: {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                city,
                temperature: units === 'F' ? 84 : 29,
                unit: units,
                condition: 'Partly Cloudy',
                source: 'toolseal-mock-mcp',
              }),
            },
          ],
          isError: false,
        },
      });
      return;
    }

    if (toolName === 'read_file') {
      send({
        jsonrpc: '2.0',
        id,
        result: {
          content: [
            {
              type: 'text',
              text: `Mock file read for ${String(args.path || '')}`,
            },
          ],
          isError: false,
        },
      });
      return;
    }

    if (toolName === 'failing_upstream_tool') {
      send({
        jsonrpc: '2.0',
        id,
        result: {
          content: [
            {
              type: 'text',
              text: `Upstream MCP execution failure: ${String(args.reason || 'simulated fault')}`,
            },
          ],
          isError: true,
        },
      });
      return;
    }

    send({
      jsonrpc: '2.0',
      id,
      error: {
        code: -32601,
        message: `Unknown tool: ${toolName}`,
      },
    });
    return;
  }

  if (id !== undefined && id !== null) {
    send({
      jsonrpc: '2.0',
      id,
      error: {
        code: -32601,
        message: `Method not found: ${method}`,
      },
    });
  }
}

const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on('line', (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;
  try {
    const parsed = JSON.parse(trimmed);
    handleRequest(parsed);
  } catch (err) {
    process.stderr.write(`Mock MCP JSON parse error: ${err instanceof Error ? err.message : String(err)}\n`);
  }
});
