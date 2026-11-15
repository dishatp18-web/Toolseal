import { WebSocketServer, WebSocket } from 'ws';
import type { IncomingMessage, Server } from 'http';
import { extractSessionTokenFromWsRequest, resolveSessionUser } from '../auth/auth.ts';
import type { WsBroadcastMessage, WsEventType } from '../../types/toolseal.ts';

class ToolsealBroadcaster {
  private wss: WebSocketServer | null = null;
  private clients = new Set<WebSocket>();

  attach(server: Server) {
    if (this.wss) return;
    this.wss = new WebSocketServer({
      server,
      path: '/ws',
      handleProtocols: (protocols) => (protocols.has('toolseal-ws') ? 'toolseal-ws' : false),
    });

    this.wss.on('connection', (ws, req: IncomingMessage) => {
      const token = extractSessionTokenFromWsRequest(req.headers);
      const user = resolveSessionUser(token);
      if (!user) {
        ws.close(1008, 'Authentication required');
        return;
      }

      this.clients.add(ws);
      this.sendTo(ws, 'connected', {
        status: 'connected',
        clientCount: this.clients.size,
      });

      ws.on('close', () => {
        this.clients.delete(ws);
      });

      ws.on('error', () => {
        this.clients.delete(ws);
      });
    });
  }

  private sendTo<T>(ws: WebSocket, type: WsEventType, payload: T) {
    if (ws.readyState !== WebSocket.OPEN) return;
    const message: WsBroadcastMessage<T> = {
      type,
      payload,
      timestamp: new Date().toISOString(),
    };
    ws.send(JSON.stringify(message));
  }

  broadcast<T>(type: WsEventType, payload: T) {
    const message: WsBroadcastMessage<T> = {
      type,
      payload,
      timestamp: new Date().toISOString(),
    };
    const serialized = JSON.stringify(message);
    for (const client of this.clients) {
      if (client.readyState === WebSocket.OPEN) {
        client.send(serialized);
      }
    }
  }

  getClientCount(): number {
    return this.clients.size;
  }
}

export const broadcaster = new ToolsealBroadcaster();
