import { useEffect, useRef, useState } from 'react';
import { getClientSessionToken } from '../lib/api';
import type { WsBroadcastMessage } from '../types/toolseal';

export type WsConnectionState = 'connecting' | 'connected' | 'reconnecting' | 'disconnected';

export function useWebSocket(onEvent: (msg: WsBroadcastMessage) => void, enabled = true) {
  const [status, setStatus] = useState<WsConnectionState>(enabled ? 'connecting' : 'disconnected');
  const handlerRef = useRef(onEvent);
  handlerRef.current = onEvent;

  useEffect(() => {
    if (!enabled) {
      setStatus('disconnected');
      return;
    }

    let ws: WebSocket | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let disposed = false;

    setStatus('connecting');

    function connect() {
      if (disposed) return;
      const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const url = `${proto}//${window.location.host}/ws`;
      const token = getClientSessionToken();

      ws = token ? new WebSocket(url, ['toolseal-ws', `toolseal-bearer.${token}`]) : new WebSocket(url);

      ws.onopen = () => {
        if (!disposed) setStatus('connected');
      };

      ws.onmessage = (event) => {
        try {
          const parsed = JSON.parse(event.data) as WsBroadcastMessage;
          handlerRef.current(parsed);
        } catch {
          // Ignore malformed frame
        }
      };

      ws.onclose = (ev) => {
        if (disposed) return;
        if (ev.code === 1008) {
          setStatus('disconnected');
          return;
        }
        setStatus('reconnecting');
        reconnectTimer = setTimeout(connect, 2500);
      };

      ws.onerror = () => {
        ws?.close();
      };
    }

    connect();

    return () => {
      disposed = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      ws?.close();
    };
  }, [enabled]);

  return status;
}
