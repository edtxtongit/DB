import { DurableObject } from "cloudflare:workers";
import { connect } from 'cloudflare:sockets';

// --- Durable Object 类定义 ---
export class ProxyDurableObject extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.env = env;
  }

  async fetch(req) {
    const ID_BYTES = new Uint8Array([
      0xef, 0x9d, 0x10, 0x4e, 0xca, 0x0e, 0x42, 0x02,
      0xba, 0x4b, 0xa0, 0xaf, 0xb9, 0x69, 0xc7, 0x47
    ]);

  
    if (req.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
      const [client, ws] = Object.values(new WebSocketPair());
      ws.accept();

      const u = new URL(req.url);


      if (u.pathname.includes('%3F')) {
        const decoded = decodeURIComponent(u.pathname);
        const queryIndex = decoded.indexOf('?');
        if (queryIndex !== -1) {
          u.search = decoded.substring(queryIndex);
          u.pathname = decoded.substring(0, queryIndex);
        }
      }

      const mode = u.searchParams.get('mode') || 'auto';
      const s5Param = u.searchParams.get('s5');
      const httpParam = u.searchParams.get('http');
      const proxyParam = u.searchParams.get('proxyip');


      const parseConfig = (path) => {
        let user, pass, host, port;
        if (path.includes('@')) {
          const [cred, server] = path.split('@');
          [user, pass] = cred.split(':');
          [host, port] = server.split(':');
        } else if (path.includes(':')) {
          [host, port] = path.split(':');
        }
        return { user, pass, host, port: +port };
      };

      const PROXY_IP = proxyParam ? String(proxyParam) : null;

      const getOrder = () => {
        if (mode === 'proxy') return ['direct', 'proxy'];
        if (mode !== 'auto') return [mode];
        const order = [];
        const searchStr = u.search.slice(1);
        for (const pair of searchStr.split('&')) {
          const key = pair.split('=')[0];
          if (key === 'direct') order.push('direct');
          else if (key === 's5') order.push('s5');
          else if (key === 'proxyip') order.push('proxy');
          else if (key === 'http') order.push('http');
        }
        return order.length ? order : ['direct'];
      };

      let remote = null;
      let udpWriter = null;
      let w = null;
      let addr = null;
      let isDNS = false;

      const socks5Connect = async (targetHost, targetPort) => {
        const config = parseConfig(s5Param);
        const sock = connect({ hostname: config.host, port: config.port });
        await sock.opened;
        const w = sock.writable.getWriter();
        const r = sock.readable.getReader();

        await w.write(new Uint8Array([5, 2, 0, 2]));
        const auth = (await r.read()).value;

        if (auth[1] === 2 && config.user) {
          const user = new TextEncoder().encode(config.user);
          const pass = new TextEncoder().encode(config.pass);
          await w.write(new Uint8Array([1, user.length, ...user, pass.length, ...pass]));
          await r.read();
        }

        const domain = new TextEncoder().encode(targetHost);
        await w.write(new Uint8Array([5, 1, 0, 3, domain.length, ...domain, targetPort >> 8, targetPort & 0xff]));
        await r.read();
        w.releaseLock();
        r.releaseLock();
        return sock;
      };

      async function httpConnect(targetAddr, targetPort) {
        const config = parseConfig(httpParam);
        const sock = connect({ hostname: config.host, port: config.port });
        await sock.opened;
        const writer = sock.writable.getWriter();
        const reader = sock.readable.getReader();

        try {
          const lines = [`CONNECT ${targetAddr}:${targetPort} HTTP/1.1`, `Host: ${targetAddr}:${targetPort}`];
          if (config.user && config.pass) {
            const auth = btoa(`${config.user}:${config.pass}`);
            lines.push(`Proxy-Authorization: Basic ${auth}`);
          }
          await writer.write(new TextEncoder().encode(lines.join('\r\n') + '\r\n\r\n'));

          let buffer = '';
          while (true) {
            const { done, value } = await reader.read();
            if (done) throw new Error('Proxy closed');
            buffer += new TextDecoder().decode(value);
            if (buffer.indexOf('\r\n\r\n') !== -1) break;
          }
          writer.releaseLock();
          reader.releaseLock();
          return sock;
        } catch (e) {
          sock.close();
          throw e;
        }
      }

      ws.addEventListener('close', () => { try { ws.close(); remote?.close(); } catch { } });

      new ReadableStream({
        start(ctrl) {
          ws.addEventListener('message', e => ctrl.enqueue(e.data));
          const early = req.headers.get('sec-websocket-protocol');
          if (early) {
            try {
              ctrl.enqueue(Uint8Array.from(atob(early.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)).buffer);
            } catch { }
          }
        }
      }).pipeTo(new WritableStream({
        async write(data) {
          if (isDNS) return udpWriter?.write(data);
          if (remote) {
            try { await w.write(data); } catch { ws.close(); }
            return;
          }
          if (data.byteLength < 24) return;
          const recvID = new Uint8Array(data, 1, 16);
          for (let i = 0; i < 9; i++) { if (recvID[i] !== ID_BYTES[i]) return; }

          const view = new DataView(data);
          const optLen = view.getUint8(17);
          const cmd = view.getUint8(18 + optLen);
          if (cmd !== 1 && cmd !== 2) return;

          let pos = 19 + optLen;
          const port = view.getUint16(pos);
          const type = view.getUint8(pos + 2);
          pos += 3;

          if (type === 1) {
            addr = `${view.getUint8(pos)}.${view.getUint8(pos + 1)}.${view.getUint8(pos + 2)}.${view.getUint8(pos + 3)}`;
            pos += 4;
          } else if (type === 2) {
            const len = view.getUint8(pos++);
            addr = new TextDecoder().decode(data.slice(pos, pos + len));
            pos += len;
          } else if (type === 3) {
            const ipv6 = [];
            for (let i = 0; i < 8; i++, pos += 2) ipv6.push(view.getUint16(pos).toString(16));
            addr = `[${ipv6.join(':')}]`;
          } else return;

          const header = new Uint8Array([data[0], 0]);
          const payload = data.slice(pos);

          if (cmd === 2) {
            if (port !== 53) return;
            isDNS = true;
            const { readable, writable } = new TransformStream({
              transform(chunk, ctrl) {
                for (let i = 0; i < chunk.byteLength;) {
                  const len = new DataView(chunk.slice(i, i + 2)).getUint16(0);
                  ctrl.enqueue(chunk.slice(i + 2, i + 2 + len));
                  i += 2 + len;
                }
              }
            });
            readable.pipeTo(new WritableStream({
              async write(query) {
                try {
                  const resp = await fetch('https://1.1.1.1/dns-query', {
                    method: 'POST',
                    headers: { 'content-type': 'application/dns-message' },
                    body: query
                  });
                  if (ws.readyState === 1) {
                    const result = new Uint8Array(await resp.arrayBuffer());
                    ws.send(new Uint8Array([...header, result.length >> 8, result.length & 0xff, ...result]));
                  }
                } catch { }
              }
            }));
            udpWriter = writable.getWriter();
            return udpWriter.write(payload);
          }

          let sock = null;
          for (const method of getOrder()) {
            try {
              if (method === 'direct') {
                sock = connect({ hostname: addr, port });
                await sock.opened;
                break;
              } else if (method === 's5' && s5Param) {
                sock = await socks5Connect(addr, port);
                break;
              } else if (method === 'proxy' && PROXY_IP) {
                const [ph, pp] = PROXY_IP.split(':');
                sock = connect({ hostname: ph, port: +(pp || port) });
                await sock.opened;
                break;
              } else if (method === 'http' && httpParam) {
                sock = await httpConnect(addr, port);
                break;
              }
            } catch { }
          }

          if (!sock) return;
          remote = sock;
          w = sock.writable.getWriter();
          await w.write(payload);

          (async () => {
            const MAX = 16 * 1024;
            let buffer = new ArrayBuffer(MAX);
            const reader = sock.readable.getReader({ mode: 'byob' });
            let sent = false;
            try {
              while (true) {
                const { value, done } = await reader.read(new Uint8Array(buffer));
                if (done) break;
                buffer = value.buffer;
                if (!sent) { ws.send(header); sent = true; }
                ws.send(value.slice());
              }
            } catch { ws.close(); }
          })();
        }
      }));

      return new Response(null, { status: 101, webSocket: client });
    }

    return new Response("Not a WebSocket request", { status: 400 });
  }
}

// --- Worker 入口 ---
export default {
  async fetch(request, env) {
    // 获取当前请求进入的机房代码，例如 "HKG" (香港), "SIN" (新加坡)
    const colo = request.cf.colo || "global-proxya";
    const id = env.PROXY_DO.idFromName(`${colo}`);
    const stub = env.PROXY_DO.get(id);
    
    // 直接转发请求给 Durable Object
    return stub.fetch(request);
  },
};
