// Raw TCP fixture ingress: preserve the candidate gateway's TLS and HTTP behavior.
import net from 'node:net'
const server = net.createServer(client => {
  const upstream = net.connect(8443, 'public-gateway')
  client.setTimeout(60000, () => client.destroy())
  upstream.setTimeout(60000, () => upstream.destroy())
  client.pipe(upstream).pipe(client)
  client.on('error', () => upstream.destroy())
  upstream.on('error', () => client.destroy())
  client.on('close', () => upstream.destroy())
  upstream.on('close', () => client.destroy())
})
server.listen(443, '0.0.0.0')
process.on('SIGTERM', () => server.close())
