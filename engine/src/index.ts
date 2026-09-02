// Bootstrap: build the Fastify app and start listening.
import { buildServer } from './server.js'
import { config } from './config.js'
import { startScheduler } from './scheduler.js'

const app = await buildServer()

startScheduler(app.log)

try {
  await app.listen({ port: config.PORT, host: config.HOST })
} catch (err) {
  app.log.error(err)
  process.exit(1)
}
