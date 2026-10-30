import type { Server } from '../../src/model'

// Records created before the rename have no namespace. Keep managing their
// existing services instead of installing a second, conflicting VPN stack.
export function resourceNamespace(server: Pick<Server, 'resourceNamespace'>): 'manetka' | 'monetka' {
  return server.resourceNamespace === 'manetka' ? 'manetka' : 'monetka'
}
