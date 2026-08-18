import type { Redis } from "ioredis";
import { env } from "../../../env";
import { logger } from "../../logger";
import { AzureManagedIdentityCredentialProvider } from "./azureManagedIdentity";
import { RefreshingTokenManager } from "./RefreshingTokenManager";
import type { ManagedAccessToken, ManagedCredentialProvider } from "./types";

// Returns null for the default static auth, leaving the existing path unchanged.
export function getRedisManagedCredentialProviderFromEnv(): ManagedCredentialProvider | null {
  switch (env.REDIS_AUTH_METHOD) {
    case "azure_managed_identity":
      return new AzureManagedIdentityCredentialProvider({
        scope: env.REDIS_AZURE_SCOPE,
        username: env.REDIS_USERNAME ?? undefined,
        clientId: env.REDIS_AZURE_CLIENT_ID ?? undefined,
      });
    case "static":
    default:
      return null;
  }
}

// ioredis v5 has no credentials hook, so the binding wraps connect() to fetch
// and apply the first token before the socket opens, then issues a live AUTH on
// each later refresh and keeps options.password fresh for reconnects. The caller
// uses lazyConnect so nothing connects until this wrapper runs; ioredis routes
// both explicit connect() and command-triggered auto-connect through connect(),
// which closes the race with callers like BullMQ that connect on their own.
//
// duplicate() is wrapped for the same reason. ioredis implements it as
// `new Redis({ ...this.options })`, so a copy inherits neither this wrapper nor
// the refresh subscription, and carries a by-value snapshot of the password.
// BullMQ builds its blocking connection that way, so without this a worker
// authenticates once and is never renewed: at the first token expiry the server
// drops it, the reconnect replays a stale password, and job consumption stops
// while producers keep enqueuing successfully. Copies share the manager, so one
// token still serves every connection.
export function bindManagedCredentialToRedis(
  client: Redis,
  provider: ManagedCredentialProvider,
  deps: { manager?: RefreshingTokenManager } = {},
): RefreshingTokenManager {
  const manager = deps.manager ?? new RefreshingTokenManager(provider);

  const applyToken = (token: ManagedAccessToken) => {
    client.options.password = token.token;
    if (provider.username) client.options.username = provider.username;
  };

  const unsubscribe = manager.onRefresh((token) => {
    applyToken(token);
    const authArgs = provider.username
      ? [provider.username, token.token]
      : [token.token];
    client
      .call("AUTH", ...authArgs)
      .catch((error) =>
        logger.warn(
          `Failed to re-authenticate Redis after ${provider.name} token refresh`,
          error,
        ),
      );
  });

  // Drop the subscription once the connection is closed for good, so a process
  // that churns connections does not accumulate listeners AUTHing dead sockets.
  client.once("end", unsubscribe);

  const connect = client.connect.bind(client);
  let bootstrap: Promise<void> | null = null;
  client.connect = ((...args: Parameters<Redis["connect"]>) => {
    if (!bootstrap) {
      bootstrap = manager
        .ensureStarted()
        .then(applyToken)
        .catch((error) => {
          bootstrap = null; // let the next connect attempt retry the token fetch
          logger.error(
            `Failed to fetch initial ${provider.name} token for Redis`,
            error,
          );
          throw error;
        });
    }
    return bootstrap.then(() => connect(...args));
  }) as Redis["connect"];

  const duplicate = client.duplicate.bind(client);
  client.duplicate = ((...args: Parameters<Redis["duplicate"]>) => {
    const copy = duplicate(...args);
    bindManagedCredentialToRedis(copy, provider, { manager });
    return copy;
  }) as Redis["duplicate"];

  return manager;
}
