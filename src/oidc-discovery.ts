import { isIP } from "node:net";

export const OIDC_ALLOWED_SIGNING_ALGORITHMS = [
  "RS256", "RS384", "RS512",
  "ES256", "ES384", "ES512",
  "PS256", "PS384", "PS512",
] as const;

export interface OidcDiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  id_token_signing_alg_values_supported: string[];
}

export interface OidcConnectionEvidence {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksEndpoint: string;
  algorithms: string[];
  signingKeyCount: number;
}

export type FederationFetch = (input: URL | string, init?: RequestInit) => Promise<Response>;

const MAX_METADATA_BYTES = 1024 * 1024;

export function requirePublicHttpsUrl(value: string | null | undefined, label: string): URL {
  if (!value || value.length > 2048) throw new Error(`${label} must be a public HTTPS URL.`);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${label} must be a public HTTPS URL.`);
  }
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    host.endsWith(".internal") ||
    host === "metadata.google" ||
    isNonPublicIp(host)
  ) {
    throw new Error(`${label} must be a public HTTPS URL.`);
  }
  return url;
}

function isNonPublicIp(host: string): boolean {
  const version = isIP(host);
  if (version === 4) {
    const [a = 0, b = 0] = host.split(".").map(Number);
    return a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 0) ||
      (a === 192 && b === 168) ||
      (a === 198 && (b === 18 || b === 19 || b === 51)) ||
      (a === 203 && b === 0);
  }
  if (version === 6) {
    const normalized = host.toLowerCase();
    if (normalized === "::" || normalized === "::1") return true;
    if (/^(fc|fd)/.test(normalized) || /^fe[89ab]/.test(normalized)) return true;
    // URL canonicalization rewrites mapped dotted IPv4 addresses to hexadecimal.
    // Block the entire mapped range so that a loopback/private IPv4 target cannot
    // bypass the IPv4 checks through an IPv6 literal.
    if (normalized.startsWith("::ffff:")) return true;
    return false;
  }
  return false;
}

function normalizeIssuer(url: URL): string {
  return url.toString().replace(/\/$/, "");
}

async function readJsonObject(response: Response, label: string): Promise<Record<string, unknown>> {
  const declaredLength = Number(response.headers?.get?.("content-length") ?? 0);
  if (declaredLength > MAX_METADATA_BYTES) throw new Error(`${label} exceeds the allowed size.`);
  const text = await response.text();
  if (text.length === 0 || Buffer.byteLength(text, "utf8") > MAX_METADATA_BYTES) {
    throw new Error(`${label} is empty or exceeds the allowed size.`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(`${label} is not valid JSON.`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`${label} must be a JSON object.`);
  }
  return parsed as Record<string, unknown>;
}

export async function discoverOidcConfiguration(
  issuerValue: string | null | undefined,
  fetchImpl: FederationFetch = fetch,
): Promise<OidcDiscoveryDocument> {
  const issuer = requirePublicHttpsUrl(issuerValue, "OIDC issuer");
  const discoveryUrl = new URL(`${normalizeIssuer(issuer)}/.well-known/openid-configuration`);
  const response = await fetchImpl(discoveryUrl, {
    redirect: "error",
    signal: AbortSignal.timeout(10_000),
    headers: { Accept: "application/json" },
  });
  if (!response.ok) throw new Error(`OIDC discovery failed with status ${response.status}.`);
  const raw = await readJsonObject(response, "OIDC discovery metadata");
  if (raw.issuer !== normalizeIssuer(issuer)) throw new Error("OIDC discovery issuer does not match the configured issuer.");
  const authorization = requirePublicHttpsUrl(String(raw.authorization_endpoint ?? ""), "OIDC authorization endpoint");
  const token = requirePublicHttpsUrl(String(raw.token_endpoint ?? ""), "OIDC token endpoint");
  const jwks = requirePublicHttpsUrl(String(raw.jwks_uri ?? ""), "OIDC JWKS endpoint");
  const advertised = Array.isArray(raw.id_token_signing_alg_values_supported)
    ? raw.id_token_signing_alg_values_supported.filter((value): value is string => typeof value === "string")
    : [];
  const algorithms = advertised.filter((value) => (OIDC_ALLOWED_SIGNING_ALGORITHMS as readonly string[]).includes(value));
  if (algorithms.length === 0) throw new Error("OIDC provider advertises no allowed asymmetric ID-token algorithm.");
  return {
    issuer: String(raw.issuer),
    authorization_endpoint: authorization.toString(),
    token_endpoint: token.toString(),
    jwks_uri: jwks.toString(),
    id_token_signing_alg_values_supported: algorithms,
  };
}

export async function testOidcConnection(
  issuerValue: string | null | undefined,
  fetchImpl: FederationFetch = fetch,
): Promise<OidcConnectionEvidence> {
  const discovery = await discoverOidcConfiguration(issuerValue, fetchImpl);
  const response = await fetchImpl(new URL(discovery.jwks_uri), {
    redirect: "error",
    signal: AbortSignal.timeout(10_000),
    headers: { Accept: "application/json" },
  });
  if (!response.ok) throw new Error(`OIDC JWKS request failed with status ${response.status}.`);
  const raw = await readJsonObject(response, "OIDC JWKS document");
  const keys = Array.isArray(raw.keys) ? raw.keys : [];
  const signingKeys = keys.filter((candidate) => {
    if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) return false;
    const key = candidate as Record<string, unknown>;
    const algorithmAllowed = key.alg === undefined ||
      (typeof key.alg === "string" && discovery.id_token_signing_alg_values_supported.includes(key.alg));
    return (key.kty === "RSA" || key.kty === "EC") &&
      (key.use === undefined || key.use === "sig") &&
      typeof key.kid === "string" && key.kid.length > 0 && algorithmAllowed;
  });
  if (signingKeys.length === 0) throw new Error("OIDC JWKS contains no compatible signing key with a key ID.");
  return {
    issuer: discovery.issuer,
    authorizationEndpoint: discovery.authorization_endpoint,
    tokenEndpoint: discovery.token_endpoint,
    jwksEndpoint: discovery.jwks_uri,
    algorithms: discovery.id_token_signing_alg_values_supported,
    signingKeyCount: signingKeys.length,
  };
}
