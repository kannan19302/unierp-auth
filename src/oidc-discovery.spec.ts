import { describe, expect, it, vi } from "vitest";
import {
  discoverOidcConfiguration,
  requirePublicHttpsUrl,
  testOidcConnection,
  type FederationFetch,
} from "./oidc-discovery";

const issuer = "https://login.example.test/tenant-a";
const discovery = {
  issuer,
  authorization_endpoint: "https://login.example.test/authorize",
  token_endpoint: "https://login.example.test/token",
  jwks_uri: "https://keys.example.test/jwks",
  id_token_signing_alg_values_supported: ["RS256", "none"],
};

function jsonResponse(value: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: new Headers({ "content-type": "application/json" }),
    text: vi.fn().mockResolvedValue(JSON.stringify(value)),
  } as unknown as Response;
}

describe("OIDC discovery trust boundary", () => {
  it.each([
    "http://login.example.test",
    "https://user:password@login.example.test",
    "https://localhost",
    "https://127.0.0.1",
    "https://169.254.169.254/metadata",
    "https://10.0.0.1",
    "https://[::1]",
    "https://[fc00::1]",
    "https://[::ffff:127.0.0.1]",
    "https://192.0.2.1",
    "https://198.51.100.1",
    "https://203.0.113.1",
    "https://metadata.google.internal",
  ])("rejects non-public issuer %s", (value) => {
    expect(() => requirePublicHttpsUrl(value, "OIDC issuer")).toThrow(/public HTTPS/);
  });

  it("uses exact issuer metadata, blocks redirects and filters symmetric/none algorithms", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse(discovery)) as FederationFetch;
    await expect(discoverOidcConfiguration(issuer, fetchImpl)).resolves.toMatchObject({
      issuer,
      id_token_signing_alg_values_supported: ["RS256"],
    });
    expect(fetchImpl).toHaveBeenCalledWith(
      new URL(`${issuer}/.well-known/openid-configuration`),
      expect.objectContaining({ redirect: "error" }),
    );
  });

  it("rejects issuer mismatch, unsafe discovered endpoints and missing asymmetric algorithms", async () => {
    for (const metadata of [
      { ...discovery, issuer: "https://attacker.example.test" },
      { ...discovery, token_endpoint: "https://169.254.169.254/token" },
      { ...discovery, id_token_signing_alg_values_supported: ["none", "HS256"] },
    ]) {
      const fetchImpl = vi.fn().mockResolvedValue(jsonResponse(metadata)) as FederationFetch;
      await expect(discoverOidcConfiguration(issuer, fetchImpl)).rejects.toThrow();
    }
  });

  it("tests JWKS reachability and accepts current plus previous rotation keys", async () => {
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(jsonResponse(discovery))
      .mockResolvedValueOnce(jsonResponse({
        keys: [
          { kty: "RSA", kid: "current", use: "sig", alg: "RS256", n: "synthetic", e: "AQAB" },
          { kty: "RSA", kid: "previous", use: "sig", alg: "RS256", n: "synthetic", e: "AQAB" },
        ],
      })) as FederationFetch;
    await expect(testOidcConnection(issuer, fetchImpl)).resolves.toMatchObject({ signingKeyCount: 2 });
  });

  it("rejects a JWKS without a compatible identified signing key", async () => {
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(jsonResponse(discovery))
      .mockResolvedValueOnce(jsonResponse({ keys: [{ kty: "oct", kid: "symmetric", alg: "HS256" }] })) as FederationFetch;
    await expect(testOidcConnection(issuer, fetchImpl)).rejects.toThrow(/no compatible signing key/);
  });
});
