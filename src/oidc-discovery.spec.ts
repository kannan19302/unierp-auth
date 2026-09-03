import { describe, expect, it, vi } from "vitest";
import {
  assertSafePublicHostname,
  discoverOidcConfiguration,
  isNonPublicIp,
  requirePublicHttpsUrl,
  testOidcConnection,
  testSamlConfiguration,
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

describe("SAML configuration preflight", () => {
  const validCert = `-----BEGIN CERTIFICATE-----
MIIDLTCCAhWgAwIBAgIQROnKm3pfgIdJRQugR1HBbTANBgkqhkiG9w0BAQsFADAb
MRkwFwYDVQQDDBBpZHAuZXhhbXBsZS50ZXN0MB4XDTI2MDkwMzAyNDUzNVoXDTI3
MDkwMzAzMDUzNVowGzEZMBcGA1UEAwwQaWRwLmV4YW1wbGUudGVzdDCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAOlW7lDKceAX4ZYub9rCmzWGHwQ1g5QA
HY7iVRsD2lDtp4Mb+I3HwNpVTNw3FSYlNR2KZxQFbWjWsjlEDC8PHt/8d2YqCApt
+0zqJ9hBLoLiWUUxExXWFLcIa1rnHIyMNHy7dFO1Bpzkaj/I+0crbgIJU21jw+Pe
pBFg1EUmEAxpWyRz3iug+jBDj2xVQL8VU1mXEnj1HheATrzKytAZOF/w+XORBpz5
4+LsI+IuuuFqFYJjR2sA1uyY7iF1hIm9KqcNF6+Xqt5yDv89+eY7g53AcO3ZVp3+
fxtKX5hdL5OKU3X1M5Wt+Dwa3++5T/VfJmaScjcMluEV08oPW/sIwk0CAwEAAaNt
MGswDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcD
ATAbBgNVHREEFDASghBpZHAuZXhhbXBsZS50ZXN0MB0GA1UdDgQWBBQIHhW25wVo
IpEZmRTGLHltlilhvzANBgkqhkiG9w0BAQsFAAOCAQEAv6ZJaJS4d3k6tsQ2K5TR
3+GTpD+766uRaEqEBeW6lT1GnNde+PDk5GGWfmw070/PKxQwytx8JFmi69qtSzLQ
oSRNkBOWjPTwEoxvrj9ZIpf9y3jGkoKH3A3pNcVkU8Whs5YNoUqg+ubjASI2amT6
N4uaOsWvIj3lByAVBmgHjDFhah7Y9Kjw3OOmnUxkufW9CmB6l0pmLpo36aDLU3xw
7cgDFrzk3PNIz7BEfwS9H/ZC9qGly/G50aP69pzmPC9Ewxnw15sH/+GcBVad9F5w
glWNiYE/RdpeIY4NLgCdai76DRZndOdZ6azbsvVNoeaMwM6dd8zyknyLmVrH0W0B
og==
-----END CERTIFICATE-----`;

  it("validates a public HTTPS SAML entry point and active X.509 certificate", () => {
    const evidence = testSamlConfiguration({
      samlEntryPoint: "https://idp.example.test/sso/saml",
      samlCert: validCert,
      samlIssuer: "unierp-test-tenant",
    });

    expect(evidence.entryPoint).toBe("https://idp.example.test/sso/saml");
    expect(evidence.issuer).toBe("unierp-test-tenant");
    expect(evidence.certificateSubject).toContain("idp.example.test");
    expect(evidence.keyAlgorithm).toBe("rsa");
    expect(evidence.fingerprint256).toBeDefined();
  });

  it("rejects insecure or non-public SAML entry points", () => {
    expect(() =>
      testSamlConfiguration({
        samlEntryPoint: "http://idp.example.test/sso",
        samlCert: validCert,
      }),
    ).toThrow(/public HTTPS URL/);

    expect(() =>
      testSamlConfiguration({
        samlEntryPoint: "https://127.0.0.1/sso",
        samlCert: validCert,
      }),
    ).toThrow(/public HTTPS URL/);

    expect(() =>
      testSamlConfiguration({
        samlEntryPoint: "https://169.254.169.254/sso",
        samlCert: validCert,
      }),
    ).toThrow(/public HTTPS URL/);
  });

  it("rejects malformed or empty certificates", () => {
    expect(() =>
      testSamlConfiguration({
        samlEntryPoint: "https://idp.example.test/sso/saml",
        samlCert: "",
      }),
    ).toThrow(/certificate is required/);

    expect(() =>
      testSamlConfiguration({
        samlEntryPoint: "https://idp.example.test/sso/saml",
        samlCert: "not-a-valid-pem",
      }),
    ).toThrow(/invalid PEM/);
  });
});

describe("DNS rebinding and egress IP defense", () => {
  it("denies private and reserved IP literals immediately", async () => {
    await expect(assertSafePublicHostname("127.0.0.1")).rejects.toThrow(/private or non-public IP/);
    await expect(assertSafePublicHostname("10.0.0.1")).rejects.toThrow(/private or non-public IP/);
    await expect(assertSafePublicHostname("192.168.1.1")).rejects.toThrow(/private or non-public IP/);
    await expect(assertSafePublicHostname("169.254.169.254")).rejects.toThrow(/private or non-public IP/);
    await expect(assertSafePublicHostname("::1")).rejects.toThrow(/private or non-public IP/);
  });

  it("denies hostnames resolving to restricted addresses via DNS lookup", async () => {
    const fakeLookup = vi.fn().mockResolvedValue([
      { address: "169.254.169.254", family: 4 },
    ]);
    await expect(assertSafePublicHostname("metadata.evil.com", fakeLookup)).rejects.toThrow(
      /resolves to private\/restricted IP/,
    );
  });

  it("accepts hostnames resolving exclusively to public IP addresses", async () => {
    const fakeLookup = vi.fn().mockResolvedValue([
      { address: "93.184.216.34", family: 4 },
    ]);
    await expect(assertSafePublicHostname("example.com", fakeLookup)).resolves.toBeUndefined();
  });
});

