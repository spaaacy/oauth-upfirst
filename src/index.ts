import express, { Request, Response } from "express";
import { jwtVerify, SignJWT } from "jose";

const app = express();
// For URL encoded body
app.use(express.urlencoded({ extended: true }));

// Hard-coded to avoid using extra (crypto) deps
const secret = "99aeee4d07fc8698eafe377a79b2c95e54b9f7a4d430d801fa133093d68eda60";
const port = 8080;
const alg = "HS256";

const approvedApplications: Record<string, { redirectUri: string }> = {
  upfirst: {
    redirectUri: "http://localhost:8081/process",
  },
};

app.get("/api/oauth/authorize", async (req: Request, res: Response) => {
  const { response_type, client_id, redirect_uri, state } = req.query;
  const clientId = client_id as string;

  if (!approvedApplications[clientId]) return res.status(400).json({ error: "Invalid client_id" });
  if (approvedApplications[clientId].redirectUri !== redirect_uri)
    return res.status(400).json({ error: "Invalid redirect_uri" });
  if (response_type !== "code") return res.status(400).json({ error: "Invalid response_type" });

  const jwt = await new SignJWT({ clientId: client_id, redirectUri: redirect_uri })
    .setProtectedHeader({
      alg,
    })
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(Buffer.from(secret));

  let redirectUrl = `${redirect_uri}?code=${jwt}`;
  if (state) {
    redirectUrl += `&state=${encodeURIComponent(state as string)}`;
  }

  res.redirect(302, redirectUrl);
});

app.post("/api/oauth/token", async (req: Request, res: Response) => {
  const { grant_type, code, client_id, redirect_uri, refresh_token } = req.body;

  // Authorization Code
  if (grant_type === "authorization_code") {
    if (!client_id || !approvedApplications[client_id]) return res.status(400).json({ error: "Invalid client_id" });
    if (approvedApplications[client_id].redirectUri !== redirect_uri)
      return res.status(400).json({ error: "Invalid redirect_uri" });

    try {
      const { payload } = await jwtVerify(code as string, Buffer.from(secret));
      if (payload.clientId !== client_id || payload.redirectUri !== redirect_uri)
        return res.status(400).json({ error: "Invalid authorization code" });

      const accessToken = await new SignJWT({ clientId: client_id })
        .setProtectedHeader({
          alg,
        })
        .setIssuedAt()
        .setExpirationTime("1h")
        .sign(Buffer.from(secret));

      const refreshToken = await new SignJWT({ clientId: client_id })
        .setProtectedHeader({
          alg,
        })
        .setIssuedAt()
        .setExpirationTime("30d")
        .sign(Buffer.from(secret));

      return res.json({
        access_token: accessToken,
        refresh_token: refreshToken,
        token_type: "bearer",
        expires_in: 3600,
      });
    } catch {
      return res.status(400).json({ error: "Authorization code expired/invalid" });
    }
  }

  // Refresh Token
  if (grant_type === "refresh_token") {
    if (!refresh_token) return res.status(400).json({ error: "Missing refresh_token" });

    try {
      const { payload } = await jwtVerify(refresh_token as string, Buffer.from(secret));

      if (payload.clientId !== client_id || !approvedApplications[client_id]) {
        return res.status(400).json({ error: "Invalid refresh_token" });
      }

      const accessToken = await new SignJWT({ clientId: client_id })
        .setProtectedHeader({
          alg,
        })
        .setIssuedAt()
        .setExpirationTime("1h")
        .sign(Buffer.from(secret));

      const newRefreshToken = await new SignJWT({ clientId: client_id })
        .setProtectedHeader({
          alg,
        })
        .setIssuedAt()
        .setExpirationTime("30d")
        .sign(Buffer.from(secret));

      return res.json({
        access_token: accessToken,
        refresh_token: newRefreshToken,
        token_type: "bearer",
        expires_in: 3600,
      });
    } catch {
      return res.status(400).json({ error: "Invalid or expired refresh token" });
    }
  }

  // Invalid Grant Type
  return res.status(400).json({ error: "Invalid grant_type" });
});

app.listen(port, () => {
  console.log("Server listening at port 8080...");
});
