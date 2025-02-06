import express, { Request, Response } from "express";
import { SignJWT } from "jose";

const app = express();

// Hard-coded to avoid using extra (crypto) deps
const secret = "99aeee4d07fc8698eafe377a79b2c95e54b9f7a4d430d801fa133093d68eda60";

const alg = "HS256";

const approvedApplications: Record<string, { redirectUri: string }> = {
  upfirst: {
    redirectUri: "http://localhost:8081/process",
  },
};

app.get("/api/oauth/authorize", async (req: Request, res: Response) => {
  const { response_type, client_id, redirect_uri } = req.query;
  const clientId = client_id as string;

  console.log(clientId);

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
  res.redirect(`${redirect_uri}?code=${jwt}`);
});

app.post("/api/oauth/token", () => {});

app.listen(8080, () => {
  console.log("Server started...");
});
