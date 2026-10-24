import express from 'express';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import { randomBytes, createHash } from 'crypto'
import { SignJWT, createRemoteJWKSet, importPKCS8, jwtVerify } from 'jose';

const app = express();

app.use(express.json());

const ISSUER = "http://localhost:3000";
const AUDIENCE = "demo-client";

const JWKS_URL = new URL("http://localhost:3000/.well-known/jwks.json")

const JWK = createRemoteJWKSet(JWKS_URL)

async function requireAuthorization(req, res, next) {

    console.log("\n \n \n", JWK, "\n \n \n")

    const auth = req?.headers?.authorization

    if (!auth || !auth.startsWith("Bearer ")) return res.status(401).send("access token required")

    const accessToken = auth.slice("Bearer ".length);
    try {
        const { payload } = await jwtVerify(accessToken, JWK, {
            issuer: ISSUER,
            audience: AUDIENCE
        })
        console.log(payload)
        req.user = payload

        next()
    } catch (error) {
    console.error("JWT verification failed:", error.message);
    console.error("Underlying cause:", error.cause);
    console.error("Error code:", error.cause?.code);

    return res.status(401).json({
        error: "invalid token",
        message: error.message
    });
    }

}

function requiredScope(scope) {
    return function (req, res, next) {
        const scopes = String(req?.user?.scope || "").split(" ").filter(Boolean);

        if (!scopes.includes(scope)) return res.status(403).json({ message: "invalid scope" })

        next()
    }
}

app.get("/api/profile/", requireAuthorization, requiredScope("api.read"), (req, res) => {
    return res.status(200).json({
        message: "protected profile data",
        user: {
            name: req?.user?.name,
            scope: req?.user?.scope,
            email: req?.user?.email,
        }
    });
})

app.listen(5000, () => { console.log("server running in port 5000") })