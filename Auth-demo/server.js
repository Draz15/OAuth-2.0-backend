import express from 'express';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import { randomBytes, createHash, createPrivateKey, createPublicKey } from 'crypto'
import { SignJWT, exportJWK, importPKCS8 } from 'jose';
import dotenv from 'dotenv';
import { readFileSync } from 'fs';

const app = express();

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
dotenv.config();


const clients = new Map();
const refreshTokens = new Map();
const authorizationCodes = new Map();

clients.set("demo-client", {
    client_id: "demo-client",
    redirectUris: ["http://localhost:4000/callback"]
});

const ISSUER = "http://localhost:3000";
const KEY_ID = "demo-key-1";

//////// load the private && public keys 

const PRIVATE_KEY_PEM = readFileSync("./private.pem", "utf-8")
const PUBLIC_KEY_PEM = readFileSync("./public.pem", "utf-8")

function sha256BaseUrl(str) {
    const hash = createHash("sha256").update(str).digest();
    return hash.toString("base64url")
}


function generateCode() {
    const code = randomBytes(32).toString("base64url")
    return code
}

function getDemoUser() {
    return { sub: "josef", name: "yousef Draz", email: "draz@gmail.com" }
}

// authorize route section

app.get('/authorize', (req, res) => {

    const { response_type, client_id, oidc_nonce, state, redirect_uri, scope = "", code_challenge, code_challenge_method } = req.query

    // validation section 
    const client = clients.get(client_id)

    if (!client) return res.status(401).send("unknown client id!!!!!!");
    if (!client.redirectUris.includes(redirect_uri)) return res.status(400).send("wrong uri");
    if (response_type != "code") return res.status(401).send("wrong response type");
    if (!code_challenge || code_challenge_method != "S256") return res.status(401).send("PKCE required : must provide code_challenge");
    if (!scope.includes("openid")) return res.status(400).send("the scope must contains openid")
    if (!oidc_nonce) return res.status.send("not authorized open id connect")

    // Normally : show login + consent UI 
    // For tutorial simplicity : auto-login + auto-consent

    const user = getDemoUser()

    const code = generateCode()

    authorizationCodes.set(code, {
        clientId: client_id,
        redirectUri: redirect_uri,
        code_challenge,
        scope,
        user,
        oidc_nonce,
        expiresIn: Date.now() + 5 * 60 * 1000
    })

    const redirect = new URL(redirect_uri)

    redirect.searchParams.set("code", code)
    if (state) redirect.searchParams.set("state", state)

    res.redirect(redirect.toString())

})
/* 
    token issuing route section
    supports
       - grant_type= authorization_code
       - grant_type= refresh_token

 */

app.post("/token", async (req, res) => {
    const { grant_type } = req.body;

    // create JWT  access_token 
    const privateKey = await importPKCS8(PRIVATE_KEY_PEM, "RS256")

    if (grant_type === "authorization_code") {
        const {
            code,
            redirect_uri,
            client_id,
            code_verifier
        } = req.body;

        const record = authorizationCodes.get(code)

        const scopes = String(record?.scope || "").split(" ").filter(Boolean);

        let oidc_id;

        if (scopes.includes("openid")) {
            if (!record?. oidc_nonce) return res.status(400).send("openid is not defined")

            oidc_id = await new SignJWT({
                name: record?.user?.name,
                email:record?.user?.email,
                nonce:record?.oidc_nonce
            }
            )
            .setProtectedHeader({alg: "RS256", kid: KEY_ID })
            .setAudience(client_id)
            .setIssuer(ISSUER)
            .setSubject(String(record.user.sub))
            .setIssuedAt()
            .setExpirationTime("15m")
            .sign(privateKey);
            
        }

        // check if the send code is exist in the authorizationCodes 
        if (!record) return res.status(401).send("not authorized code")

        // check if the code expires or not 
        if (record.expiresIn < Date.now()) {
            // delete the expired code 
            authorizationCodes.delete(code)
            return res.status(401).send("expired code")
        }

        // check if the user_id sended exist in the record  
        if (record.clientId != client_id || record.redirectUri != redirect_uri) return res.status(403).send("not existing user")


        // PKCE Validation 

        const codeChallenge = sha256BaseUrl(code_verifier)
        if (codeChallenge != record.code_challenge) return res.status(403).send("forbidden user");

        // one time use code 
        authorizationCodes.delete(code)

        const accessToken = await new SignJWT({
            scope: record.scope,
            name: record.user.name,
            email: record.user.email
        })
            .setProtectedHeader({ alg: "RS256", kid: KEY_ID })
            .setIssuer(ISSUER)
            .setAudience(client_id)
            .setIssuedAt()
            .setExpirationTime("15m")
            .sign(privateKey)

        const refresh_token = generateCode()

        refreshTokens.set(refresh_token, {
            clientId: client_id,
            scope: record.scope,
            sub: record.user.sub,
            name: record.user.name,
            email: record.user.email,
            expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000
        })

        return res.status(200).json({
            access_token: accessToken,
            token_type: "Bearer",
            refresh_token,
            expires_after: 900,
            scope: record.scope,
             ...(oidc_id ? { id_token: oidc_id } : {})
        })

    }

    if (grant_type === "refresh_token") {
        if (grant_type === "refresh_token") {
            const { refresh_token, client_id } = req.body;

            const record = refreshTokens.get(refresh_token);

            if (!record) {
                return res.status(401).send("Invalid refresh token");
            }

            if (record.clientId !== client_id) {
                return res.status(403).send("Invalid client");
            }

            const accessToken = await new SignJWT({
                scope: record.scope,
                name: record.name,
                email: record.email
            })
                .setProtectedHeader({ alg: "RS256", kid: KEY_ID })
                .setIssuer(ISSUER)
                .setAudience(client_id)
                .setIssuedAt()
                .setExpirationTime("15m")
                .sign(privateKey);

            return res.status(200).json({
                access_token: accessToken,
                token_type: "Bearer",
                expires_after: 900,
                scope: record.scope
            });
        }
    }

    res.status(400).send("unsupported grant type");
})
/*
    JWKS endpoint:

    Resource server fetch public key here to validate JWT signatures
 */
app.get("/.well-known/jwks.json", async (req, res) => {
    try {
        // create JWT  access_token 
        const privateKeyObject = createPrivateKey(PRIVATE_KEY_PEM);
        const publicKeyObject = createPublicKey(privateKeyObject);
        /*
    
        jose exports JWK object, but we need public key .
        for tutorial simplicity, jose can export from privet and (it includes public parts) 
    
        */
        const JWK = await  exportJWK(publicKeyObject);
        console.log(JWK)

        JWK.use = "sig"
        JWK.alg = "RS256"
        JWK.kid = KEY_ID

        res.json({ keys: [JWK] })

    } catch (error) {
        console.log(error?.message);
        return res.status(500).json({ error: error?.message });
    }

})


app.listen(3000, () => { console.log("app is running") })