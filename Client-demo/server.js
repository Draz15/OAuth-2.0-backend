import express, { application } from 'express';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import { randomBytes, createHash } from 'crypto';
import { createRemoteJWKSet, jwtVerify } from "jose";
import dotenv from 'dotenv';
import axios from 'axios';

const app = express();

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
dotenv.config();


const AUTH_SERVER = "http://localhost:3000";
const RESOURCE_SERVER = "http://localhost:5000";

const REDIRECT_URI = "http://localhost:4000/callback";
const CLIENT_ID = "demo-client";


function generateVerifier() {
    const code_verifier = randomBytes(32).toString("base64url");
    return code_verifier;
}

function sha256BaseUrl(verifier) {
    const code_challenge = createHash("sha256").update(verifier).digest();
    return code_challenge.toString("base64url");
}


function generateState() {
    const state = randomBytes(16).toString("base64url");
    return state;
}

app.get("/", (req, res) => {

    res.send(
        `
        <h2>client app</h2>
        <p>this app uses authorization code + PKCE</p>
        <a href="/login">login</a>
        `
    )
})


app.get("/login", async (req, res) => {
    const code_verifier = generateVerifier();
    const code_challenge = sha256BaseUrl(code_verifier);
    const nonce = randomBytes(32).toString("base64url");
    const state = generateState();

    res.cookie("code_verifier", code_verifier, { httpOnly: true });
    res.cookie("oauth_state", state, { httpOnly: true });
    res.cookie("oidc_nonce", nonce, { httpOnly: true, });

    const authorizeURL = new URL(`${AUTH_SERVER}/authorize`);
    authorizeURL.searchParams.set("response_type", "code");
    authorizeURL.searchParams.set("client_id", CLIENT_ID);
    authorizeURL.searchParams.set("redirect_uri", REDIRECT_URI);
    authorizeURL.searchParams.set("scope", "openid api.read profile email");
    authorizeURL.searchParams.set("state", state);
    authorizeURL.searchParams.set("code_challenge", code_challenge);
    authorizeURL.searchParams.set("oidc_nonce", nonce);
    authorizeURL.searchParams.set("code_challenge_method", "S256");

    res.redirect(authorizeURL.toString());
})

app.get("/callback", async (req, res) => {
    console.log("CALLBACK REACHED \n \n \n \n");
    const { code, state } = req.query;

    const storedState = req?.cookies?.oauth_state;
    const storedCodeVerifier = req?.cookies?.code_verifier;
    const oidc_nonce = req?.cookies?.oidc_nonce;

    if (!code) return res.status(401).send("code is needed");
    if (!state || state !== storedState) return res.status(401).send("state is invalid");

    try {
        // exchange code for token 
        const tokenRes = await axios.post(`${AUTH_SERVER}/token`,
            new URLSearchParams({
                grant_type: "authorization_code",
                code,
                redirect_uri: REDIRECT_URI,
                client_id: CLIENT_ID,
                code_verifier: storedCodeVerifier
            }).toString(),
            { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
        );

        const { access_token, refresh_token, id_token, expires_after } = tokenRes.data

        if (!id_token) return res.status(401).send("open id token is required, not authorized request")

        const OIDC_JWKS = createRemoteJWKSet(new URL(`${AUTH_SERVER}/.well-known/jwks.json`));

        const { payload } = await jwtVerify(
            id_token,
            OIDC_JWKS,
            {
                issuer: AUTH_SERVER,
                audience: CLIENT_ID
            }
        );

        if (!payload) return res.status(403).send("forbidden , don't do that again");

        if (typeof oidc_nonce !== "string" || typeof payload.nonce !== "string"
            || payload.nonce !== oidc_nonce) {

            return res.status(401).send("unauthorized openid");
        }



        res.cookie("access_token", access_token, { httpOnly: true });
        res.cookie("refresh_token", refresh_token, { httpOnly: true });

        res.send(`
            <h3>logged in</h3>
            <p>access toke expired in ${expires_after}</p>
            <a href="/profile">call protected api</a>
            <br/><br/>
            <a href="/refresh">refresh access token</a>

            `)

    } catch (error) {
        console.log("Status:", error.response?.status);
        console.log("Response data:", error.response?.data);
        console.log("Request URL:", error.config?.url);
        console.log("Message:", error.message);
    }

})

app.get("/profile", async (req, res) => {

    const accessToken = req?.cookies?.access_token

    if (!accessToken) return res.redirect("/")

    try {
        const userData = await axios.get(`${RESOURCE_SERVER}/api/profile`,
            { headers: { Authorization: `Bearer ${accessToken}` } }
        )

        const { name, scope, email } = userData.data.user;

        res.send(`
            <pre>
            scope is ${scope}
            user name is ${name}
            email is ${email}
            </pre>
            `)

    } catch (error) {
        console.log("Status:", error.response?.status);
        console.log("API response:", error.response?.data);

        return res.status(error.response?.status || 500).send(
            JSON.stringify(error.response?.data || error.message)
        );
    }
})


app.get("/refresh", async (req, res) => {
    const refreshToken = req?.cookies?.refresh_token;

    if (!refreshToken) {
        return res.status(401).send("You need a refresh token");
    }

    try {
        const tokenRes = await axios.post(
            `${AUTH_SERVER}/token`,
            new URLSearchParams({
                grant_type: "refresh_token",
                refresh_token: refreshToken,
                client_id: CLIENT_ID,
            }).toString(),
            {
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            }
        );

        const { access_token } = tokenRes.data;

        res.cookie("access_token", access_token, {
            httpOnly: true,
        });

        return res.send(`
            <h2>Refreshed access token</h2>
            <a href="/profile">Call the API again!</a>
        `);
    } catch (error) {
        console.error(error.response?.data || error.message);

        return res.status(
            error.response?.status || 500
        ).send("Failed to refresh access token");
    }
});


app.listen(4000, () => {
    console.log("server sunning in por 4000")
})
