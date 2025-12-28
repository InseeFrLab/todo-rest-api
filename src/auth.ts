import { oidcSpa, extractRequestAuthContext } from "oidc-spa/server";
import { z } from "zod";
import { HTTPException } from "hono/http-exception";
import type { HonoRequest } from "hono";

const { bootstrapAuth, validateAndDecodeAccessToken, ofTypeDecodedAccessToken } = oidcSpa
    .withExpectedDecodedAccessTokenShape({
        decodedAccessTokenSchema: z.object({
            sub: z.string(),
            name: z.string(),
            email: z.string().optional(),
            realm_access: z
                .object({
                    roles: z.array(z.string())
                })
                .optional()
        })
    })
    .createUtils();

export { bootstrapAuth };

type DecodedAccessToken = typeof ofTypeDecodedAccessToken;

export type User = {
    id: string;
    name: string;
    email: string | undefined;
};

async function decodedAccessTokenToUser(
    decodedAccessToken: DecodedAccessToken
): Promise<User> {
    const { sub, name, email } = decodedAccessToken;

    // Potentially fetch additional data that represent your user.

    const user: User = {
        id: sub,
        name,
        email
    };

    return user;
}

export async function getUser(params: {
    req: HonoRequest;
    requiredRole?: "realm-admin" | "support-staff";
}): Promise<User> {
    const { req, requiredRole } = params;

    const requestAuthContext = extractRequestAuthContext({
        request: req,
        trustProxy: true
    });

    if (!requestAuthContext) {
        // Demo shortcut: we return 401 on missing Authorization, but a mixed
        // public/private endpoint could instead return undefined here and let
        // the caller decide whether to process an anonymous request.
        console.warn("Anonymous request");
        throw new HTTPException(401); // Unauthorized
    }

    if (!requestAuthContext.isWellFormed) {
        console.warn(requestAuthContext.debugErrorMessage);
        throw new HTTPException(400); // Bad Request
    }

    const { isSuccess, debugErrorMessage, decodedAccessToken } =
        await validateAndDecodeAccessToken(
            requestAuthContext.accessTokenAndMetadata
        );

    if (!isSuccess) {
        console.warn(debugErrorMessage);
        throw new HTTPException(401); // Unauthorized
    }

    // Your custom Authorization logic: Grant per request access depending
    // on the access token claim.
    if (requiredRole) {
        if (!decodedAccessToken.realm_access?.roles.includes(requiredRole)) {
            console.warn(`User missing role: ${requiredRole}`);
            throw new HTTPException(403); // Forbidden
        }
    }

    const user = await decodedAccessTokenToUser(decodedAccessToken);

    return user;
}

export async function getUser_ws(params: { req: HonoRequest }) {
    const { req } = params;

    const value = req.header("Sec-WebSocket-Protocol");

    if (value === undefined) {
        throw new HTTPException(400); // Bad Request
    }

    const accessToken = value
        .split(",")
        .map(p => p.trim())
        .map(p => {
            const match = p.match(/^authorization_bearer_(.+)$/);

            if (match === null) {
                return undefined;
            }

            return match[1];
        })
        .filter(t => t !== undefined)[0];

    if (accessToken === undefined) {
        throw new HTTPException(400); // Bad Request
    }

    const { isSuccess, debugErrorMessage, decodedAccessToken } =
        await validateAndDecodeAccessToken({
            scheme: "Bearer",
            accessToken,
            // NOTE: The DPoP protocol does not cover WebSocket Upgrade request.
            // We chose to accept tokens even if the proof isn't provided.
            rejectIfAccessTokenDPoPBound: false
        });

    if (!isSuccess) {
        console.warn(debugErrorMessage);
        throw new HTTPException(401); // Unauthorized
    }

    const user = await decodedAccessTokenToUser(decodedAccessToken);

    return user;
}


