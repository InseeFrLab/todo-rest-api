import { oidcSpa, extractRequestAuthContext } from "oidc-spa/server";
import { z } from "zod";
import { HTTPException } from "hono/http-exception";
import type { HonoRequest } from "hono";

const { bootstrapAuth, validateAndDecodeAccessToken } = oidcSpa
    .withExpectedDecodedAccessTokenShape({
        decodedAccessTokenSchema: z.object({
            sub: z.string(),
            realm_access: z.object({
                roles: z.array(z.string())
            }).optional()
        })
    })
    .createUtils();

export { bootstrapAuth };

export type User = {
    id: string;
};

export async function getUser(
    req: HonoRequest,
    requiredRole?: "realm-admin" | "support-staff"
): Promise<User> {
    const requestAuthContext = extractRequestAuthContext({
        request: req,
        trustProxy: true
    });

    if( !requestAuthContext ){
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

    const user: User = {
        id: decodedAccessToken.sub
    };

    return user;
}
