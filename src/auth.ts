import { oidcSpa } from "oidc-spa/server";
import { z } from "zod";
import { HTTPException } from "hono/http-exception";
import type { HonoRequest } from "hono";

const { bootstrapAuth, validateAndDecodeAccessToken } = oidcSpa
    .withExpectedDecodedAccessTokenShape({
        decodedAccessTokenSchema: z.object({
            sub: z.string(),
            realm_access: z.object({
                roles: z.array(z.string())
            })
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

    const { isSuccess, errorCause, debugErrorMessage, decodedAccessToken } =
        await validateAndDecodeAccessToken({
            request: {
                url: req.url,
                method: req.method,
                getHeaderValue: headerName => req.header(headerName)
            }
        });

    if (!isSuccess) {

        if( errorCause === "missing Authorization header" ){
            console.warn("Anonymous request");
        }else{
            console.warn(debugErrorMessage);
        }

        throw new HTTPException(401);
    }

    if (
        requiredRole !== undefined &&
        !decodedAccessToken.realm_access.roles.includes(requiredRole)
    ) {
        console.warn(`User missing role: ${requiredRole}`);
        throw new HTTPException(403);
    }

    return {
        id: decodedAccessToken.sub
    };
}
