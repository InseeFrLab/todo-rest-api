import { createOidcBackend } from "oidc-spa/backend";
import { z } from "zod";
import { HTTPException } from "hono/http-exception";

const zDecodedAccessToken = z.object({
    sub: z.string(),
    aud: z.union([z.string(), z.array(z.string())]),
    realm_access: z.object({
        roles: z.array(z.string())
    })
    // Some other info you might want to read from the accessToken, example:
    // preferred_username: z.string()
});

export type DecodedAccessToken = z.infer<typeof zDecodedAccessToken>;

export async function createDecodeAccessToken(params: { 
    issuerUri: string;
    audience: string 
}) {
    const { issuerUri, audience } = params;

    const { verifyAndDecodeAccessToken } = await createOidcBackend({
        issuerUri,
        decodedAccessTokenSchema: zDecodedAccessToken
    });

    async function decodeAccessToken(params: {
        authorizationHeaderValue: string | undefined;
        requiredRole?: string;
    }): Promise<DecodedAccessToken> {
        const { authorizationHeaderValue, requiredRole } = params;

        if (authorizationHeaderValue === undefined) {
            throw new HTTPException(401);
        }

        const result = await verifyAndDecodeAccessToken({
            accessToken: authorizationHeaderValue.replace(/^Bearer /, "")
        });

        if (!result.isValid) {
            switch (result.errorCase) {
                case "does not respect schema":
                    throw new Error(`The access token does not respect the schema ${result.errorMessage}`);
                case "invalid signature":
                case "expired":
                    throw new HTTPException(401);
            }
        }

        const { decodedAccessToken } = result;

        if (requiredRole !== undefined && !decodedAccessToken.realm_access.roles.includes(requiredRole)) {
            throw new HTTPException(401);
        }

        {
            const { aud } = decodedAccessToken;

            const aud_array = typeof aud === "string" ? [aud] : aud;

            if (!aud_array.includes(audience)) {
                throw new HTTPException(401);
            }
        }

        return decodedAccessToken;
    }

    return { decodeAccessToken };
}