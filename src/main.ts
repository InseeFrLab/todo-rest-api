import { z, createRoute, OpenAPIHono } from "@hono/zod-openapi";
import { serve } from "@hono/node-server";
import { HTTPException } from "hono/http-exception";
import { getUserTodoStore } from "./todo";
import { cors } from "hono/cors";
import { assert } from "tsafe/assert";
import { createDecodeAccessToken } from "./oidc";

(async function main() {
    const { decodeAccessToken } = await createDecodeAccessToken({
        issuerUri: (() => {
            const value = process.env.OIDC_ISSUER_URI;

            assert(value !== undefined, "OIDC_ISSUER_URI must be defined");

            return value;
        })(),
        audience: (() => {
            const value = process.env.OIDC_AUDIENCE;

            assert(value !== undefined, "OIDC_AUDIENCE must be defined");

            return value;
        })()
    });

    const app = new OpenAPIHono();

    app.use("*", cors());

    {
        const route = createRoute({
            method: "put",
            path: "/todo/{id}",
            request: {
                params: z.object({
                    id: z
                        .string()
                        .min(1)
                        .openapi({
                            param: {
                                name: "id",
                                in: "path"
                            },
                            example: "1212121"
                        })
                }),
                body: {
                    content: {
                        "application/json": {
                            schema: z.object({
                                text: z
                                    .string()
                                    .min(1)
                                    .optional()
                                    .openapi({
                                        param: {
                                            name: "text",
                                            in: "header"
                                        },
                                        example: "Clean my room"
                                    }),
                                isDone: z
                                    .boolean()
                                    .optional()
                                    .openapi({
                                        param: {
                                            name: "isDone",
                                            in: "header"
                                        },
                                        example: false
                                    })
                            })
                        }
                    }
                }
            },
            responses: {
                200: {
                    description: "Update an existing todo item"
                }
            }
        });

        app.openapi(route, async c => {
            const decodedAccessToken = await decodeAccessToken({
                authorizationHeaderValue: c.req.header("Authorization")
            });

            const { id } = c.req.valid("param");
            const { text, isDone } = c.req.valid("json");

            const todoStore = getUserTodoStore(decodedAccessToken.sub);

            const todo = todoStore.getAll().find(({ id: todoId }) => todoId === id);

            assert(todo !== undefined);

            todoStore.addOrUpdate({
                id,
                text: text ?? todo.text,
                isDone: isDone ?? todo.isDone
            });

            return c.json({
                message: "Todo item created or updated"
            });
        });
    }

    {
        const route = createRoute({
            method: "put",
            path: "/todo",
            request: {
                body: {
                    content: {
                        "application/json": {
                            schema: z.object({
                                text: z
                                    .string()
                                    .min(1)
                                    .openapi({
                                        param: {
                                            name: "text",
                                            in: "header"
                                        },
                                        example: "Clean my room"
                                    })
                            })
                        }
                    }
                }
            },
            responses: {
                200: {
                    content: {
                        "application/json": {
                            schema: z.object({
                                id: z.string().openapi({
                                    example: "123",
                                    description: "The id of the newly created todo item"
                                })
                            })
                        }
                    },
                    description: "Create a new todo item returns the newly created todo item's id"
                }
            }
        });

        app.openapi(route, async c => {
            const decodedAccessToken = await decodeAccessToken({
                authorizationHeaderValue: c.req.header("Authorization")
            });

            if (decodedAccessToken === undefined) {
                throw new HTTPException(401);
            }

            const { text } = c.req.valid("json");

            const todoStore = getUserTodoStore(decodedAccessToken.sub);

            const id = Math.random().toString();

            todoStore.addOrUpdate({
                id,
                isDone: false,
                text
            });

            return c.json({ id });
        });
    }

    {
        const route = createRoute({
            method: "get",
            path: "/todos",
            responses: {
                200: {
                    content: {
                        "application/json": {
                            schema: z.array(
                                z
                                    .object({
                                        id: z.string().openapi({
                                            example: "123"
                                        }),
                                        text: z.string().openapi({
                                            example: "Clean my room"
                                        }),
                                        isDone: z.boolean().openapi({
                                            example: false
                                        })
                                    })
                                    .openapi("Todo")
                            )
                        }
                    },
                    description: "Get all user's todo"
                }
            }
        });

        app.openapi(route, async c => {
            const decodedAccessToken = await decodeAccessToken({
                authorizationHeaderValue: c.req.header("Authorization")
            });

            if (decodedAccessToken === undefined) {
                throw new HTTPException(401);
            }

            const todos = getUserTodoStore(decodedAccessToken.sub).getAll();

            return c.json(todos);
        });
    }

    {
        const route = createRoute({
            method: "delete",
            path: "/todo/{id}",
            request: {
                params: z.object({
                    id: z
                        .string()
                        .min(1)
                        .openapi({
                            param: {
                                name: "id",
                                in: "path"
                            },
                            example: "1212121"
                        })
                })
            },
            responses: {
                200: {
                    description: "Deleted a todo item"
                }
            }
        });

        app.openapi(route, async c => {
            const decodedAccessToken = await decodeAccessToken({
                authorizationHeaderValue: c.req.header("Authorization")
            });

            const { id } = c.req.valid("param");

            if (decodedAccessToken === undefined) {
                throw new HTTPException(401);
            }

            getUserTodoStore(decodedAccessToken.sub).remove(id);

            return c.json({
                message: "Todo item deleted"
            });
        });
    }

    // The OpenAPI documentation will be available at /doc
    app.doc("/doc", {
        openapi: "3.0.0",
        info: {
            // NOTE: Replaced at build time
            version: "{{VERSION}}",
            title: "todos"
        }
    });

    if (process.env.PORT === undefined) {
        throw new Error("PORT must be defined in the environment variables");
    }

    const port = parseInt(process.env.PORT);

    serve({
        fetch: app.fetch,
        port
    });

    console.log(`\nServer running. OpenAPI documentation available at http://localhost:${port}/doc`);
})();
