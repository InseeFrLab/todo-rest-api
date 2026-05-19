import { NodeSDK } from "@opentelemetry/sdk-node";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { ConsoleSpanExporter, SimpleSpanProcessor, BatchSpanProcessor } from "@opentelemetry/sdk-trace-node";

export function setupTracing() {
    if (process.env.OTEL_ENABLED !== "true") {
        return;
    }

    const isDevMode = process.env.MODE === "dev";

    const sdk = new NodeSDK({
        serviceName: "todo-rest-api",
        spanProcessor: isDevMode
            ? new SimpleSpanProcessor(new ConsoleSpanExporter())
            : new BatchSpanProcessor(new OTLPTraceExporter())
    });

    sdk.start();
}
