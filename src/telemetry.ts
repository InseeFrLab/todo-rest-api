import { NodeSDK } from "@opentelemetry/sdk-node";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { ConsoleSpanExporter } from "@opentelemetry/sdk-trace-node";

export function setupTracing() {
    const sdk = new NodeSDK({
        serviceName: "todo-rest-api",
        traceExporter:
            process.env.MODE === "dev"
                ? new ConsoleSpanExporter()
                : new OTLPTraceExporter()
    });

    console.log(
        process.env.MODE === "dev"
            ? "Using ConsoleSpanExporter for tracing"
            : "Using OTLPTraceExporter for tracing"
    );

    sdk.start();
}
