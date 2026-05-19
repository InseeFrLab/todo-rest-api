import { diag, DiagConsoleLogger, DiagLogLevel } from "@opentelemetry/api";
import { NodeSDK } from "@opentelemetry/sdk-node";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { ConsoleSpanExporter } from "@opentelemetry/sdk-trace-node";
import { SimpleSpanProcessor } from "@opentelemetry/sdk-trace-base";

export function setupTracing() {
    diag.setLogger(new DiagConsoleLogger(), DiagLogLevel.ERROR);

    const traceExporter = new OTLPTraceExporter({
        url: `${process.env.OTEL_EXPORTER_OTLP_ENDPOINT}/v1/traces`
    });

    const spanProcessors = [
        new SimpleSpanProcessor(traceExporter),
        new SimpleSpanProcessor(new ConsoleSpanExporter())
    ];

    const sdk = new NodeSDK({
        serviceName: "todo-rest-api",
        spanProcessors
    });

    sdk.start();
}
