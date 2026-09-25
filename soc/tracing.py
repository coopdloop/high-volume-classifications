"""OpenTelemetry tracing -> Phoenix, using OpenInference span conventions.

Set PHOENIX_ENABLED=false to disable. Traces land in the Phoenix UI (:6006)
under project PHOENIX_PROJECT (default: jev-soc-agent).
"""

import json
import os
from contextlib import contextmanager

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

_initialized = False


def init(service: str = "jev-soc-agent"):
    global _initialized
    if _initialized or os.getenv("PHOENIX_ENABLED", "true").lower() != "true":
        return
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

    endpoint = os.getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://localhost:6006/v1/traces")
    provider = TracerProvider(resource=Resource.create({
        "service.name": service,
        "openinference.project.name": os.getenv("PHOENIX_PROJECT", "jev-soc-agent"),
    }))
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
    trace.set_tracer_provider(provider)
    _initialized = True


def get(name: str = "jev-soc-agent"):
    return trace.get_tracer(name)


def _j(v) -> str:
    return v if isinstance(v, str) else json.dumps(v, default=str)


@contextmanager
def llm_call(name: str, *, model: str, input_value):
    """LLM span following OpenInference conventions (Phoenix renders these)."""
    with get().start_as_current_span(name) as span:
        span.set_attribute("openinference.span.kind", "LLM")
        span.set_attribute("llm.model_name", model or "?")
        span.set_attribute("input.value", _j(input_value))
        span.set_attribute("input.mime_type", "application/json")
        yield span


def finish(span, output_value, *, usage: dict | None = None, cost: float | None = None,
           metadata: dict | None = None):
    span.set_attribute("output.value", _j(output_value))
    span.set_attribute("output.mime_type", "application/json")
    if usage:
        for src, dst in (("prompt_tokens", "llm.token_count.prompt"),
                         ("completion_tokens", "llm.token_count.completion"),
                         ("total_tokens", "llm.token_count.total"),
                         ("input_tokens", "llm.token_count.prompt"),
                         ("output_tokens", "llm.token_count.completion")):
            if usage.get(src) is not None:
                span.set_attribute(dst, usage[src])
    if cost is not None:
        span.set_attribute("llm.cost", cost)
    if metadata:
        span.set_attribute("metadata", _j(metadata))


@contextmanager
def chain(name: str, **attrs):
    """Parent span (event pipeline / campaign) that LLM spans nest under."""
    with get().start_as_current_span(name) as span:
        span.set_attribute("openinference.span.kind", "CHAIN")
        for k, v in attrs.items():
            if v is not None:
                span.set_attribute(k, _j(v))
        yield span
